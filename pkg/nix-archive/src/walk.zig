//! NAR serialisation straight from the filesystem, without spawning
//! `nix store dump-path`. Walks with openat/getdents64/statx relative to
//! directory fds, and reads file contents directly into the sink's input
//! buffer so file data is copied exactly once out of the kernel.

const std = @import("std");
const builtin = @import("builtin");
const Sink = @import("sink.zig").Sink;

pub const supported = builtin.target.os.tag == .linux;

pub const Error = error{
    Io,
    UnsupportedFileType,
    FileChanged,
    NameTooLong,
} || @import("sink.zig").Error;

/// errno of the last failed syscall on this thread, for diagnostics.
pub threadlocal var last_errno: i32 = 0;

const linux = std.os.linux;

fn check(rc: usize) Error!usize {
    const e = linux.errno(rc);
    if (e == .SUCCESS) return rc;
    last_errno = @backingInt(e);
    return error.Io;
}

fn closeFd(fd: i32) void {
    _ = linux.close(fd);
}

/// Files at least this large are mmapped; sink.write feeds them unbuffered.
const mmap_threshold = @import("sink.zig").direct_threshold;
/// Bytes mapped at once; a page multiple, so every window offset is aligned.
const mmap_window = 16 << 20;

const Kind = enum { regular, executable, symlink, directory };

const Node = struct {
    kind: Kind,
    size: u64,
};

fn statAt(dirfd: i32, name: [*:0]const u8) Error!Node {
    var stx: linux.Statx = undefined;
    _ = try check(linux.statx(dirfd, name, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true, .SIZE = true }, &stx));
    const mode: u32 = stx.mode;
    return switch (mode & linux.S.IFMT) {
        linux.S.IFREG => .{ .kind = if (mode & 0o100 != 0) .executable else .regular, .size = stx.size },
        linux.S.IFLNK => .{ .kind = .symlink, .size = stx.size },
        linux.S.IFDIR => .{ .kind = .directory, .size = 0 },
        else => error.UnsupportedFileType,
    };
}

const Writer = struct {
    sink: *Sink,
    arena: std.mem.Allocator,
    /// getdents64 buffer, shared: a directory is fully listed before recursing.
    dents: []u8,

    fn str(self: *Writer, s: []const u8) Error!void {
        try self.len(s.len);
        try self.sink.write(s);
        try self.pad(s.len);
    }

    fn len(self: *Writer, n: u64) Error!void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, n, .little);
        try self.sink.write(&buf);
    }

    fn pad(self: *Writer, n: u64) Error!void {
        const zeros: [8]u8 = @splat(0);
        const rem: usize = @intCast(n % 8);
        if (rem != 0) try self.sink.write(zeros[0 .. 8 - rem]);
    }

    fn node(self: *Writer, dirfd: i32, name: [*:0]const u8, n: Node) Error!void {
        try self.str("(");
        try self.str("type");
        switch (n.kind) {
            .regular, .executable => {
                try self.str("regular");
                if (n.kind == .executable) {
                    try self.str("executable");
                    try self.str("");
                }
                try self.str("contents");
                try self.contents(dirfd, name, n.size);
            },
            .symlink => {
                try self.str("symlink");
                try self.str("target");
                var buf: [4096]u8 = undefined;
                const got = try check(linux.readlinkat(dirfd, name, &buf, buf.len));
                if (got >= buf.len) return error.NameTooLong;
                try self.str(buf[0..got]);
            },
            .directory => {
                try self.str("directory");
                try self.directory(dirfd, name);
            },
        }
        try self.str(")");
    }

    fn contents(self: *Writer, dirfd: i32, name: [*:0]const u8, size: u64) Error!void {
        const fd: i32 = @intCast(try check(linux.openat(dirfd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0)));
        defer closeFd(fd);
        try self.len(size);
        // Large files are hashed straight out of the page cache: no
        // kernel-to-user copy, and the sink feeds the mapping without
        // buffering it. Store paths are immutable, so the mapping is stable.
        // A window at a time, so peak RSS does not grow with the file.
        var done: u64 = 0;
        if (size >= mmap_threshold) {
            while (done < size) {
                const window: usize = @intCast(@min(size - done, mmap_window));
                const rc = linux.mmap(null, window, .{ .READ = true }, .{ .TYPE = .PRIVATE, .POPULATE = true }, fd, @intCast(done));
                if (linux.errno(rc) != .SUCCESS) {
                    // Read the rest instead, from where the mappings stopped.
                    _ = try check(linux.lseek(fd, @intCast(done), linux.SEEK.SET));
                    break;
                }
                const ptr: [*]u8 = @ptrFromInt(rc);
                defer _ = linux.munmap(ptr, window);
                try self.sink.write(ptr[0..window]);
                done += window;
            }
        }
        var remaining = size - done;
        while (remaining > 0) {
            var dst = self.sink.spare();
            if (dst.len == 0) {
                try self.sink.flush();
                dst = self.sink.spare();
            }
            const want: usize = @intCast(@min(remaining, dst.len));
            const rc = linux.read(fd, dst.ptr, want);
            const e = linux.errno(rc);
            if (e == .INTR) continue;
            const got = try check(rc);
            if (got == 0) return error.FileChanged;
            remaining -= got;
            try self.sink.commit(got);
        }
        try self.pad(size);
    }

    fn directory(self: *Writer, parent: i32, name: [*:0]const u8) Error!void {
        const fd: i32 = @intCast(try check(linux.openat(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0)));
        defer closeFd(fd);

        const Entry = struct { name: [:0]const u8, dtype: u8 };
        var entries: std.ArrayList(Entry) = .empty;
        const buf = self.dents;
        while (true) {
            const n = try check(linux.getdents64(fd, buf.ptr, @intCast(buf.len)));
            if (n == 0) break;
            var off: usize = 0;
            while (off < n) {
                const reclen = std.mem.readInt(u16, buf[off + 16 ..][0..2], builtin.target.cpu.arch.endian());
                const dtype = buf[off + 18];
                const entry_name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&buf[off + 19])), 0);
                off += reclen;
                if (std.mem.eql(u8, entry_name, ".") or std.mem.eql(u8, entry_name, "..")) continue;
                try entries.append(self.arena, .{ .name = try self.arena.dupeSentinel(u8, entry_name, 0), .dtype = dtype });
            }
        }

        // NAR entries are ordered bytewise, like Nix's std::map<std::string>.
        std.mem.sort(Entry, entries.items, {}, struct {
            fn lessThan(_: void, a: Entry, b: Entry) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lessThan);

        for (entries.items) |entry| {
            const child: Node = switch (entry.dtype) {
                linux.DT.DIR => .{ .kind = .directory, .size = 0 },
                linux.DT.LNK => .{ .kind = .symlink, .size = 0 },
                else => try statAt(fd, entry.name.ptr),
            };
            try self.str("entry");
            try self.str("(");
            try self.str("name");
            try self.str(entry.name);
            try self.str("node");
            try self.node(fd, entry.name.ptr, child);
            try self.str(")");
        }
    }
};

/// Serialise `path` as a NAR into `sink`.
pub fn dump(sink: *Sink, path: [*:0]const u8) Error!void {
    if (!supported) @compileError("NAR dumping is only implemented for Linux");
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.c_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var w: Writer = .{ .sink = sink, .arena = arena, .dents = try arena.alloc(u8, 64 * 1024) };
    const root = try statAt(linux.AT.FDCWD, path);
    try w.str("nix-archive-1");
    try w.node(linux.AT.FDCWD, path, root);
}
