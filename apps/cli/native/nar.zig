//! Upload-only C boundary over the NAR core from Snowstead PR #2.
const std = @import("std");
const builtin = @import("builtin");
const archive = @import("nix-archive");
const Sink = archive.Sink;
const allocator = std.heap.c_allocator;
const fast = switch (builtin.target.cpu.arch) {
    .x86_64 => builtin.target.cpu.hasAll(.x86, &.{ .avx2, .sha }),
    .aarch64 => builtin.target.cpu.hasAll(.aarch64, &.{.sha2}),
    else => false,
};

fn options(level: c_int, threads: c_int, size: u64) archive.Options {
    return .{ .level = level, .threads = threads, .nar_size = size, .hash = true };
}

fn dump(path: [*:0]const u8, level: c_int, threads: c_int, size: u64, write: archive.WriteFn, ctx: ?*anyopaque, out: *archive.Digest) callconv(.c) c_int {
    if (comptime !archive.supported) return -2;
    var sink = Sink.init(allocator, options(level, threads, size), write, ctx) catch return -1;
    defer sink.deinit(allocator);
    archive.dump(&sink, path) catch return -1;
    out.* = sink.finish() catch return -1;
    return 0;
}

// These are used only on platforms whose filesystem walker is not supported.
fn create(level: c_int, threads: c_int, size: u64, write: archive.WriteFn, ctx: ?*anyopaque) callconv(.c) ?*Sink {
    const sink = allocator.create(Sink) catch return null;
    sink.* = Sink.init(allocator, options(level, threads, size), write, ctx) catch {
        allocator.destroy(sink);
        return null;
    };
    return sink;
}
fn update(sink: *Sink, buf: [*]const u8, len: usize) callconv(.c) c_int {
    sink.write(buf[0..len]) catch return -1;
    return 0;
}
fn finish(sink: *Sink, out: *archive.Digest) callconv(.c) c_int {
    out.* = sink.finish() catch return -1;
    return 0;
}
fn free(sink: *Sink) callconv(.c) void {
    sink.deinit(allocator);
    allocator.destroy(sink);
}
comptime {
    const prefix = if (fast) "sn_fast_" else "sn_";
    @export(&dump, .{ .name = prefix ++ "dump" });
    @export(&create, .{ .name = prefix ++ "create" });
    @export(&update, .{ .name = prefix ++ "update" });
    @export(&finish, .{ .name = prefix ++ "finish" });
    @export(&free, .{ .name = prefix ++ "free" });
}
