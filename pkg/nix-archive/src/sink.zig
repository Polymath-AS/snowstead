//! The compressing sink: NAR bytes go in, get hashed and counted, are
//! zstd-compressed, and the compressed bytes are hashed, counted and
//! handed to a caller-supplied write callback. Everything happens in a
//! single pass; zstd worker threads do the compression when enabled.

const std = @import("std");
const zstd = @import("zstd.zig");
const Sha256 = @import("sha256.zig").Sha256;

pub const WriteFn = *const fn (ctx: ?*anyopaque, buf: [*]const u8, len: usize) callconv(.c) c_int;

pub const Digest = extern struct {
    file_hash: [32]u8,
    file_size: u64,
    nar_hash: [32]u8,
    nar_size: u64,
};

pub const Error = error{ Zstd, Aborted, OutOfMemory };

pub const Options = struct {
    /// 0 disables compression (the output is the raw NAR).
    level: c_int = 3,
    /// zstd worker threads; 0 compresses on the calling thread.
    threads: c_int = 0,
    /// The exact NAR size, 0 when unknown. It is pledged to zstd, which then
    /// sizes its window to the NAR and records the size in the frame, so a
    /// decoder allocates no more than the NAR needs. A stream of another
    /// length fails.
    nar_size: u64 = 0,
    /// 0 keeps the level's window. Otherwise long-distance matching with a
    /// window of 2^window_log bytes (at most 27, the largest a stock Nix
    /// decoder accepts), which finds repeats across a large NAR.
    window_log: c_int = 0,
    /// false skips both SHA-256 passes; the digest then carries sizes only.
    /// For an uploader whose server verifies the content anyway.
    hash: bool = true,
};

const in_capacity = 1 << 20;

/// Writes at least this large bypass the input buffer.
pub const direct_threshold = in_capacity;

/// NAR streams below this size are compressed on the calling thread:
/// spinning up zstd workers costs more than it saves.
const multithread_threshold = 4 << 20;

pub const Sink = struct {
    hash: bool = true,
    nar_hasher: Sha256 = .init(.{}),
    nar_size: u64 = 0,
    file_hasher: Sha256 = .init(.{}),
    file_size: u64 = 0,
    cctx: ?*zstd.CCtx = null,
    in_buf: []u8,
    in_len: usize = 0,
    out_buf: []u8,
    write_fn: WriteFn,
    write_ctx: ?*anyopaque,

    pub fn init(allocator: std.mem.Allocator, options: Options, write_fn: WriteFn, write_ctx: ?*anyopaque) Error!Sink {
        const in_buf = try allocator.alloc(u8, in_capacity);
        errdefer allocator.free(in_buf);

        var cctx: ?*zstd.CCtx = null;
        // At function scope so a failed out_buf allocation frees it too.
        errdefer _ = zstd.ZSTD_freeCCtx(cctx);
        var out_len: usize = 0;
        if (options.level != 0) {
            cctx = zstd.ZSTD_createCCtx() orelse return error.OutOfMemory;
            if (zstd.isError(zstd.ZSTD_CCtx_setParameter(cctx.?, zstd.c_compressionLevel, options.level))) return error.Zstd;
            if (options.threads > 0 and (options.nar_size == 0 or options.nar_size >= multithread_threshold)) {
                // Fails harmlessly on a single-threaded libzstd build.
                _ = zstd.ZSTD_CCtx_setParameter(cctx.?, zstd.c_nbWorkers, options.threads);
            }
            if (options.window_log != 0) {
                if (options.window_log < 10 or options.window_log > 27) return error.Zstd;
                if (zstd.isError(zstd.ZSTD_CCtx_setParameter(cctx.?, zstd.c_enableLongDistanceMatching, 1))) return error.Zstd;
                if (zstd.isError(zstd.ZSTD_CCtx_setParameter(cctx.?, zstd.c_windowLog, options.window_log))) return error.Zstd;
            }
            if (options.nar_size > 0) {
                if (zstd.isError(zstd.ZSTD_CCtx_setPledgedSrcSize(cctx.?, options.nar_size))) return error.Zstd;
            }
            out_len = zstd.ZSTD_CStreamOutSize();
        }
        const out_buf = try allocator.alloc(u8, out_len);

        return .{
            .hash = options.hash,
            .cctx = cctx,
            .in_buf = in_buf,
            .out_buf = out_buf,
            .write_fn = write_fn,
            .write_ctx = write_ctx,
        };
    }

    pub fn deinit(self: *Sink, allocator: std.mem.Allocator) void {
        if (self.cctx) |cctx| _ = zstd.ZSTD_freeCCtx(cctx);
        allocator.free(self.in_buf);
        allocator.free(self.out_buf);
        self.* = undefined;
    }

    /// Buffered write of NAR bytes.
    pub fn write(self: *Sink, bytes: []const u8) Error!void {
        if (self.in_len + bytes.len <= self.in_buf.len) {
            @memcpy(self.in_buf[self.in_len..][0..bytes.len], bytes);
            self.in_len += bytes.len;
            return;
        }
        try self.flush();
        if (bytes.len >= self.in_buf.len) {
            try self.feed(bytes);
        } else {
            @memcpy(self.in_buf[0..bytes.len], bytes);
            self.in_len = bytes.len;
        }
    }

    /// Free tail of the input buffer, for callers that read straight into it.
    pub fn spare(self: *Sink) []u8 {
        return self.in_buf[self.in_len..];
    }

    pub fn commit(self: *Sink, n: usize) Error!void {
        self.in_len += n;
        if (self.in_len == self.in_buf.len) try self.flush();
    }

    pub fn flush(self: *Sink) Error!void {
        if (self.in_len == 0) return;
        const pending = self.in_buf[0..self.in_len];
        self.in_len = 0;
        try self.feed(pending);
    }

    fn feed(self: *Sink, data: []const u8) Error!void {
        if (self.hash) self.nar_hasher.update(data);
        self.nar_size += data.len;
        const cctx = self.cctx orelse return self.emit(data);
        var input: zstd.InBuffer = .{ .src = data.ptr, .size = data.len, .pos = 0 };
        while (input.pos < input.size) {
            var output: zstd.OutBuffer = .{ .dst = self.out_buf.ptr, .size = self.out_buf.len, .pos = 0 };
            if (zstd.isError(zstd.ZSTD_compressStream2(cctx, &output, &input, zstd.e_continue))) return error.Zstd;
            if (output.pos > 0) try self.emit(self.out_buf[0..output.pos]);
        }
    }

    fn emit(self: *Sink, data: []const u8) Error!void {
        // Uncompressed output is the NAR itself: hash it once, not twice.
        if (self.hash and self.cctx != null) self.file_hasher.update(data);
        self.file_size += data.len;
        if (self.write_fn(self.write_ctx, data.ptr, data.len) != 0) return error.Aborted;
    }

    pub fn finish(self: *Sink) Error!Digest {
        try self.flush();
        if (self.cctx) |cctx| {
            var input: zstd.InBuffer = .{ .src = null, .size = 0, .pos = 0 };
            while (true) {
                var output: zstd.OutBuffer = .{ .dst = self.out_buf.ptr, .size = self.out_buf.len, .pos = 0 };
                const remaining = zstd.ZSTD_compressStream2(cctx, &output, &input, zstd.e_end);
                if (zstd.isError(remaining)) return error.Zstd;
                if (output.pos > 0) try self.emit(self.out_buf[0..output.pos]);
                if (remaining == 0) break;
            }
        }
        var digest: Digest = undefined;
        if (!self.hash) {
            @memset(&digest.nar_hash, 0);
            @memset(&digest.file_hash, 0);
        } else {
            self.nar_hasher.final(&digest.nar_hash);
            if (self.cctx != null) self.file_hasher.final(&digest.file_hash) else {
                digest.file_hash = digest.nar_hash;
            }
        }
        digest.nar_size = self.nar_size;
        digest.file_size = self.file_size;
        return digest;
    }
};
