//! Server-side upload verification: feed the compressed NAR as it arrives
//! and get back the hash/size of both the compressed file and the NAR it
//! decompresses to. The server signs narinfo from these values rather than
//! trusting what the client claims.

const std = @import("std");
const snitch = @import("snitch");
const zstd = @import("zstd.zig");
const Digest = @import("sink.zig").Digest;
const Sha256 = @import("sha256.zig").Sha256;

pub const Compression = enum(c_int) { none = 0, zstd = 1 };

pub const Error = error{ Zstd, Truncated, NotNar, OutOfMemory, SizeExceeded };

const nar_magic = "\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00";

pub const Verifier = struct {
    file_hasher: Sha256 = .init(.{}),
    file_size: u64 = 0,
    nar_hasher: Sha256 = .init(.{}),
    nar_size: u64 = 0,
    max_nar_size: u64 = std.math.maxInt(u64),
    dctx: ?*zstd.DCtx = null,
    out_buf: []u8 = &.{},
    /// Last ZSTD_decompressStream result; 0 means a frame just ended.
    frame_state: usize = 0,
    head: [nar_magic.len]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, compression: Compression) Error!Verifier {
        return initBounded(allocator, compression, std.math.maxInt(u64));
    }

    /// A ceiling, not an exact-size assertion: callers still compare the digest.
    pub fn initBounded(allocator: std.mem.Allocator, compression: Compression, max_nar_size: u64) Error!Verifier {
        const zone = snitch.zone("archive.verify.init");
        defer zone.end();
        var v: Verifier = .{ .max_nar_size = max_nar_size };
        if (compression == .zstd) {
            v.dctx = zstd.ZSTD_createDCtx() orelse return error.OutOfMemory;
            errdefer _ = zstd.ZSTD_freeDCtx(v.dctx);
            // Match stock Nix and Sink's largest supported long-distance window
            // (128 MiB). Do not let an upload request arbitrarily large history.
            if (zstd.isError(zstd.ZSTD_DCtx_setParameter(v.dctx.?, zstd.d_windowLogMax, 27))) return error.Zstd;
            v.out_buf = try allocator.alloc(u8, zstd.ZSTD_DStreamOutSize() * 4);
        }
        return v;
    }

    pub fn deinit(self: *Verifier, allocator: std.mem.Allocator) void {
        const zone = snitch.zone("archive.verify.deinit");
        defer zone.end();
        if (self.dctx) |dctx| _ = zstd.ZSTD_freeDCtx(dctx);
        allocator.free(self.out_buf);
        self.* = undefined;
    }

    fn nar(self: *Verifier, data: []const u8) Error!void {
        const zone = snitch.zone("archive.verify.nar_hash");
        defer zone.end();
        if (data.len > self.max_nar_size - self.nar_size) return error.SizeExceeded;
        if (self.nar_size < self.head.len) {
            const n = @min(data.len, self.head.len - self.nar_size);
            @memcpy(self.head[self.nar_size..][0..n], data[0..n]);
        }
        self.nar_hasher.update(data);
        self.nar_size += data.len;
    }

    pub fn update(self: *Verifier, data: []const u8) Error!void {
        const zone = snitch.zone("archive.verify.update");
        defer zone.end();
        if (data.len > std.math.maxInt(u64) - self.file_size) return error.SizeExceeded;
        snitch.measureCall("archive.verify.file_hash", Sha256.update, .{ &self.file_hasher, data });
        self.file_size += data.len;
        const dctx = self.dctx orelse return self.nar(data);
        var input: zstd.InBuffer = .{ .src = data.ptr, .size = data.len, .pos = 0 };
        while (true) {
            // Allow one sentinel byte past the ceiling to distinguish exact
            // completion (including frame trailers) from excess output. Saturate
            // before narrowing so even an unbounded u64 ceiling cannot overflow.
            const output_size: usize = @intCast(@min(self.out_buf.len, (self.max_nar_size - self.nar_size) +| 1));
            var output: zstd.OutBuffer = .{ .dst = self.out_buf.ptr, .size = output_size, .pos = 0 };
            const rc = snitch.measureCall("archive.verify.decompress", zstd.ZSTD_decompressStream, .{ dctx, &output, &input });
            if (zstd.isError(rc)) return error.Zstd;
            self.frame_state = rc;
            if (output.pos > 0) try self.nar(self.out_buf[0..output.pos]);
            // Done once the input is consumed and zstd has no more buffered output.
            if (input.pos == input.size and output.pos < output.size) break;
        }
    }

    pub fn finish(self: *Verifier) Error!Digest {
        const zone = snitch.zone("archive.verify.finish");
        defer zone.end();
        if (self.dctx != null and self.frame_state != 0) return error.Truncated;
        if (self.nar_size < self.head.len or !std.mem.eql(u8, &self.head, nar_magic)) return error.NotNar;
        var digest: Digest = undefined;
        self.file_hasher.final(&digest.file_hash);
        self.nar_hasher.final(&digest.nar_hash);
        digest.file_size = self.file_size;
        digest.nar_size = self.nar_size;
        return digest;
    }
};

test "bounded raw verification and counter overflow" {
    const a = std.testing.allocator;
    var exact = try Verifier.initBounded(a, .none, nar_magic.len);
    defer exact.deinit(a);
    try exact.update(nar_magic);
    try std.testing.expectEqual(nar_magic.len, (try exact.finish()).nar_size);

    var excess = try Verifier.initBounded(a, .none, nar_magic.len - 1);
    defer excess.deinit(a);
    try std.testing.expectError(error.SizeExceeded, excess.update(nar_magic));
    try std.testing.expectEqual(0, excess.nar_size);

    var overflow = try Verifier.init(a, .none);
    defer overflow.deinit(a);
    overflow.file_size = std.math.maxInt(u64);
    try std.testing.expectError(error.SizeExceeded, overflow.update("x"));
    overflow.file_size = 0;
    overflow.nar_size = std.math.maxInt(u64);
    try std.testing.expectError(error.SizeExceeded, overflow.update("x"));
}

test "bounded zstd stops before hashing oversized output in one update" {
    // A 128 KiB RLE block encoded in ten bytes, with unknown frame size.
    const frame = "\x28\xb5\x2f\xfd\x00\x38\x03\x00\x10x";
    var v = try Verifier.initBounded(std.testing.allocator, .zstd, 24);
    defer v.deinit(std.testing.allocator);
    try std.testing.expectError(error.SizeExceeded, v.update(frame));
    // The first output request is capped at 25 bytes, rather than draining the
    // entire frame and checking its size later. None of that excess is hashed.
    try std.testing.expectEqual(0, v.nar_size);
}
