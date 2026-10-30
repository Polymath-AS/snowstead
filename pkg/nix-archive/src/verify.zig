//! Server-side upload verification: feed the compressed NAR as it arrives
//! and get back the hash/size of both the compressed file and the NAR it
//! decompresses to. The server signs narinfo from these values rather than
//! trusting what the client claims.

const std = @import("std");
const zstd = @import("zstd.zig");
const Digest = @import("sink.zig").Digest;
const Sha256 = @import("sha256.zig").Sha256;

pub const Compression = enum(c_int) { none = 0, zstd = 1 };

pub const Error = error{ Zstd, Truncated, NotNar, OutOfMemory };

const nar_magic = "\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00";

pub const Verifier = struct {
    file_hasher: Sha256 = .init(.{}),
    file_size: u64 = 0,
    nar_hasher: Sha256 = .init(.{}),
    nar_size: u64 = 0,
    dctx: ?*zstd.DCtx = null,
    out_buf: []u8 = &.{},
    /// Last ZSTD_decompressStream result; 0 means a frame just ended.
    frame_state: usize = 0,
    head: [nar_magic.len]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, compression: Compression) Error!Verifier {
        var v: Verifier = .{};
        if (compression == .zstd) {
            v.dctx = zstd.ZSTD_createDCtx() orelse return error.OutOfMemory;
            errdefer _ = zstd.ZSTD_freeDCtx(v.dctx);
            v.out_buf = try allocator.alloc(u8, zstd.ZSTD_DStreamOutSize() * 4);
        }
        return v;
    }

    pub fn deinit(self: *Verifier, allocator: std.mem.Allocator) void {
        if (self.dctx) |dctx| _ = zstd.ZSTD_freeDCtx(dctx);
        allocator.free(self.out_buf);
        self.* = undefined;
    }

    fn nar(self: *Verifier, data: []const u8) void {
        if (self.nar_size < self.head.len) {
            const n = @min(data.len, self.head.len - self.nar_size);
            @memcpy(self.head[self.nar_size..][0..n], data[0..n]);
        }
        self.nar_hasher.update(data);
        self.nar_size += data.len;
    }

    pub fn update(self: *Verifier, data: []const u8) Error!void {
        self.file_hasher.update(data);
        self.file_size += data.len;
        const dctx = self.dctx orelse return self.nar(data);
        var input: zstd.InBuffer = .{ .src = data.ptr, .size = data.len, .pos = 0 };
        while (true) {
            var output: zstd.OutBuffer = .{ .dst = self.out_buf.ptr, .size = self.out_buf.len, .pos = 0 };
            const rc = zstd.ZSTD_decompressStream(dctx, &output, &input);
            if (zstd.isError(rc)) return error.Zstd;
            self.frame_state = rc;
            if (output.pos > 0) self.nar(self.out_buf[0..output.pos]);
            // Done once the input is consumed and zstd has no more buffered output.
            if (input.pos == input.size and output.pos < output.size) break;
        }
    }

    pub fn finish(self: *Verifier) Error!Digest {
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
