//! Multi-block SHA-256 for x86-64 SHA-NI.
//!
//! std's SHA-NI path compresses one block per call: it loads and shuffles
//! the state from memory, runs the rounds, and stores it back, every 64
//! bytes. Here the state stays in two xmm registers (ABEF / CDGH) for the
//! whole buffer, and message words are byte-swapped with one shuffle per
//! 16 bytes. The per-block instruction sequence is std's. Without SHA-NI
//! this is std's implementation.

const std = @import("std");
const builtin = @import("builtin");

pub const accelerated = builtin.target.cpu.arch == .x86_64 and
    builtin.zig_backend != .stage2_c and
    builtin.target.cpu.hasAll(.x86, &.{ .sha, .avx2 });

pub const Sha256 = if (accelerated) Fast else std.crypto.hash.sha2.Sha256;

const V4u32 = @Vector(4, u32);

const K = [64]u32{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

const iv = [8]u32{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

inline fn loadBe(bytes: *const [16]u8) V4u32 {
    const v: @Vector(16, u8) = bytes.*;
    const swapped = @shuffle(u8, v, undefined, [16]i32{ 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 });
    return @bitCast(swapped);
}

/// Compresses `blocks` (a multiple of 64 bytes) into `state`.
fn compress(state: *[8]u32, blocks: []const u8) void {
    var x: V4u32 = .{ state[5], state[4], state[1], state[0] };
    var y: V4u32 = .{ state[7], state[6], state[3], state[2] };
    var off: usize = 0;
    while (off < blocks.len) : (off += 64) {
        const x0 = x;
        const y0 = y;
        var m: [16]V4u32 = undefined;
        inline for (0..4) |i| m[i] = loadBe(blocks[off + 16 * i ..][0..16]);

        inline for (0..16) |k| {
            if (k < 12) {
                var tmp = m[k];
                m[k + 4] = asm (
                    \\ sha256msg1 %[w4_7], %[tmp]
                    \\ vpalignr $0x4, %[w8_11], %[w12_15], %[result]
                    \\ paddd %[tmp], %[result]
                    \\ sha256msg2 %[w12_15], %[result]
                    : [tmp] "=&x" (tmp),
                      [result] "=&x" (-> V4u32),
                    : [_] "0" (tmp),
                      [w4_7] "x" (m[k + 1]),
                      [w8_11] "x" (m[k + 2]),
                      [w12_15] "x" (m[k + 3]),
                );
            }
            const w: V4u32 = m[k] +% @as(V4u32, K[4 * k ..][0..4].*);
            y = asm ("sha256rnds2 %[x], %[y]"
                : [y] "=x" (-> V4u32),
                : [_] "0" (y),
                  [x] "x" (x),
                  [_] "{xmm0}" (w),
            );
            x = asm ("sha256rnds2 %[y], %[x]"
                : [x] "=x" (-> V4u32),
                : [_] "0" (x),
                  [y] "x" (y),
                  [_] "{xmm0}" (@as(V4u32, @bitCast(@as(u128, @bitCast(w)) >> 64))),
            );
        }
        x +%= x0;
        y +%= y0;
    }
    state[0] = x[3];
    state[1] = x[2];
    state[4] = x[1];
    state[5] = x[0];
    state[2] = y[3];
    state[3] = y[2];
    state[6] = y[1];
    state[7] = y[0];
}

pub const Fast = struct {
    pub const digest_length = 32;
    pub const Options = struct {};

    s: [8]u32 = iv,
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init(_: Options) Fast {
        return .{};
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Fast.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Fast, b: []const u8) void {
        var off: usize = 0;
        if (d.buf_len != 0) {
            const take = @min(64 - d.buf_len, b.len);
            @memcpy(d.buf[d.buf_len..][0..take], b[0..take]);
            d.buf_len += @intCast(take);
            off = take;
            if (d.buf_len < 64) {
                d.total_len += b.len;
                return;
            }
            compress(&d.s, &d.buf);
            d.buf_len = 0;
        }
        const full = (b.len - off) / 64 * 64;
        if (full > 0) compress(&d.s, b[off..][0..full]);
        off += full;
        const rest = b[off..];
        @memcpy(d.buf[0..rest.len], rest);
        d.buf_len = @intCast(rest.len);
        d.total_len += b.len;
    }

    pub fn final(d: *Fast, out: *[digest_length]u8) void {
        const bits = d.total_len * 8;
        d.buf[d.buf_len] = 0x80;
        @memset(d.buf[d.buf_len + 1 ..], 0);
        if (d.buf_len >= 56) {
            compress(&d.s, &d.buf);
            @memset(&d.buf, 0);
        }
        std.mem.writeInt(u64, d.buf[56..64], bits, .big);
        compress(&d.s, &d.buf);
        for (d.s, 0..) |word, i| std.mem.writeInt(u32, out[4 * i ..][0..4], word, .big);
    }
};

test "matches std SHA-256 for every length and split" {
    const Std = std.crypto.hash.sha2.Sha256;
    var prng: std.Random.DefaultPrng = .init(9);
    const r = prng.random();
    var data: [1000]u8 = undefined;
    r.bytes(&data);
    for (0..data.len) |n| {
        var want: [32]u8 = undefined;
        Std.hash(data[0..n], &want, .{});
        var got: [32]u8 = undefined;
        Sha256.hash(data[0..n], &got, .{});
        try std.testing.expectEqualSlices(u8, &want, &got);

        var h = Sha256.init(.{});
        var off: usize = 0;
        while (off < n) {
            const step = @min(n - off, r.uintAtMost(usize, 150));
            h.update(data[off..][0..step]);
            off += step;
        }
        h.final(&got);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}
