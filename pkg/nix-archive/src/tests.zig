const std = @import("std");
const Sink = @import("sink.zig").Sink;
const Options = @import("sink.zig").Options;
const Verifier = @import("verify.zig").Verifier;

const Collect = struct {
    list: std.ArrayList(u8) = .empty,

    fn write(ctx: ?*anyopaque, buf: [*]const u8, len: usize) callconv(.c) c_int {
        const self: *Collect = @ptrCast(@alignCast(ctx.?));
        self.list.appendSlice(std.testing.allocator, buf[0..len]) catch return 1;
        return 0;
    }
};

fn fakeNar(a: std.mem.Allocator, body_len: usize) ![]u8 {
    var nar: std.ArrayList(u8) = .empty;
    try nar.appendSlice(a, "\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00");
    var prng: std.Random.DefaultPrng = .init(42);
    for (0..body_len) |i| try nar.append(a, if (i % 7 == 0) prng.random().int(u8) else 'x');
    return nar.toOwnedSlice(a);
}

fn roundTrip(level: c_int, threads: c_int, body_len: usize) !void {
    try roundTripWith(.{ .level = level, .threads = threads }, body_len, false);
}

fn roundTripWith(options: Options, body_len: usize, pledge: bool) !void {
    const level = options.level;
    const a = std.testing.allocator;
    const nar = try fakeNar(a, body_len);
    defer a.free(nar);

    var opts = options;
    if (pledge) opts.nar_size = nar.len;
    var out: Collect = .{};
    defer out.list.deinit(a);
    var sink = try Sink.init(a, opts, Collect.write, &out);
    defer sink.deinit(a);
    // Uneven writes exercise the buffering paths.
    var off: usize = 0;
    var step: usize = 1;
    while (off < nar.len) : (step = step * 3 + 1) {
        const n = @min(step, nar.len - off);
        try sink.write(nar[off..][0..n]);
        off += n;
    }
    const produced = try sink.finish();

    var expected_nar: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(nar, &expected_nar, .{});
    try std.testing.expectEqualSlices(u8, &expected_nar, &produced.nar_hash);
    try std.testing.expectEqual(@as(u64, nar.len), produced.nar_size);
    try std.testing.expectEqual(@as(u64, out.list.items.len), produced.file_size);

    var v = try Verifier.init(a, if (level == 0) .none else .zstd);
    defer v.deinit(a);
    var i: usize = 0;
    while (i < out.list.items.len) : (i += 4093) {
        try v.update(out.list.items[i..@min(i + 4093, out.list.items.len)]);
    }
    const verified = try v.finish();
    try std.testing.expectEqualSlices(u8, &produced.nar_hash, &verified.nar_hash);
    try std.testing.expectEqualSlices(u8, &produced.file_hash, &verified.file_hash);
    try std.testing.expectEqual(produced.nar_size, verified.nar_size);
    try std.testing.expectEqual(produced.file_size, verified.file_size);
}

test "compress then verify round-trips" {
    try roundTrip(3, 0, 1000);
    try roundTrip(3, 0, 3 << 20);
    try roundTrip(1, 4, 9 << 20);
    try roundTrip(0, 0, 5000);
}

test "long-distance matching with an exact pledged size round-trips" {
    try roundTripWith(.{ .level = 3, .window_log = 27 }, 3 << 20, true);
    try roundTripWith(.{ .level = 9, .threads = 4, .window_log = 27 }, 9 << 20, true);
    try roundTripWith(.{ .level = 3 }, 1000, true);
}

test "invalid options and mismatched pledges are refused" {
    const a = std.testing.allocator;
    var none: Collect = .{};
    try std.testing.expectError(error.Zstd, Sink.init(a, .{ .window_log = 28 }, Collect.write, &none));

    var out: Collect = .{};
    defer out.list.deinit(a);
    var sink = try Sink.init(a, .{ .nar_size = 10 }, Collect.write, &out);
    defer sink.deinit(a);
    try sink.write("only five");
    try std.testing.expectError(error.Zstd, sink.finish());
}

test "verifier rejects truncated and non-NAR input" {
    const a = std.testing.allocator;
    const nar = try fakeNar(a, 100_000);
    defer a.free(nar);
    var out: Collect = .{};
    defer out.list.deinit(a);
    var sink = try Sink.init(a, .{}, Collect.write, &out);
    defer sink.deinit(a);
    try sink.write(nar);
    _ = try sink.finish();

    var v = try Verifier.init(a, .zstd);
    defer v.deinit(a);
    try v.update(out.list.items[0 .. out.list.items.len / 2]);
    try std.testing.expectError(error.Truncated, v.finish());

    var raw = try Verifier.init(a, .none);
    defer raw.deinit(a);
    try raw.update("definitely not a nar archive....");
    try std.testing.expectError(error.NotNar, raw.finish());
}

test "hash = false writes the same stream and sizes without hashing" {
    const a = std.testing.allocator;
    const nar = try fakeNar(a, 100_000);
    defer a.free(nar);
    var outs: [2]Collect = .{ .{}, .{} };
    defer for (&outs) |*o| o.list.deinit(a);
    var digests: [2]@import("sink.zig").Digest = undefined;
    for ([_]bool{ true, false }, &outs, &digests) |hash, *out, *digest| {
        var sink = try Sink.init(a, .{ .level = 3, .hash = hash }, Collect.write, out);
        defer sink.deinit(a);
        try sink.write(nar);
        digest.* = try sink.finish();
    }
    try std.testing.expectEqualSlices(u8, outs[0].list.items, outs[1].list.items);
    try std.testing.expectEqual(digests[0].nar_size, digests[1].nar_size);
    try std.testing.expectEqual(digests[0].file_size, digests[1].file_size);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0)), &digests[1].nar_hash);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0)), &digests[1].file_hash);
}
