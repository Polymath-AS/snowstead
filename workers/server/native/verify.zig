//! C boundary for the streaming magic/hash/decompression verifier, not a NAR parser.
//! create transfers ownership to the caller; free releases it after any outcome.
const std = @import("std");
const builtin = @import("builtin");
const archive = @import("nix-archive");
const snitch = @import("snitch");
const fast = switch (builtin.target.cpu.arch) {
    .x86_64 => builtin.target.cpu.hasAll(.x86, &.{ .avx2, .sha }),
    .aarch64 => builtin.target.cpu.hasAll(.aarch64, &.{.sha2}),
    else => false,
};

// No async operations are submitted through this I/O implementation. The
// profiler only uses its clock and stderr, including on Rust worker threads.
var profile_io: std.Io.Threaded = .init_single_threaded;

comptime {
    const prefix = if (fast) "sn_fast_" else "sn_";
    @export(&createBounded, .{ .name = prefix ++ "verify_create_bounded" });
    @export(&update, .{ .name = prefix ++ "verify_update" });
    @export(&finish, .{ .name = prefix ++ "verify_finish" });
    @export(&free, .{ .name = prefix ++ "verify_free" });
    if (snitch.enabled) {
        @export(&profileStart, .{ .name = prefix ++ "profile_start" });
        @export(&profileFinish, .{ .name = prefix ++ "profile_finish" });
    }
}

fn profileStart() callconv(.c) void {
    snitch.start(profile_io.io(), std.heap.c_allocator);
}

fn profileFinish() callconv(.c) void {
    snitch.finish(.{});
}

inline fn verifierAllocator() std.mem.Allocator {
    if (comptime snitch.enabled) {
        if (snitch.defaultProfiler() != null) return snitch.allocator();
    }
    return std.heap.c_allocator;
}

// Keep these statuses in sync with src/native.rs. No Zig error crosses the ABI.
const ok: c_int = 0;
const invalid_argument: c_int = 1;
const out_of_memory: c_int = 2;
const zstd_error: c_int = 3;
const truncated: c_int = 4;
const not_nar: c_int = 5;
const size_exceeded: c_int = 6;

fn status(err: anyerror) c_int {
    return switch (err) {
        error.OutOfMemory => out_of_memory,
        error.Zstd => zstd_error,
        error.Truncated => truncated,
        error.NotNar => not_nar,
        error.SizeExceeded => size_exceeded,
        else => unreachable,
    };
}

fn verifier(ptr: *anyopaque) *archive.Verifier {
    return @ptrCast(@alignCast(ptr));
}

fn createBounded(compression: c_int, max_nar_size: u64, out: ?*?*anyopaque) callconv(.c) c_int {
    const zone = snitch.zone("native.verify.create");
    defer zone.end();
    const allocator = verifierAllocator();
    const result = out orelse return invalid_argument;
    result.* = null;
    const mode: archive.Compression = switch (compression) {
        0 => .none,
        1 => .zstd,
        else => return invalid_argument,
    };
    const v = allocator.create(archive.Verifier) catch return out_of_memory;
    v.* = archive.Verifier.initBounded(allocator, mode, max_nar_size) catch |err| {
        allocator.destroy(v);
        return status(err);
    };
    result.* = v;
    return ok;
}

// ptr must be live, exclusively borrowed, and created by sn_verify_create_bounded.
// On error the caller must free it, not resume verification.
fn update(ptr: ?*anyopaque, data: ?[*]const u8, len: usize) callconv(.c) c_int {
    const zone = snitch.zone("native.verify.update");
    defer zone.end();
    const v = verifier(ptr orelse return invalid_argument);
    if (len == 0) return ok;
    const bytes = data orelse return invalid_argument;
    v.update(bytes[0..len]) catch |err| return status(err);
    return ok;
}

// The output is initialized only on success; finish must not be called twice.
fn finish(ptr: ?*anyopaque, out: ?*archive.Digest) callconv(.c) c_int {
    const zone = snitch.zone("native.verify.finish");
    defer zone.end();
    const v = verifier(ptr orelse return invalid_argument);
    const result = out orelse return invalid_argument;
    result.* = v.finish() catch |err| return status(err);
    return ok;
}

fn free(ptr: ?*anyopaque) callconv(.c) void {
    const zone = snitch.zone("native.verify.free");
    defer zone.end();
    const allocator = verifierAllocator();
    const v = verifier(ptr orelse return);
    v.deinit(allocator);
    allocator.destroy(v);
}
