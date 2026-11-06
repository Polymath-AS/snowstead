const std = @import("std");

pub fn build(b: *std.Build) void {
    const options = b.addOptions();
    options.addOption(bool, "snitch", b.option(bool, "snitch", "Enable profiling") orelse false);
    options.addOption(bool, "snitch_timing", true);
    options.addOption(bool, "snitch_memory", true);
    _ = b.addModule("snitch", .{
        .root_source_file = b.path("src/snitch.zig"),
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
        .imports = &.{.{ .name = "build_options", .module = options.createModule() }},
    });
}
