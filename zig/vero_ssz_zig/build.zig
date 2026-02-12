const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "vero_ssz_zig",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);

    const run_step = b.step("build-lib", "Build shared library");
    run_step.dependOn(&lib.step);
}
