const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main pmtr executable
    const pmtr_exe = b.addExecutable(.{
        .name = "pmtr",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    pmtr_exe.linkLibC();
    b.installArtifact(pmtr_exe);

    // onconnect utility
    const onconnect_exe = b.addExecutable(.{
        .name = "onconnect",
        .root_source_file = b.path("src/onconnect.zig"),
        .target = target,
        .optimize = optimize,
    });
    onconnect_exe.linkLibC();
    b.installArtifact(onconnect_exe);

    // Run command for pmtr
    const run_cmd = b.addRunArtifact(pmtr_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run pmtr");
    run_step.dependOn(&run_cmd.step);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.linkLibC();

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
