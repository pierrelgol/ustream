const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{},
    });

    const exe = b.addExecutable(.{
        .name = "ustream",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const check = b.addExecutable(.{
        .name = "ustream",
        .root_module = exe_mod,
    });

    const convert = b.step("convert", "convert input.mp4 into Annex-B h264");

    const convert_command = b.addSystemCommand(&.{
        "ffmpeg",
        "-i",
        "./input.mp4",
        "-map",
        "0:v:0",
        "-c:v",
        "copy",
        "-bsf:v",
        "h264_mp4toannexb",
        "input.h264",
    });
    convert.dependOn(&convert_command.step);

    const play = b.step("play", "Run ffplay, to see the output of the server");

    const play_command = b.addSystemCommand(&.{
        "ffplay",
        "-protocol_whitelist",
        "file,udp,rtp",
        "session.sdp",
    });

    play.dependOn(&play_command.step);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    run_cmd.addFileArg(b.path("input.h264"));
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);

    const check_step = b.step("check", "Run checks");
    check_step.dependOn(&check.step);
}
