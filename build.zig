const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the root module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Library: libpftrace
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "pftrace",
        .root_module = lib_mod,
    });

    // Install the static library (zig-out/lib/libpftrace.a)
    b.installArtifact(lib);

    // Install the public header (zig-out/include/pftrace.h)
    b.installFile("include/pftrace.h", "include/pftrace.h");
}
