const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const package_check = b.addSystemCommand(&.{ "sh", "tools/check-package.sh" });
    const check_package_step = b.step("check-package", "Verify package files and manifest metadata");
    check_package_step.dependOn(&package_check.step);

    // Create the root module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
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

    // Keep redistribution terms alongside installed library artifacts.
    b.installFile("LICENSE", "LICENSE");

    const proto_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/proto.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const library_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const proto_module = b.createModule(.{
        .root_source_file = b.path("src/proto.zig"),
        .target = target,
        .optimize = optimize,
    });
    const encoder_failure_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/encoder_failure.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "proto", .module = proto_module }},
        }),
    });

    const run_proto_tests = b.addRunArtifact(proto_tests);
    const run_library_tests = b.addRunArtifact(library_tests);
    const run_encoder_failure_tests = b.addRunArtifact(encoder_failure_tests);
    const zig_tests_step = b.step("test-zig", "Run Zig encoder and library unit tests");
    zig_tests_step.dependOn(&run_proto_tests.step);
    zig_tests_step.dependOn(&run_library_tests.step);
    zig_tests_step.dependOn(&run_encoder_failure_tests.step);

    const c_abi_test = b.addExecutable(.{
        .name = "pftrace-c-abi-test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    c_abi_test.root_module.addCSourceFiles(.{
        .files = &.{"tests/c_abi.c"},
        .flags = &.{ "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
    });
    c_abi_test.root_module.addIncludePath(b.path("include"));
    c_abi_test.root_module.linkLibrary(lib);
    const run_c_abi_test = b.addRunArtifact(c_abi_test);
    const c_abi_step = b.step("test-c-abi", "Build and run the C public ABI test");
    c_abi_step.dependOn(&run_c_abi_test.step);

    const cpp_abi_test = b.addExecutable(.{
        .name = "pftrace-cpp-abi-test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });
    cpp_abi_test.root_module.addCSourceFiles(.{
        .files = &.{"tests/cpp_abi.cpp"},
        .flags = &.{ "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
    });
    cpp_abi_test.root_module.addIncludePath(b.path("include"));
    cpp_abi_test.root_module.linkLibrary(lib);
    const run_cpp_abi_test = b.addRunArtifact(cpp_abi_test);
    const cpp_abi_step = b.step("test-cpp-abi", "Build and run the C++ public ABI test");
    cpp_abi_step.dependOn(&run_cpp_abi_test.step);

    const example_names = [_][]const u8{
        "test_api",
        "test_high_level",
        "test_flow",
        "test_big_trace",
    };
    const examples_step = b.step("test-examples", "Build and run maintained C examples");
    for (example_names) |name| {
        const source = b.fmt("examples/{s}.c", .{name});
        const example = b.addExecutable(.{
            .name = b.fmt("pftrace-example-{s}", .{name}),
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        example.root_module.addCSourceFiles(.{
            .files = &.{source},
            .flags = &.{ "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
        });
        example.root_module.addIncludePath(b.path("include"));
        example.root_module.linkLibrary(lib);
        examples_step.dependOn(&b.addRunArtifact(example).step);
    }

    const test_step = b.step("test", "Run all unit and public ABI tests");
    test_step.dependOn(zig_tests_step);
    test_step.dependOn(c_abi_step);
    test_step.dependOn(cpp_abi_step);
    test_step.dependOn(examples_step);
}
