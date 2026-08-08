const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const package_check = b.addSystemCommand(&.{ "sh", "tools/check-package.sh" });
    const check_package_step = b.step("check-package", "Verify package files and manifest metadata");
    check_package_step.dependOn(&package_check.step);

    const documentation_check = b.addSystemCommand(&.{ "sh", "tools/check-docs.sh" });
    const documentation_step = b.step("test-docs", "Compile README C snippets and check public API inventory");
    documentation_step.dependOn(&documentation_check.step);

    const release_validation = b.addSystemCommand(&.{ "sh", "tools/release-validate.sh" });
    const release_validation_step = b.step("release-validate", "Build and validate clean source archive (requires Zig 0.15.0 and Perfetto)");
    release_validation_step.dependOn(&release_validation.step);

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

    // Release ABI gates compile the installed public header without attempting
    // to run target binaries. Runtime coverage stays on native test hosts.
    const linux_aarch64 = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .gnu,
    });
    const macos_aarch64 = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .macos,
    });

    const linux_aarch64_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "pftrace-linux-aarch64",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = linux_aarch64,
            .optimize = optimize,
            .pic = true,
        }),
    });
    const macos_aarch64_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "pftrace-macos-aarch64",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = macos_aarch64,
            .optimize = optimize,
            .pic = true,
        }),
    });

    const linux_aarch64_layout = b.addObject(.{
        .name = "pftrace-public-layout-linux-aarch64",
        .root_module = b.createModule(.{
            .target = linux_aarch64,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    linux_aarch64_layout.root_module.addCSourceFiles(.{
        .files = &.{"tests/abi/public_layout.c"},
        .flags = &.{ "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
    });
    linux_aarch64_layout.root_module.addIncludePath(b.path("include"));

    const macos_aarch64_layout = b.addObject(.{
        .name = "pftrace-public-layout-macos-aarch64",
        .root_module = b.createModule(.{
            .target = macos_aarch64,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    macos_aarch64_layout.root_module.addCSourceFiles(.{
        .files = &.{"tests/abi/public_layout.c"},
        .flags = &.{ "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
    });
    macos_aarch64_layout.root_module.addIncludePath(b.path("include"));

    const linux_aarch64_step = b.step("check-linux-aarch64", "Compile library and public header for Linux aarch64 (no runtime test)");
    linux_aarch64_step.dependOn(&linux_aarch64_lib.step);
    linux_aarch64_step.dependOn(&linux_aarch64_layout.step);
    const macos_aarch64_step = b.step("check-macos-aarch64", "Compile library and public header for macOS arm64 (no runtime test)");
    macos_aarch64_step.dependOn(&macos_aarch64_lib.step);
    macos_aarch64_step.dependOn(&macos_aarch64_layout.step);

    const native_layout = b.addObject(.{
        .name = "pftrace-public-layout-native",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    native_layout.root_module.addCSourceFiles(.{
        .files = &.{"tests/abi/public_layout.c"},
        .flags = &.{ "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
    });
    native_layout.root_module.addIncludePath(b.path("include"));
    const exported_symbols = b.addSystemCommand(&.{ "sh", "tests/abi/check-symbols.sh" });
    exported_symbols.addFileArg(lib.getEmittedBin());
    exported_symbols.addFileArg(b.path("tests/abi/expected_symbols.txt"));
    const abi_step = b.step("test-abi", "Check exported symbols and public C ABI layout");
    abi_step.dependOn(&native_layout.step);
    abi_step.dependOn(&exported_symbols.step);

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
    const writer_failure_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/writer_failure.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "pftrace", .module = lib_mod }},
        }),
    });
    const run_writer_failure_tests = b.addRunArtifact(writer_failure_tests);
    const zig_tests_step = b.step("test-zig", "Run Zig encoder and library unit tests");
    zig_tests_step.dependOn(&run_proto_tests.step);
    zig_tests_step.dependOn(&run_library_tests.step);
    zig_tests_step.dependOn(&run_encoder_failure_tests.step);
    const writer_failure_step = b.step("test-writer-failure", "Run deterministic writer sink failure tests");
    writer_failure_step.dependOn(&run_writer_failure_tests.step);

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

    const c_api_failures = b.addExecutable(.{
        .name = "pftrace-c-api-failures",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    c_api_failures.root_module.addCSourceFiles(.{
        .files = &.{"tests/c_api_failures.c"},
        .flags = &.{ "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
    });
    c_api_failures.root_module.addIncludePath(b.path("include"));
    c_api_failures.root_module.linkLibrary(lib);
    const run_c_api_failures = b.addRunArtifact(c_api_failures);
    const c_api_failures_step = b.step("test-c-api-failures", "Run C public API failure matrix");
    c_api_failures_step.dependOn(&run_c_api_failures.step);

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

    const perfetto_fixture_generator = b.addExecutable(.{
        .name = "pftrace-perfetto-fixtures",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    perfetto_fixture_generator.root_module.addCSourceFiles(.{
        .files = &.{"tests/fixtures/generate.c"},
        .flags = &.{ "-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic" },
    });
    perfetto_fixture_generator.root_module.addIncludePath(b.path("include"));
    perfetto_fixture_generator.root_module.linkLibrary(lib);
    const perfetto_test = b.addSystemCommand(&.{ "sh", "tests/perfetto/run.sh" });
    perfetto_test.addFileArg(perfetto_fixture_generator.getEmittedBin());
    const perfetto_step = b.step("test-perfetto", "Run pinned Perfetto trace-processor compatibility suite");
    perfetto_step.dependOn(&perfetto_test.step);

    const test_step = b.step("test", "Run all unit and public ABI tests");
    test_step.dependOn(zig_tests_step);
    test_step.dependOn(c_abi_step);
    test_step.dependOn(c_api_failures_step);
    test_step.dependOn(writer_failure_step);
    test_step.dependOn(cpp_abi_step);
    test_step.dependOn(examples_step);
    test_step.dependOn(abi_step);
    test_step.dependOn(documentation_step);
}
