#!/bin/sh
set -eu

for path in \
    LICENSE \
    README.md \
    CHANGELOG.md \
    build.zig \
    build.zig.zon \
    bindings/crystal/README.md \
    bindings/crystal/shard.yml \
    bindings/crystal/src/lib_pftrace.cr \
    bindings/crystal/src/pftrace.cr \
    examples/test_api.c \
    include/pftrace.h \
    src/main.zig \
    src/proto.zig \
    src/schema.zig \
    tests/c_abi.c \
    tests/cpp_abi.cpp
do
    if [ ! -f "$path" ]; then
        printf 'missing package path: %s\n' "$path" >&2
        exit 1
    fi
done

if ! grep -Fq '.name = .libpftrace' build.zig.zon ||
    ! grep -Fq '.minimum_zig_version = "0.15.0"' build.zig.zon
then
    printf '%s\n' 'package manifest is missing required libpftrace metadata' >&2
    exit 1
fi

# Keep release package and final public contract aligned. Public header is C ABI
# contract; README is user-facing contract.
for required in \
    'Successful initialization allocates' \
    'Each writer has one exclusive owning thread' \
    'automatic sink writes' \
    'sticky `PFTRACE_IO_ERROR`' \
    'PFTRACE_CLOCK_ID_LINUX_BOOTTIME' \
    'Builder migration'
do
    if ! grep -Fq "$required" README.md include/pftrace.h; then
        printf 'missing public concurrency or behavior contract: %s\n' "$required" >&2
        exit 1
    fi
done

for unsupported_claim in \
    'Zero-Allocation (Critical Path)' \
    'Resource limit enforcement' \
    'Use-After-Free detections'
do
    if grep -Fq "$unsupported_claim" README.md include/pftrace.h; then
        printf 'unsupported public claim: %s\n' "$unsupported_claim" >&2
        exit 1
    fi
done
