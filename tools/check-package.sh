#!/bin/sh
set -eu

for path in \
    LICENSE \
    README.md \
    build.zig \
    build.zig.zon \
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

# Keep public claims aligned with current implementation until bounded writer work
# lands. This is intentionally a documentation check: the public header is the C
# ABI contract and README is the user-facing contract.
for required in \
    'Current allocation and I/O behavior' \
    'exclusive ownership by one thread at a time' \
    'Independent writers may be used concurrently' \
    'their own drain thread' \
    'no worker thread' \
    'exclusive single-thread ownership' \
    'Packet and track-event handles belong to the writer that created them' \
    'must have stopped before lifecycle'
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
