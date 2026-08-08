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
    src/schema.zig
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
