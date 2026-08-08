#!/bin/sh
# Build, test, and checksum a clean v0.1.0 source archive. Run only from a
# final committed revision; tagging remains a deliberate release-owner action.
set -eu

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$source_dir/zig-out/release"}
zig_bin=${RELEASE_ZIG:-zig}
expected_zig=${RELEASE_ZIG_VERSION:-0.15.0}
require_crystal=${RELEASE_REQUIRE_CRYSTAL:-1}
release_commit=${RELEASE_COMMIT:-$(git -C "$source_dir" rev-parse HEAD)}
version=$(sed -nE 's/^[[:space:]]*\.version = "([^"]+)",/\1/p' "$source_dir/build.zig.zon")

test -n "$version"
if test -n "$(git -C "$source_dir" status --porcelain)"; then
  echo 'release validation requires a clean worktree at the final release commit' >&2
  exit 1
fi
actual_zig=$($zig_bin version)
case "$actual_zig" in "$expected_zig"|"$expected_zig"-*) ;; *)
  echo "release validation requires Zig $expected_zig; got $actual_zig" >&2
  exit 1
esac

if [ "${#release_commit}" -ne 40 ]; then
  echo "RELEASE_COMMIT must be a full 40-character Git object ID" >&2
  exit 1
fi
case "$release_commit" in *[!0123456789abcdef]*)
  echo "RELEASE_COMMIT must be a full 40-character Git object ID" >&2
  exit 1
esac
git -C "$source_dir" cat-file -e "$release_commit^{commit}"

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/libpftrace-release.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
archive_root="$tmpdir/libpftrace-$version"
checkout_root="$tmpdir/checkout"
mkdir -p "$archive_root" "$output_dir"
mkdir -p "$checkout_root"
git -C "$source_dir" archive "$release_commit" | tar -xf - -C "$checkout_root"

# Explicit copy list mirrors build.zig.zon's declared release paths. No build
# directory is copied, so all tests execute from a clean source archive.
for path in LICENSE README.md CHANGELOG.md build.zig build.zig.zon bindings examples include src tests tools; do
  cp -R "$checkout_root/$path" "$archive_root/$path"
done

archive="$output_dir/libpftrace-$version.tar.gz"
tar -czf "$archive" -C "$tmpdir" "libpftrace-$version"
if command -v sha256sum >/dev/null 2>&1; then
  checksum=$(sha256sum "$archive" | awk '{print $1}')
else
  checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
printf '%s  %s\n' "$checksum" "$(basename "$archive")" > "$archive.sha256"

for path in LICENSE README.md CHANGELOG.md build.zig build.zig.zon \
    bindings/crystal/src/pftrace.cr examples/test_high_level.c include/pftrace.h \
    src/main.zig tests/abi/expected_symbols.txt tools/release-validate.sh; do
  tar -tzf "$archive" | grep -Fx "libpftrace-$version/$path" >/dev/null
done

(
  cd "$archive_root"
  "$zig_bin" build check-package
  "$zig_bin" build test
  "$zig_bin" build test-abi
  "$zig_bin" build check-linux-aarch64
  "$zig_bin" build check-macos-aarch64
  if command -v crystal >/dev/null 2>&1; then
    crystal spec bindings/crystal/spec
  elif [ "$require_crystal" = 1 ]; then
    echo 'Crystal is required for release validation but is unavailable' >&2
    exit 1
  fi
  "$zig_bin" build test-perfetto
)

printf 'archive: %s\nsha256: %s\nvalidated commit: %s\n' "$archive" "$checksum" "$release_commit"
