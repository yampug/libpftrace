#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <static-library> <expected-symbol-manifest>" >&2
  exit 2
fi

library=$1
expected=$2
actual=$(mktemp "${TMPDIR:-/tmp}/pftrace-symbols.XXXXXX")
trap 'rm -f "$actual"' EXIT HUP INT TERM

case "$(uname -s)" in
  Darwin) nm -gU "$library" ;;
  *) nm -g --defined-only "$library" ;;
esac | awk '$2 == "T" {
  symbol = $3
  sub(/^_/, "", symbol)
  if (symbol ~ /^pftrace_/) print symbol
}' | LC_ALL=C sort -u > "$actual"

if ! cmp -s "$expected" "$actual"; then
  echo "public exported-symbol manifest changed: $expected" >&2
  diff -u "$expected" "$actual" >&2 || true
  echo "Review intentional ABI changes and update manifest with release notes." >&2
  exit 1
fi
