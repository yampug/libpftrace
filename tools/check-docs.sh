#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
readme="$root/README.md"
header="$root/include/pftrace.h"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/pftrace-docs.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

for name in direct builder; do
  awk -v name="$name" '
    $0 == "<!-- doc-check: " name " -->" { on = 1; next }
    on && $0 == "<!-- /doc-check -->" { exit }
    on && $0 == "```c" { code = 1; next }
    on && code && $0 == "```" { exit }
    code { print }
  ' "$readme" > "$tmpdir/$name.c"
  test -s "$tmpdir/$name.c"
  cc -std=c17 -Wall -Wextra -Werror -pedantic -I"$root/include" -fsyntax-only "$tmpdir/$name.c"
done

symbols=$(rg -oP 'pftrace_[A-Za-z0-9_]+(?=\s*\()' "$header" | sort -u)
missing=0
for symbol in $symbols; do
  if ! grep -Fq "$symbol" "$readme"; then
    echo "README API inventory missing $symbol" >&2
    missing=1
  fi
done
test "$missing" -eq 0
