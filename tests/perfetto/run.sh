#!/bin/sh
set -eu

# Perfetto v57.2. See README for release archive checksums and update steps.
generator=${1:?missing fixture generator}
tool=${PERFETTO_TRACE_PROCESSOR:-}
if [ -z "$tool" ]; then
  tool=$(command -v trace_processor_shell || true)
fi
if [ -z "$tool" ] || [ ! -x "$tool" ]; then
  echo "test-perfetto: missing pinned Perfetto v57.2 trace_processor_shell; set PERFETTO_TRACE_PROCESSOR=/path/to/trace_processor_shell" >&2
  exit 2
fi
if ! "$tool" --version 2>&1 | grep -q 'v57\.2'; then
  echo "test-perfetto: need Perfetto trace_processor_shell v57.2" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/libpftrace-perfetto.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
valid="$work/valid.pftrace"
prefix="$work/rejected-prefix.pftrace"
"$generator" "$valid" "$prefix"

assert_trace() {
  sql=$1
  trace=$2
  output="$work/query.csv"
  "$tool" query -f "$sql" "$trace" >"$output" 2>"$work/stderr"
  expected=$(grep -c '^SELECT ' "$sql")
  if grep -qi 'corrupt\|malformed\|error' "$work/stderr" || [ "$(grep -c '"ok"' "$output")" -ne "$expected" ]; then
    echo "test-perfetto: semantic assertion or parser corruption warning for $trace" >&2
    cat "$work/stderr" >&2
    cat "$output" >&2
    return 1
  fi
}
assert_trace tests/perfetto/expected.sql "$valid"
assert_trace tests/perfetto/rejected_prefix.sql "$prefix"

# Negative control: truncate mid-packet. Same semantic SQL must not pass.
size=$(wc -c <"$valid")
cut=$((size - 1))
dd if="$valid" of="$work/truncated.pftrace" bs=1 count="$cut" 2>/dev/null
if assert_trace tests/perfetto/expected.sql "$work/truncated.pftrace"; then
  echo "test-perfetto: truncated control unexpectedly passed" >&2
  exit 1
fi
