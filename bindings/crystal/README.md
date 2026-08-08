# libpftrace-crystal

Crystal bindings for [libpftrace](https://github.com/yourusername/libpftrace).

## Installation

### Local Path Dependency
Since this shard relies on the `libpftrace.a` static library built from the root of the repository, the easiest way to use it is via a local path dependency.

1.  Ensure you have built the C library in the root of the repo:
    ```bash
    cd /path/to/libpftrace
    zig build
    ```

2.  Add the dependency to your project's `shard.yml`:
    ```yaml
    dependencies:
      pftrace:
        path: /path/to/libpftrace/bindings/crystal
    ```

3.  Run `shards install`.

## Usage

```crystal
require "pftrace"

Pftrace.open("trace.pftrace") do |ctx|
  # Metadata
  ctx.write_process_descriptor(100, "MyProcess")
  ctx.write_thread_descriptor(100, 101, "Worker")

  # Tracing
  ctx.trace("MyEvent", type: Pftrace::EventType::SliceBegin) do |ev|
    ev.arg("key", "value")
    ev.arg("counter", 123)
  end
  # ... work ...
  ctx.trace("MyEvent", type: :slice_end)
end
```

Every C status is checked by the high-level API. Failures raise
`Pftrace::Error`, whose `status` is the original `LibPftrace::Status` value.
`Trace#finalize` flushes and seals the writer; `Trace#close` releases it.
`Pftrace.open` performs both in that order. Event wrappers are invalidated when
their block ends and raise `PFTRACE_INVALID_STATE` if reused.

`Trace` is single-writer: use one Crystal thread/fiber execution context at a
time for a writer and do not retain an event outside its block. `finalize` and
`close` reject active C builder construction. A finalized writer cannot accept
new mutations. `PFTRACE_IO_ERROR` from a sink is terminal and sticky; other
status failures are recoverable after caller corrects input or capacity.

For bounded writers, initialize options before changing them:

```crystal
options = Pftrace::Trace.default_options
options.packet_scratch_capacity = 64 * 1024
options.output_batch_capacity = 64 * 1024
options.maximum_packet_bytes = 64 * 1024

Pftrace.open("trace.pftrace", options) do |trace|
  trace.write_clock_snapshot(LibPftrace::CLOCK_ID_CUSTOM_FIRST, 1_000)
end
```

Defaults reserve 1 MiB each for packet scratch/output batch/max packet/max
string, 1024 each for arguments/categories/flow kinds, depth 64, unlimited
trace bytes, and batch by default. `maximum_packet_bytes` must fit both buffers.
Writer initialization allocates bookkeeping and those two configured buffers;
normal direct events, descriptors, clocks, builder calls, flush, and finalize
do not allocate. Complete packets batch until full or `flush_each_packet`;
automatic flushes, `Trace#flush`, and `Trace#finalize` can block in sink I/O.
Use application-owned drain scheduling when isolation is required.

Crystal `Trace#trace` uses status-aware builder API. For lowest-overhead common
events, construct `LibPftrace::Event` and call `LibPftrace.write_event`, then
pass result through `Pftrace.check!`; the C call borrows event and array memory
only synchronously. Strings may contain embedded NUL bytes through
`LibPftrace::String`; NUL C wrappers are bounded to 1 MiB plus terminator.

Path initialization owns/closes path file. FD initialization borrows descriptor.
Callback function/context stay caller-owned for writer lifetime and must report
success only after consuming full buffer. Clock timestamps are nanoseconds;
clock ID 6 is Linux `CLOCK_BOOTTIME` only, while application clock IDs begin at
`LibPftrace::CLOCK_ID_CUSTOM_FIRST` (64). libpftrace does not synchronize clocks.

Migration: old pointer-only `pftrace_init` has no error result; use options-aware
constructors. C/C++ must check every mutation status; Crystal high-level methods
already raise `Pftrace::Error`. Prefer direct events where their data model fits,
otherwise use `Trace#trace` and let its block close event before packet commit.

Run binding specs after building root static library:

```bash
zig build
crystal spec bindings/crystal/spec
```

## Internal Details

The bindings link statically against `libpftrace.a`. The link path is currently hardcoded relative to the source files (`../../../zig-out/lib`). If you move this directory, you may need to adjust the `@Link` annotation in `src/lib_pftrace.cr`.
