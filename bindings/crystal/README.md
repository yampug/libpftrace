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

`LibPftrace` mirrors public status, string, options, callback-sink, direct-event,
argument, clock, and lifecycle ABI types. C calls borrow Crystal strings and
direct-event arrays only for their synchronous duration; do not retain such
pointers in callbacks after the call returns. Callback contexts remain owned by
the Crystal caller for the writer lifetime.

Run binding specs after building root static library:

```bash
zig build
crystal spec bindings/crystal/spec
```

## Internal Details

The bindings link statically against `libpftrace.a`. The link path is currently hardcoded relative to the source files (`../../../zig-out/lib`). If you move this directory, you may need to adjust the `@Link` annotation in `src/lib_pftrace.cr`.
