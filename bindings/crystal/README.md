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
  ctx.trace("MyEvent", type: :slice_begin) do |ev|
    ev.arg("key", "value")
    ev.arg("counter", 123)
  end
  # ... work ...
  ctx.trace("MyEvent", type: :slice_end)
end
```

## Internal Details

The bindings link statically against `libpftrace.a`. The link path is currently hardcoded relative to the source files (`../../../zig-out/lib`). If you move this directory, you may need to adjust the `@Link` annotation in `src/lib_pftrace.cr`.
