# libpftrace

A high-performance, **zero-dependency** Zig library that implements a high-level, domain-specific C API for generating Perfetto `.pftrace` files.

`libpftrace` abstracts away all Protocol Buffer internals, allowing you to instrument C/C++ (or any language with C FFI) applications with rich tracing capabilities (Flows, Tracks, Arguments) without linking against the massive official Perfetto SDK or `protobuf-lite`.

## Features

- **Zero-Allocation (Critical Path)**: Designed for low-overhead tracing.
- **Protobuf-Free**: No external dependencies; implements a minimal internal encoder.
- **Rich API**:
    - **Custom Tracks**: Process and Thread track descriptors.
    - **Flows**: Link events across threads and processes.
    - **Structured Data**: Typed arguments (int, string, bool, double), Log messages, Counters.
    - **Tasks**: `TaskExecution` support with source location interning.
- **Robust & Secure**:
    - Strict input validation (NULL checks).
    - Resource limit enforcement (max message size checks).
    - Use-After-Free detections (Magic Number safeguards).

## Usage

### Building

Requirements: [Zig](https://ziglang.org/) 0.15.0.

Newer Zig releases are supported only after CI passes for that release. The
current development head is not an implicit supported version.

```bash
zig build
# Produces zig-out/lib/libpftrace.a
```

### C API Example

```c
#include "pftrace.h"

int main() {
    pftrace_writer_t* w = pftrace_init("trace.pftrace");
    if (!w) return 1;

    // 1. Metadata
    pftrace_write_linux_boottime_clock_snapshot(w, 1000000000);
    pftrace_write_process_track_descriptor(w, 100, 1234, "MyApp");
    pftrace_write_thread_track_descriptor(w, 101, 100, 1234, 5678, "Worker");

    // 2. Events
    pftrace_packet_t* p = pftrace_packet_begin(w);
    pftrace_packet_set_timestamp(p, 1000000500);
    pftrace_packet_set_timestamp_clock_id(p, PFTRACE_CLOCK_ID_LINUX_BOOTTIME);
    
    pftrace_track_event_t* te = pftrace_packet_begin_track_event(p);
    pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN);
    pftrace_track_event_set_track_uuid(te, 101);
    pftrace_track_event_set_name(te, "DoWork");
    
    // Arguments
    pftrace_track_event_add_arg_string(te, "user_id", "u-123");
    pftrace_track_event_add_arg_int(te, "payload_size", 4096);
    
    // Flows
    pftrace_track_event_add_flow_id(te, 99);

    pftrace_track_event_end(te);
    pftrace_packet_end(w, p);

    pftrace_destroy(w);
    return 0;
}
```

## Examples

Check the `examples/` directory for full test programs.

## Clocks

All timestamps are nanoseconds. `pftrace_write_clock_snapshot` accepts a
caller-selected Perfetto clock ID and timestamp; use built-in Perfetto IDs only
for their documented clock domains. `PFTRACE_CLOCK_ID_LINUX_BOOTTIME` (6) is
Linux `CLOCK_BOOTTIME` only. Use
`pftrace_write_linux_boottime_clock_snapshot` only for that source; do not map
macOS or another platform's arbitrary monotonic clock to ID 6.

Application-defined clocks start at `PFTRACE_CLOCK_ID_CUSTOM_FIRST` (64). Set
the matching packet ID with `pftrace_packet_set_timestamp_clock_id` or the
direct event's `timestamp_clock_id`. Application-defined clock IDs are
process-local unless application supplies its own correlation; libpftrace does
not synchronize clocks across processes or machines.

## License

[MIT](LICENSE). Copyright (c) 2026 yampug.

## Perfetto compatibility suite

`zig build test-perfetto` generates deterministic direct and builder fixtures,
then queries them with Perfetto trace processor SQL. It needs release **v57.2**
`trace_processor_shell`; set `PERFETTO_TRACE_PROCESSOR` to its executable when
it is not on `PATH`. Missing or wrong-version tools fail clearly, rather than
silently skipping compatibility tests.

Pin source: [Perfetto v57.2 release](https://github.com/google/perfetto/releases/tag/v57.2).
Recorded release-archive SHA-256 values: Linux amd64
`a5354a4a133cc629bb398da53c95515e5a49d4bd96edfebe1ebc3221c85d936f`; macOS
arm64 `f0f282ef199a2942ee5286856cd57260b11e93f95fdd80e3ffafe2f56ed936de`.
To update: download target release archive, verify its SHA-256, extract
`trace_processor_shell`, update version/checksum here and `tests/perfetto/run.sh`,
then run `zig build test-perfetto`.
