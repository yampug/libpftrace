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

Requirements: [Zig](https://ziglang.org/) 0.15+ (or latest master).

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
    pftrace_write_clock_snapshot(w, 1000000000);
    pftrace_write_process_track_descriptor(w, 100, 1234, "MyApp");
    pftrace_write_thread_track_descriptor(w, 101, 100, 1234, 5678, "Worker");

    // 2. Events
    pftrace_packet_t* p = pftrace_packet_begin(w);
    pftrace_packet_set_timestamp(p, 1000000500);
    
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

## License

MIT
