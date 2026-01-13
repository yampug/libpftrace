#include "pftrace.h"
#include <stdio.h>

int main() {
  printf("Initializing Domain Specific Trace...\n");
  pftrace_writer_t *w = pftrace_init("domain.pftrace");
  if (!w) {
    printf("Failed to init\n");
    return 1;
  }

  // 1. Metadata: Define Process and Thread
  // Process UUID 100, PID 5000, Name "Renderer"
  pftrace_write_process_track_descriptor(w, 100, 5000, "Renderer");

  // Thread UUID 101, PID 5000, TID 5001, Name "MainThread", Parent Process 100
  pftrace_write_thread_track_descriptor(w, 101, 100, 5000, 5001, "MainThread");

  // 2. Slice on Thread 101
  {
    pftrace_packet_t *p = pftrace_packet_begin(w);
    pftrace_packet_set_timestamp(p, 10000);
    pftrace_packet_set_trusted_packet_sequence_id(p, 42);

    pftrace_track_event_t *te = pftrace_packet_begin_track_event(p);
    pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN);
    pftrace_track_event_set_track_uuid(te, 101); // Refers to Thread 101
    pftrace_track_event_set_name(te, "DrawFrame");

    // Log message associated with this event
    pftrace_track_event_set_log_message(te, "Start drawing now");

    pftrace_track_event_end(te);
    pftrace_packet_end(w, p);
  }

  // 3. Slice End
  {
    pftrace_packet_t *p = pftrace_packet_begin(w);
    pftrace_packet_set_timestamp(p, 20000);
    pftrace_packet_set_trusted_packet_sequence_id(p, 42);

    pftrace_track_event_t *te = pftrace_packet_begin_track_event(p);
    pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_END);
    pftrace_track_event_set_track_uuid(te, 101);

    pftrace_track_event_end(te);
    pftrace_packet_end(w, p);
  }

  pftrace_destroy(w);
  printf("Done. Output: domain.pftrace\n");
  return 0;
}
