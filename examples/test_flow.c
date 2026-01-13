#include "pftrace.h"
#include <stdio.h>

int main() {
  printf("Initializing Flow Trace...\n");
  pftrace_writer_t *w = pftrace_init("flow.pftrace");
  if (!w) {
    printf("Failed to init\n");
    return 1;
  }

  // Process/Thread Metadata
  pftrace_write_process_track_descriptor(w, 100, 5000, "Renderer");
  pftrace_write_thread_track_descriptor(w, 101, 100, 5000, 5001, "MainThread");

  // Sync Clocks
  pftrace_write_clock_snapshot(w, 10000); // 10000 ns boottime

  // Flow source
  {
    pftrace_packet_t *p = pftrace_packet_begin(w);
    pftrace_packet_set_timestamp(p, 10000);

    pftrace_track_event_t *te = pftrace_packet_begin_track_event(p);
    pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN);
    pftrace_track_event_set_track_uuid(te, 101);
    pftrace_track_event_set_name(te, "RequestStart");
    pftrace_track_event_add_flow_id(te, 999); // Start Flow 999

    pftrace_track_event_end(te);
    pftrace_packet_end(w, p);
  }

  // Flow destination
  {
    pftrace_packet_t *p = pftrace_packet_begin(w);
    pftrace_packet_set_timestamp(p, 20000);

    pftrace_track_event_t *te = pftrace_packet_begin_track_event(p);
    pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN);
    pftrace_track_event_set_track_uuid(te, 101);
    pftrace_track_event_set_name(te, "RequestEnd");
    pftrace_track_event_add_terminating_flow_id(te, 999); // End Flow 999

    // Emulate a posted task completion
    pftrace_track_event_set_task_execution(te, "src/rpc.c", "complete_request",
                                           123);

    pftrace_track_event_end(te);
    pftrace_packet_end(w, p);
  }

  pftrace_destroy(w);
  printf("Done. Output: flow.pftrace\n");
  return 0;
}
