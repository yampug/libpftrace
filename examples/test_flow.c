#include "pftrace.h"
#include <stdio.h>

static int check(pftrace_status_t status, const char *operation) {
  if (status == PFTRACE_OK) return 0;
  fprintf(stderr, "%s: %s\n", operation, pftrace_status_string(status));
  return 1;
}

static int write_flow(pftrace_writer_t *writer, uint64_t timestamp, const char *name,
                      int terminating) {
  pftrace_packet_t *packet = pftrace_packet_begin(writer);
  pftrace_track_event_t *event;
  if (packet == NULL) return check(pftrace_writer_status(writer), "packet begin");
  if (check(pftrace_packet_set_timestamp(packet, timestamp), "timestamp") ||
      check(pftrace_packet_set_timestamp_clock_id(packet, PFTRACE_CLOCK_ID_LINUX_BOOTTIME), "clock") ||
      ((event = pftrace_packet_begin_track_event(packet)) == NULL) ||
      check(pftrace_track_event_set_type(event, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN), "event type") ||
      check(pftrace_track_event_set_track_uuid(event, 101), "track") ||
      check(pftrace_track_event_set_name(event, name), "name") ||
      check(terminating ? pftrace_track_event_add_terminating_flow_id(event, 999)
                       : pftrace_track_event_add_flow_id(event, 999), "flow") ||
      check(pftrace_track_event_end(event), "event end") ||
      check(pftrace_packet_commit(packet), "packet commit")) return 1;
  return 0;
}

int main(void) {
  pftrace_writer_t *writer = NULL;
  if (check(pftrace_init_path_with_options("flow.pftrace", NULL, &writer), "path init") ||
      check(pftrace_write_process_track_descriptor(writer, 100, 5000, "Renderer"), "process descriptor") ||
      check(pftrace_write_thread_track_descriptor(writer, 101, 100, 5000, 5001, "MainThread"), "thread descriptor") ||
      check(pftrace_write_linux_boottime_clock_snapshot(writer, 10000), "clock snapshot") ||
      write_flow(writer, 10000, "RequestStart", 0) ||
      write_flow(writer, 20000, "RequestEnd", 1) ||
      check(pftrace_finalize(writer), "finalize") ||
      check(pftrace_destroy(writer), "destroy")) return 1;
  return 0;
}
