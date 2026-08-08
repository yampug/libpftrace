#include "pftrace.h"
#include <stdio.h>

static int check(pftrace_status_t status, const char *operation) {
  if (status == PFTRACE_OK) return 0;
  fprintf(stderr, "%s: %s\n", operation, pftrace_status_string(status));
  return 1;
}

int main(void) {
  pftrace_writer_options_t options;
  pftrace_writer_t *writer = NULL;
  char name[32];
  if (check(pftrace_writer_options_init(&options), "options init")) return 1;
  options.packet_scratch_capacity = 64 * 1024;
  options.output_batch_capacity = 64 * 1024;
  options.maximum_packet_bytes = 64 * 1024;
  if (check(pftrace_init_path_with_options("big_trace.pftrace", &options, &writer), "path init") ||
      check(pftrace_write_clock_snapshot(writer, PFTRACE_CLOCK_ID_CUSTOM_FIRST, 1000000000), "clock snapshot") ||
      check(pftrace_write_process_track_descriptor(writer, 100, 1234, "StressTestProcess"), "process descriptor") ||
      check(pftrace_write_thread_track_descriptor(writer, 101, 100, 1234, 5678, "WorkerThread"), "thread descriptor")) return 1;
  for (unsigned i = 0; i < 1000; ++i) {
    const int length = snprintf(name, sizeof(name), "iteration_%u", i);
    const pftrace_event_common_t common = {
        .timestamp_ns = 1000000000ULL + (uint64_t)i * 100000,
        .timestamp_clock_id = PFTRACE_CLOCK_ID_CUSTOM_FIRST,
        .trusted_packet_sequence_id = 1,
        .track_uuid = 101,
    };
    const pftrace_string_t event_name = { .data = name, .size = (size_t)length };
    if (length < 0 || (size_t)length >= sizeof(name) ||
        check(pftrace_write_instant(writer, &common, event_name), "write event")) {
      (void)pftrace_destroy(writer);
      return 1;
    }
  }
  if (check(pftrace_finalize(writer), "finalize") || check(pftrace_destroy(writer), "destroy")) return 1;
  return 0;
}
