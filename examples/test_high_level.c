#include "pftrace.h"
#include <stdio.h>

static int check(pftrace_status_t status, const char *operation) {
  if (status == PFTRACE_OK) return 0;
  fprintf(stderr, "%s: %s\n", operation, pftrace_status_string(status));
  return 1;
}

int main(void) {
  pftrace_writer_t *writer = NULL;
  pftrace_writer_options_t options;
  const pftrace_string_t name = { .data = "DrawFrame", .size = 9 };
  const pftrace_arg_t arguments[] = {{
      .key = { .data = "frame", .size = 5 },
      .type = PFTRACE_ARG_TYPE_UINT64,
      .value.uint64_value = 1,
  }};
  const pftrace_event_t begin = {
      .timestamp_ns = 10000,
      .timestamp_clock_id = PFTRACE_CLOCK_ID_CUSTOM_FIRST,
      .trusted_packet_sequence_id = 42,
      .track_uuid = 101,
      .type = PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN,
      .name = name,
      .arguments = arguments,
      .argument_count = 1,
  };
  pftrace_event_t end = begin;
  end.timestamp_ns = 20000;
  end.type = PFTRACE_TRACK_EVENT_TYPE_SLICE_END;
  end.arguments = NULL;
  end.argument_count = 0;

  if (check(pftrace_writer_options_init(&options), "options init") ||
      check(pftrace_init_path_with_options("domain.pftrace", &options, &writer), "path init") ||
      check(pftrace_write_clock_snapshot(writer, PFTRACE_CLOCK_ID_CUSTOM_FIRST, 10000), "clock snapshot") ||
      check(pftrace_write_process_track_descriptor(writer, 100, 5000, "Renderer"), "process descriptor") ||
      check(pftrace_write_thread_track_descriptor(writer, 101, 100, 5000, 5001, "MainThread"), "thread descriptor") ||
      check(pftrace_write_event(writer, &begin), "slice begin") ||
      check(pftrace_write_event(writer, &end), "slice end") ||
      check(pftrace_finalize(writer), "finalize") ||
      check(pftrace_destroy(writer), "destroy")) return 1;
  return 0;
}
