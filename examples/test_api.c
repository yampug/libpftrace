#include "pftrace.h"
#include <stdio.h>

struct memory_sink { size_t calls; size_t bytes; };

static pftrace_status_t write_memory(void *context, const uint8_t *bytes,
                                     size_t size) {
  struct memory_sink *sink = context;
  if (size != 0 && bytes == NULL) return PFTRACE_INVALID_ARGUMENT;
  sink->calls++;
  sink->bytes += size;
  return PFTRACE_OK;
}

static int check(pftrace_status_t status, const char *operation) {
  if (status == PFTRACE_OK) return 0;
  fprintf(stderr, "%s: %s\n", operation, pftrace_status_string(status));
  return 1;
}

int main(void) {
  pftrace_writer_options_t options;
  pftrace_writer_t *writer = NULL;
  struct memory_sink sink = {0};
  const pftrace_event_common_t common = {
      .timestamp_ns = 1000,
      .timestamp_clock_id = PFTRACE_CLOCK_ID_CUSTOM_FIRST,
      .trusted_packet_sequence_id = 42,
      .track_uuid = 101,
  };
  const pftrace_string_t name = { .data = "callback event", .size = 14 };

  if (check(pftrace_writer_options_init(&options), "options init")) return 1;
  options.packet_scratch_capacity = 256;
  options.output_batch_capacity = 256; /* Multiple complete packets batch. */
  options.maximum_packet_bytes = 256;
  if (check(pftrace_init_callback_with_options(write_memory, &sink, &options,
                                               &writer), "callback init")) return 1;
  if (check(pftrace_write_instant(writer, &common, name), "write direct event") ||
      check(pftrace_flush(writer), "flush") ||
      check(pftrace_finalize(writer), "finalize") ||
      check(pftrace_destroy(writer), "destroy")) return 1;
  if (sink.calls == 0 || sink.bytes == 0) {
    fprintf(stderr, "callback did not receive trace bytes\n");
    return 1;
  }
  return 0;
}
