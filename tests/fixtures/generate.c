#include "pftrace.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define STR(s) ((pftrace_string_t){(s), sizeof(s) - 1})
#define CHECK(call) do { if ((call) != PFTRACE_OK) goto fail; } while (0)

static int write_valid(const char *path) {
  pftrace_writer_options_t options;
  pftrace_writer_t *writer = NULL;
  uint64_t flows[] = { 41, 42 };
  uint64_t ending_flows[] = { 41, 42 };
  pftrace_string_t categories[] = { STR("compat"), STR("fixture") };
  pftrace_arg_t args[] = {
    { STR("string"), PFTRACE_ARG_TYPE_STRING, { .string_value = STR("value") } },
    { STR("int_min"), PFTRACE_ARG_TYPE_INT64, { .int64_value = INT64_MIN } },
    { STR("int_max"), PFTRACE_ARG_TYPE_INT64, { .int64_value = INT64_MAX } },
    { STR("uint_max"), PFTRACE_ARG_TYPE_UINT64, { .uint64_value = UINT64_MAX } },
    { STR("double"), PFTRACE_ARG_TYPE_DOUBLE, { .double_value = 3.5 } },
    { STR("bool"), PFTRACE_ARG_TYPE_BOOL, { .bool_value = true } },
    { STR("pointer"), PFTRACE_ARG_TYPE_POINTER, { .pointer_value = UINT64_C(0x1234) } },
  };
  pftrace_event_t event = {
    .timestamp_ns = 1000,
    .timestamp_clock_id = PFTRACE_CLOCK_ID_CUSTOM_FIRST,
    .trusted_packet_sequence_id = 7,
    .track_uuid = 101,
    .type = PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN,
    .name = STR("direct_begin"),
    .flow_ids = flows, .flow_id_count = 2,
    .categories = categories, .category_count = 2,
    .arguments = args, .argument_count = sizeof(args) / sizeof(args[0]),
  };

  CHECK(pftrace_writer_options_init(&options));
  options.flush_each_packet = true;
  CHECK(pftrace_init_path_with_options(path, &options, &writer));
  CHECK(pftrace_write_clock_snapshot(writer, PFTRACE_CLOCK_ID_CUSTOM_FIRST, 900));
  CHECK(pftrace_write_linux_boottime_clock_snapshot(writer, 800));
  CHECK(pftrace_write_process_track_descriptor(writer, 100, 123, "compat-process"));
  CHECK(pftrace_write_thread_track_descriptor(writer, 101, 100, 123, 456, "compat-thread"));
  CHECK(pftrace_write_event(writer, &event));

  event.timestamp_ns = 1100;
  event.type = PFTRACE_TRACK_EVENT_TYPE_SLICE_END;
  event.name = STR("direct_end");
  event.flow_ids = NULL; event.flow_id_count = 0;
  event.terminating_flow_ids = ending_flows; event.terminating_flow_id_count = 2;
  event.categories = NULL; event.category_count = 0;
  event.arguments = NULL; event.argument_count = 0;
  CHECK(pftrace_write_event(writer, &event));
  event.timestamp_ns = 1200; event.type = PFTRACE_TRACK_EVENT_TYPE_INSTANT; event.name = STR("direct_instant");
  CHECK(pftrace_write_event(writer, &event));
  event.timestamp_ns = 1300; event.type = PFTRACE_TRACK_EVENT_TYPE_COUNTER; event.name = STR("direct_counter"); event.counter_value = INT64_MIN;
  CHECK(pftrace_write_event(writer, &event));
  event.timestamp_ns = 1400; event.type = PFTRACE_TRACK_EVENT_TYPE_UNSPECIFIED; event.name = STR("direct_unspecified");
  CHECK(pftrace_write_event(writer, &event));
  event.timestamp_ns = 1500; event.type = PFTRACE_TRACK_EVENT_TYPE_INSTANT; event.name = STR("direct_equivalent");
  event.trusted_packet_sequence_id = 8;
  CHECK(pftrace_write_event(writer, &event));

  pftrace_packet_t *packet = pftrace_packet_begin(writer);
  if (packet == NULL) goto fail;
  CHECK(pftrace_packet_set_timestamp(packet, 1500));
  CHECK(pftrace_packet_set_timestamp_clock_id(packet, PFTRACE_CLOCK_ID_CUSTOM_FIRST));
  CHECK(pftrace_packet_set_trusted_packet_sequence_id(packet, 8));
  pftrace_track_event_t *builder = pftrace_packet_begin_track_event(packet);
  if (builder == NULL) goto fail;
  CHECK(pftrace_track_event_set_type(builder, PFTRACE_TRACK_EVENT_TYPE_INSTANT));
  CHECK(pftrace_track_event_set_track_uuid(builder, 101));
  CHECK(pftrace_track_event_set_name(builder, "builder_equivalent"));
  CHECK(pftrace_track_event_add_arg_string(builder, "builder_arg", "same-schema"));
  CHECK(pftrace_track_event_end(builder));
  CHECK(pftrace_packet_commit(packet));
  CHECK(pftrace_finalize(writer));
  return pftrace_destroy(writer) == PFTRACE_OK ? 0 : 1;

fail:
  if (writer != NULL) (void)pftrace_destroy(writer);
  return 1;
}

static int write_rejected_prefix(const char *path) {
  pftrace_writer_options_t options;
  pftrace_writer_t *writer = NULL;
  pftrace_event_t event = { .type = PFTRACE_TRACK_EVENT_TYPE_INSTANT, .name = STR("good") };
  CHECK(pftrace_writer_options_init(&options));
  options.maximum_string_bytes = 4;
  options.flush_each_packet = true;
  CHECK(pftrace_init_path_with_options(path, &options, &writer));
  CHECK(pftrace_write_event(writer, &event));
  event.name = STR("too_long");
  if (pftrace_write_event(writer, &event) != PFTRACE_CAPACITY_EXCEEDED) goto fail;
  event.name = STR("after_reject");
  if (pftrace_write_event(writer, &event) != PFTRACE_CAPACITY_EXCEEDED) goto fail;
  event.name = STR("okay");
  CHECK(pftrace_write_event(writer, &event));
  CHECK(pftrace_finalize(writer));
  return pftrace_destroy(writer) == PFTRACE_OK ? 0 : 1;

fail:
  if (writer != NULL) (void)pftrace_destroy(writer);
  return 1;
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  return write_valid(argv[1]) || write_rejected_prefix(argv[2]);
}
