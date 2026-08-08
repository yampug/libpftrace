#include "pftrace.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct callback_state {
  size_t calls;
  size_t bytes;
  pftrace_status_t result;
};

static pftrace_status_t capture_write(void *context, const uint8_t *bytes,
                                      size_t size) {
  struct callback_state *const state = context;
  if (bytes == NULL || size == 0) {
    return PFTRACE_INVALID_ARGUMENT;
  }
  ++state->calls;
  state->bytes += size;
  return state->result;
}

int main(void) {
  const uint64_t flow_ids[] = {UINT64_C(1)};
  const uint64_t terminating_flow_ids[] = {UINT64_C(2)};
  const pftrace_string_t categories[] = {{"category", 8}};
  pftrace_arg_t arguments[] = {
      {{"string", 6}, PFTRACE_ARG_TYPE_STRING, {{NULL, 0}}},
      {{"int64", 5}, PFTRACE_ARG_TYPE_INT64, {{NULL, 0}}},
      {{"uint64", 6}, PFTRACE_ARG_TYPE_UINT64, {{NULL, 0}}},
      {{"double", 6}, PFTRACE_ARG_TYPE_DOUBLE, {{NULL, 0}}},
      {{"bool", 4}, PFTRACE_ARG_TYPE_BOOL, {{NULL, 0}}},
      {{"pointer", 7}, PFTRACE_ARG_TYPE_POINTER, {{NULL, 0}}},
  };
  arguments[0].value.string_value = (pftrace_string_t){"value", 5};
  arguments[1].value.int64_value = INT64_C(-1);
  arguments[2].value.uint64_value = UINT64_C(1);
  arguments[3].value.double_value = 1.5;
  arguments[4].value.bool_value = true;
  arguments[5].value.pointer_value = UINT64_C(0x1234);
  const pftrace_event_t direct_event = {
      UINT64_C(1), 0, 1, 2, PFTRACE_TRACK_EVENT_TYPE_INSTANT, {"event", 5}, 0,
      flow_ids, 1, terminating_flow_ids, 1, categories, 1, arguments,
      sizeof(arguments) / sizeof(arguments[0])};
  const pftrace_event_common_t direct_common = {
      UINT64_C(1), 0, 1, 2, flow_ids, 1, terminating_flow_ids, 1, arguments,
      sizeof(arguments) / sizeof(arguments[0])};
  if (direct_event.arguments[5].type != PFTRACE_ARG_TYPE_POINTER) {
    return 1;
  }
  _Static_assert(PFTRACE_OK == 0 && PFTRACE_INVALID_ARGUMENT == 1 &&
                     PFTRACE_INVALID_STATE == 2 &&
                     PFTRACE_CAPACITY_EXCEEDED == 3 &&
                     PFTRACE_MESSAGE_TOO_LARGE == 4 &&
                     PFTRACE_IO_ERROR == 5 && PFTRACE_DISABLED == 6,
                 "pftrace status values are ABI");
  if (pftrace_status_string(PFTRACE_OK) == NULL ||
      pftrace_status_string((pftrace_status_t)99) == NULL ||
      pftrace_writer_status(NULL) != PFTRACE_INVALID_ARGUMENT) {
    return 1;
  }
  pftrace_writer_options_t options;
  if (pftrace_writer_options_init(&options) != PFTRACE_OK ||
      options.struct_size != sizeof(options)) {
    return 1;
  }
  const char *const invalid_path = "pftrace-invalid-options.pftrace";
  FILE *const sentinel = fopen(invalid_path, "wb");
  if (sentinel == NULL || fputs("keep", sentinel) < 0 || fclose(sentinel) != 0) {
    return 1;
  }
  options.maximum_packet_bytes = options.output_batch_capacity + 1;
  pftrace_writer_t *invalid_writer = (pftrace_writer_t *)(uintptr_t)1;
  if (pftrace_init_with_options(invalid_path, &options, &invalid_writer) !=
          PFTRACE_INVALID_ARGUMENT ||
      invalid_writer != NULL) {
    (void)remove(invalid_path);
    return 1;
  }
  char retained[5] = {0};
  FILE *const retained_file = fopen(invalid_path, "rb");
  if (retained_file == NULL || fread(retained, 1, 4, retained_file) != 4 ||
      fclose(retained_file) != 0 || strcmp(retained, "keep") != 0 ||
      remove(invalid_path) != 0) {
    return 1;
  }
  if (pftrace_writer_options_init(&options) != PFTRACE_OK) {
    return 1;
  }
  options.packet_scratch_capacity = 128;
  options.output_batch_capacity = 128;
  options.maximum_packet_bytes = 128;
  pftrace_writer_t *custom_writer = NULL;
  const char *const custom_path = "pftrace-custom-options.pftrace";
  if (pftrace_init_path_with_options(custom_path, &options, &custom_writer) != PFTRACE_OK ||
      custom_writer == NULL || pftrace_destroy(custom_writer) != PFTRACE_OK ||
      remove(custom_path) != 0) {
    return 1;
  }
  const char *const path = "pftrace-c-abi-test.pftrace";
  pftrace_writer_t *const writer = pftrace_init(path);
  if (writer == NULL) {
    return 1;
  }

  pftrace_packet_t *const packet = pftrace_packet_begin(writer);
  if (packet == NULL) {
    pftrace_destroy(writer);
    (void)remove(path);
    return 1;
  }

  if (pftrace_packet_set_timestamp(packet, UINT64_C(1)) != PFTRACE_OK ||
      pftrace_packet_set_timestamp_clock_id(packet, PFTRACE_CLOCK_ID_CUSTOM_FIRST) != PFTRACE_OK ||
      pftrace_packet_set_trusted_packet_sequence_id(packet, UINT32_C(1)) != PFTRACE_OK ||
      pftrace_packet_end(writer, packet) != PFTRACE_OK ||
      pftrace_packet_set_timestamp(packet, UINT64_C(2)) != PFTRACE_INVALID_STATE ||
      pftrace_writer_status(writer) != PFTRACE_OK) {
    pftrace_destroy(writer);
    (void)remove(path);
    return 1;
  }

  pftrace_packet_t *const packet_with_event = pftrace_packet_begin(writer);
  pftrace_track_event_t *const event =
      packet_with_event == NULL ? NULL : pftrace_packet_begin_track_event(packet_with_event);
  if (packet_with_event == NULL || event == NULL || pftrace_packet_begin(writer) != NULL ||
      pftrace_destroy(writer) != PFTRACE_INVALID_STATE ||
      pftrace_packet_end(writer, packet_with_event) != PFTRACE_INVALID_STATE ||
      pftrace_track_event_end(event) != PFTRACE_OK ||
      pftrace_track_event_end(event) != PFTRACE_INVALID_STATE ||
      pftrace_packet_commit(packet_with_event) != PFTRACE_OK) {
    (void)pftrace_destroy(writer);
    (void)remove(path);
    return 1;
  }

  const char *const path2 = "pftrace-c-abi-test-2.pftrace";
  pftrace_writer_t *const writer2 = pftrace_init(path2);
  pftrace_packet_t *const packet2 = pftrace_packet_begin(writer);
  if (writer2 == NULL || packet2 == NULL ||
      pftrace_packet_end(writer2, packet2) != PFTRACE_INVALID_STATE ||
      pftrace_packet_commit(packet2) != PFTRACE_OK ||
      pftrace_destroy(writer2) != PFTRACE_OK ||
      remove(path2) != 0) {
    (void)pftrace_destroy(writer);
    (void)remove(path);
    return 1;
  }
  if (pftrace_destroy(writer) != PFTRACE_OK) {
    (void)remove(path);
    return 1;
  }

  struct callback_state memory = {0, 0, PFTRACE_OK};
  pftrace_writer_t *callback_writer = NULL;
  if (pftrace_init_callback_with_options(NULL, NULL, NULL, &callback_writer) !=
          PFTRACE_INVALID_ARGUMENT ||
      callback_writer != NULL ||
      pftrace_init_fd_with_options(-1, NULL, &callback_writer) !=
          PFTRACE_INVALID_ARGUMENT ||
      callback_writer != NULL) {
    return 1;
  }
  if (pftrace_init_callback_with_options(capture_write, &memory, NULL,
                                         &callback_writer) != PFTRACE_OK ||
      callback_writer == NULL ||
      pftrace_write_event(callback_writer, &direct_event) != PFTRACE_OK ||
      pftrace_write_slice_begin(callback_writer, &direct_common, (pftrace_string_t){"begin", 5}) != PFTRACE_OK ||
      pftrace_write_slice_end(callback_writer, &direct_common, (pftrace_string_t){"end", 3}) != PFTRACE_OK ||
      pftrace_write_instant(callback_writer, &direct_common, (pftrace_string_t){"instant", 7}) != PFTRACE_OK ||
      pftrace_write_counter(callback_writer, &direct_common, (pftrace_string_t){"counter", 7}, INT64_MIN) != PFTRACE_OK ||
      pftrace_write_clock_snapshot(callback_writer, PFTRACE_CLOCK_ID_UNSPECIFIED,
                                   UINT64_C(42)) != PFTRACE_OK ||
      pftrace_write_clock_snapshot(callback_writer, PFTRACE_CLOCK_ID_CUSTOM_FIRST,
                                   UINT64_C(43)) != PFTRACE_OK ||
      memory.calls != 0 || pftrace_flush(callback_writer) != PFTRACE_OK ||
      memory.calls != 1 || memory.bytes == 0 ||
      pftrace_flush(callback_writer) != PFTRACE_OK || memory.calls != 1 ||
      pftrace_finalize(callback_writer) != PFTRACE_OK ||
      pftrace_finalize(callback_writer) != PFTRACE_OK ||
      pftrace_write_linux_boottime_clock_snapshot(callback_writer, UINT64_C(44)) != PFTRACE_INVALID_STATE ||
      pftrace_destroy(callback_writer) != PFTRACE_OK) {
    return 1;
  }

  struct callback_state failing = {0, 0, PFTRACE_INVALID_ARGUMENT};
  callback_writer = NULL;
  if (pftrace_init_callback_with_options(capture_write, &failing, NULL,
                                         &callback_writer) != PFTRACE_OK ||
      pftrace_write_linux_boottime_clock_snapshot(callback_writer, UINT64_C(1)) != PFTRACE_OK ||
      pftrace_finalize(callback_writer) != PFTRACE_IO_ERROR ||
      failing.calls != 1 || pftrace_writer_status(callback_writer) != PFTRACE_IO_ERROR ||
      pftrace_write_linux_boottime_clock_snapshot(callback_writer, UINT64_C(2)) != PFTRACE_IO_ERROR ||
      failing.calls != 1 || pftrace_destroy(callback_writer) != PFTRACE_IO_ERROR) {
    return 1;
  }

  FILE *const borrowed = tmpfile();
  callback_writer = NULL;
  if (borrowed == NULL ||
      pftrace_init_fd_with_options(fileno(borrowed), NULL, &callback_writer) != PFTRACE_OK ||
      pftrace_write_linux_boottime_clock_snapshot(callback_writer, UINT64_C(3)) != PFTRACE_OK ||
      pftrace_finalize(callback_writer) != PFTRACE_OK ||
      pftrace_destroy(callback_writer) != PFTRACE_OK ||
      fputs("still-open", borrowed) < 0 || fclose(borrowed) != 0) {
    return 1;
  }

  if (pftrace_writer_options_init(&options) != PFTRACE_OK) {
    return 1;
  }
  options.packet_scratch_capacity = 8;
  options.output_batch_capacity = 8;
  options.maximum_packet_bytes = 8;
  memory = (struct callback_state){0, 0, PFTRACE_OK};
  callback_writer = NULL;
  pftrace_packet_t *batch_packet = NULL;
  if (pftrace_init_callback_with_options(capture_write, &memory, &options,
                                         &callback_writer) != PFTRACE_OK ||
      (batch_packet = pftrace_packet_begin(callback_writer)) == NULL ||
      pftrace_packet_commit(batch_packet) != PFTRACE_OK || memory.calls != 0 ||
      (batch_packet = pftrace_packet_begin(callback_writer)) == NULL ||
      pftrace_packet_commit(batch_packet) != PFTRACE_OK || memory.calls != 0 ||
      (batch_packet = pftrace_packet_begin(callback_writer)) == NULL ||
      pftrace_packet_commit(batch_packet) != PFTRACE_OK || memory.calls != 0 ||
      (batch_packet = pftrace_packet_begin(callback_writer)) == NULL ||
      pftrace_packet_commit(batch_packet) != PFTRACE_OK || memory.calls != 1 ||
      (batch_packet = pftrace_packet_begin(callback_writer)) == NULL ||
      pftrace_packet_commit(batch_packet) != PFTRACE_OK || memory.calls != 1 ||
      pftrace_flush(callback_writer) != PFTRACE_OK || memory.calls != 2 ||
      pftrace_destroy(callback_writer) != PFTRACE_OK) {
    return 1;
  }

  if (pftrace_writer_options_init(&options) != PFTRACE_OK) {
    return 1;
  }
  options.flush_each_packet = true;
  memory = (struct callback_state){0, 0, PFTRACE_OK};
  callback_writer = NULL;
  if (pftrace_init_callback_with_options(capture_write, &memory, &options,
                                         &callback_writer) != PFTRACE_OK ||
      pftrace_write_linux_boottime_clock_snapshot(callback_writer, UINT64_C(4)) != PFTRACE_OK ||
      pftrace_write_linux_boottime_clock_snapshot(callback_writer, UINT64_C(5)) != PFTRACE_OK ||
      memory.calls != 2 || pftrace_destroy(callback_writer) != PFTRACE_OK) {
    return 1;
  }

  return remove(path) == 0 ? 0 : 1;
}
