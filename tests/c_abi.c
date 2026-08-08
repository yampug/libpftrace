#include "pftrace.h"

#include <stdio.h>
#include <string.h>

int main(void) {
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
  if (pftrace_init_with_options(custom_path, &options, &custom_writer) != PFTRACE_OK ||
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

  return remove(path) == 0 ? 0 : 1;
}
