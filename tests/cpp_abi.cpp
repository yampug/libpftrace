#include "pftrace.h"

#include <cstdio>

int main() {
  const uint64_t flow_ids[] = {UINT64_C(1)};
  const uint64_t terminating_flow_ids[] = {UINT64_C(2)};
  const pftrace_string_t categories[] = {{"category", 8}};
  pftrace_arg_t arguments[] = {
      {{"string", 6}, PFTRACE_ARG_TYPE_STRING, {{nullptr, 0}}},
      {{"int64", 5}, PFTRACE_ARG_TYPE_INT64, {{nullptr, 0}}},
      {{"uint64", 6}, PFTRACE_ARG_TYPE_UINT64, {{nullptr, 0}}},
      {{"double", 6}, PFTRACE_ARG_TYPE_DOUBLE, {{nullptr, 0}}},
      {{"bool", 4}, PFTRACE_ARG_TYPE_BOOL, {{nullptr, 0}}},
      {{"pointer", 7}, PFTRACE_ARG_TYPE_POINTER, {{nullptr, 0}}},
  };
  arguments[0].value.string_value = {"value", 5};
  arguments[1].value.int64_value = INT64_C(-1);
  arguments[2].value.uint64_value = UINT64_C(1);
  arguments[3].value.double_value = 1.5;
  arguments[4].value.bool_value = true;
  arguments[5].value.pointer_value = UINT64_C(0x1234);
  const pftrace_event_t direct_event = {
      UINT64_C(1), 0, 1, 2, PFTRACE_TRACK_EVENT_TYPE_INSTANT, {"event", 5}, 0,
      flow_ids, 1, terminating_flow_ids, 1, categories, 1, arguments,
      sizeof(arguments) / sizeof(arguments[0])};
  if (direct_event.arguments[5].type != PFTRACE_ARG_TYPE_POINTER) {
    return 1;
  }
  const char *const path = "pftrace-cpp-abi-test.pftrace";
  pftrace_writer_t *const writer = pftrace_init(path);
  if (writer == nullptr) {
    return 1;
  }

  pftrace_packet_t *const packet = pftrace_packet_begin(writer);
  if (packet == nullptr) {
    pftrace_destroy(writer);
    (void)std::remove(path);
    return 1;
  }

  pftrace_packet_set_timestamp(packet, UINT64_C(1));
  pftrace_packet_set_timestamp_clock_id(packet, PFTRACE_CLOCK_ID_CUSTOM_FIRST);
  pftrace_packet_set_trusted_packet_sequence_id(packet, UINT32_C(1));
  pftrace_packet_end(writer, packet);
  pftrace_destroy(writer);

  return std::remove(path) == 0 ? 0 : 1;
}
