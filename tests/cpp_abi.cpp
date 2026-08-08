#include "pftrace.h"

#include <cstdio>

int main() {
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
  pftrace_packet_set_trusted_packet_sequence_id(packet, UINT32_C(1));
  pftrace_packet_end(writer, packet);
  pftrace_destroy(writer);

  return std::remove(path) == 0 ? 0 : 1;
}
