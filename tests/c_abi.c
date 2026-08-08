#include "pftrace.h"

#include <stdio.h>

int main(void) {
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

  pftrace_packet_set_timestamp(packet, UINT64_C(1));
  pftrace_packet_set_trusted_packet_sequence_id(packet, UINT32_C(1));
  pftrace_packet_end(writer, packet);
  pftrace_destroy(writer);

  return remove(path) == 0 ? 0 : 1;
}
