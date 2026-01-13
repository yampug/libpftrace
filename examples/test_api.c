#include "pftrace.h"
#include <stdio.h>
#include <string.h>

// Simple test to generate a valid trace packet
// We will manually construct a packet with a timestamp and some interned data.
// Field IDs:
// TracePacket:
//  timestamp = 8
//  trusted_packet_sequence_id = 10
//  interned_data = 12
// InternedData:
//  event_categories = 1 (EventCategory)
// EventCategory:
//  iid = 1
//  name = 2

int main() {
  printf("Creating trace...\n");
  PerfettoWriter *w = pftrace_create("test.pftrace", 12);
  if (!w) {
    printf("Failed to create writer\n");
    return 1;
  }

  // Packet 1: Metadata / Interned Data
  size_t packet1 = pftrace_begin_packet(w);

  pftrace_write_u64(w, 8, 1000); // timestamp = 1000 ns
  pftrace_write_u64(w, 10, 42);  // trusted_packet_sequence_id = 42

  // interned_data
  size_t interned = pftrace_begin_nested(w, 12);

  // event_categories
  size_t cat = pftrace_begin_nested(w, 1);
  pftrace_write_u64(w, 1, 1); // iid = 1
  pftrace_write_string(w, 2, "benchmark", 9);
  pftrace_end_nested(w, cat);

  pftrace_end_nested(w, interned);
  pftrace_end_packet(w, packet1);

  // Packet 2: Actual Event
  size_t packet2 = pftrace_begin_packet(w);
  pftrace_write_u64(w, 8, 2000); // timestamp = 2000 ns
  pftrace_write_u64(w, 10, 42);  // same sequence

  // TrackEvent (ID 11)
  size_t track_event = pftrace_begin_nested(w, 11);

  // type = 1 (SLICE_BEGIN)
  pftrace_write_u64(w, 9, 1);

  // categories (interned ID) = 1
  // Field 22 is categories (repeated uint64 for interned id)
  pftrace_write_u64(w, 22, 1);

  pftrace_end_nested(w, track_event);
  pftrace_end_packet(w, packet2);

  pftrace_flush(w);
  pftrace_destroy(w);

  printf("Trace written to test.pftrace\n");
  return 0;
}
