#include "pftrace.h"
#include <stdio.h>
#include <unistd.h>

// Global timestamp simulator
static uint64_t g_timestamp = 1000000000; // Start at 1s
static pftrace_writer_t *g_writer = NULL;

void simulate_work(int depth, int max_depth) {
  if (depth > max_depth)
    return;

  g_timestamp += 100000; // +100us per call entry

  pftrace_packet_t *p = pftrace_packet_begin(g_writer);
  pftrace_packet_set_timestamp(p, g_timestamp);
  pftrace_packet_set_trusted_packet_sequence_id(p, 1);

  pftrace_track_event_t *te = pftrace_packet_begin_track_event(p);
  pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN);
  pftrace_track_event_set_track_uuid(te, 101); // Main Thread

  char name[32];
  snprintf(name, sizeof(name), "Depth_%d", depth);
  pftrace_track_event_set_name(te, name);

  // Add some random args to make it bigger
  pftrace_track_event_add_arg_int(te, "depth", depth);
  pftrace_track_event_add_arg_double(te, "load_factor",
                                     (double)depth / max_depth);

  pftrace_track_event_end(te);
  pftrace_packet_end(g_writer, p);

  // Recurse
  simulate_work(depth + 1, max_depth);

  g_timestamp += 200000; // +200us work inside

  // End Slice
  p = pftrace_packet_begin(g_writer);
  pftrace_packet_set_timestamp(p, g_timestamp);
  pftrace_packet_set_trusted_packet_sequence_id(p, 1);

  te = pftrace_packet_begin_track_event(p);
  pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_END);
  pftrace_track_event_set_track_uuid(te, 101); // End on same track

  pftrace_track_event_end(te);
  pftrace_packet_end(g_writer, p);
}

int main() {
  printf("Generating huge trace 'big_trace.pftrace'...\n");
  g_writer = pftrace_init("big_trace.pftrace");
  if (!g_writer)
    return 1;

  // Metadata
  pftrace_write_clock_snapshot(g_writer, g_timestamp);
  pftrace_write_process_track_descriptor(g_writer, 100, 1234,
                                         "StressTestProcess");
  pftrace_write_thread_track_descriptor(g_writer, 101, 100, 1234, 5678,
                                        "WorkerThread");

  // Loop to create volume
  const int NUM_ITERATIONS = 10000;
  const int MAX_DEPTH = 50;

  for (int i = 0; i < NUM_ITERATIONS; i++) {
    if (i % 1000 == 0)
      printf("Iteration %d/%d...\n", i, NUM_ITERATIONS);

    // Wrap each iteration in a "loop" slice
    pftrace_packet_t *p = pftrace_packet_begin(g_writer);
    pftrace_packet_set_timestamp(p, g_timestamp);
    pftrace_packet_set_trusted_packet_sequence_id(p, 1);

    pftrace_track_event_t *te = pftrace_packet_begin_track_event(p);
    pftrace_track_event_set_type(te, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN);
    pftrace_track_event_set_track_uuid(te, 101);
    char buf[32];
    snprintf(buf, 32, "Loop_%d", i);
    pftrace_track_event_set_name(te, buf);
    pftrace_track_event_set_log_message(te, "Starting loop iteration");
    pftrace_track_event_end(te);
    pftrace_packet_end(g_writer, p);

    // Recursive stack
    simulate_work(1, MAX_DEPTH);

    g_timestamp += 50000;

    // End Loop slice
    p = pftrace_packet_begin(g_writer);
    pftrace_packet_set_timestamp(p, g_timestamp);
    pftrace_track_event_t *te_end = pftrace_packet_begin_track_event(p);
    pftrace_track_event_set_type(te_end, PFTRACE_TRACK_EVENT_TYPE_SLICE_END);
    pftrace_track_event_set_track_uuid(te_end, 101);
    pftrace_track_event_end(te_end);
    pftrace_packet_end(g_writer, p);
  }

  pftrace_destroy(g_writer);
  printf("Done. total time simulated: %llu ns\n", g_timestamp - 1000000000);
  return 0;
}
