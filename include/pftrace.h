#ifndef LIBPERFETTO_H
#define LIBPERFETTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pftrace_writer_t pftrace_writer_t;
typedef struct pftrace_packet_t pftrace_packet_t;
typedef struct pftrace_track_event_t pftrace_track_event_t;

typedef enum {
  PFTRACE_TRACK_EVENT_TYPE_UNSPECIFIED = 0,
  PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN = 1,
  PFTRACE_TRACK_EVENT_TYPE_SLICE_END = 2,
  PFTRACE_TRACK_EVENT_TYPE_INSTANT = 3,
  PFTRACE_TRACK_EVENT_TYPE_COUNTER = 4,
} pftrace_track_event_type_t;

// --- Lifecycle ---
//
// Concurrency and ownership contract:
// - A writer has exclusive single-thread ownership. Calls using the same writer
//   must not overlap on more than one thread.
// - Packet and track-event handles belong to the writer that created them. Do not
//   pass a handle to another writer or use it after its matching end call.
// - Independent writers may be used concurrently.
// - End every active track event and packet before pftrace_destroy. Construction
//   must have stopped before lifecycle teardown begins.
//
// libpftrace does not own application scheduling: it creates no worker thread,
// queue, or implicit synchronization. Writes performed by this API are synchronous
// and can block; callers requiring realtime isolation should use their own drain
// thread. Invalid handles or violations of this contract are unsupported; no
// use-after-free detection is promised.
pftrace_writer_t *pftrace_init(const char *file_path);
void pftrace_destroy(pftrace_writer_t *w);

// --- Packet Lifecycle ---
// A packet returned by pftrace_packet_begin belongs to w. Pass the same w to
// pftrace_packet_end, and end every track event begun from packet first.
pftrace_packet_t *pftrace_packet_begin(pftrace_writer_t *w);
void pftrace_packet_end(pftrace_writer_t *w, pftrace_packet_t *packet);

// --- Core Features ---
void pftrace_packet_set_timestamp(pftrace_packet_t *p, uint64_t timestamp_ns);
void pftrace_packet_set_trusted_packet_sequence_id(pftrace_packet_t *p,
                                                   uint32_t seq_id);

// --- Domain Objects ---
void pftrace_write_process_track_descriptor(pftrace_writer_t *w, uint64_t uuid,
                                            int32_t pid, const char *name);
void pftrace_write_thread_track_descriptor(pftrace_writer_t *w, uint64_t uuid,
                                           uint64_t parent_uuid, int32_t pid,
                                           int32_t tid, const char *name);
void pftrace_write_clock_snapshot(pftrace_writer_t *w, uint64_t boottime_ns);

// --- Track Events ---
// A track event belongs to the writer that owns p. It must end before p ends and
// must not be used after pftrace_track_event_end returns.
pftrace_track_event_t *pftrace_packet_begin_track_event(pftrace_packet_t *p);
void pftrace_track_event_end(pftrace_track_event_t *te);

void pftrace_track_event_set_type(pftrace_track_event_t *te,
                                  pftrace_track_event_type_t type);
void pftrace_track_event_set_name(pftrace_track_event_t *te, const char *name);
void pftrace_track_event_set_track_uuid(pftrace_track_event_t *te,
                                        uint64_t uuid);
void pftrace_track_event_add_category(pftrace_track_event_t *te,
                                      const char *category);
void pftrace_track_event_set_counter_value(pftrace_track_event_t *te,
                                           int64_t value);
void pftrace_track_event_add_flow_id(pftrace_track_event_t *te,
                                     uint64_t flow_id);
void pftrace_track_event_add_terminating_flow_id(pftrace_track_event_t *te,
                                                 uint64_t flow_id);

// --- Structured Features ---
void pftrace_track_event_set_log_message(pftrace_track_event_t *te,
                                         const char *body);
void pftrace_track_event_set_task_execution(pftrace_track_event_t *te,
                                            const char *file, const char *func,
                                            uint32_t line);

// --- Arguments ---
void pftrace_track_event_add_arg_string(pftrace_track_event_t *te,
                                        const char *key, const char *value);
void pftrace_track_event_add_arg_int(pftrace_track_event_t *te, const char *key,
                                     int64_t value);
void pftrace_track_event_add_arg_uint(pftrace_track_event_t *te,
                                      const char *key, uint64_t value);
void pftrace_track_event_add_arg_double(pftrace_track_event_t *te,
                                        const char *key, double value);
void pftrace_track_event_add_arg_bool(pftrace_track_event_t *te,
                                      const char *key, bool value);
void pftrace_track_event_add_arg_ptr(pftrace_track_event_t *te, const char *key,
                                     uint64_t value);

#ifdef __cplusplus
}
#endif

#endif // LIBPERFETTO_H
