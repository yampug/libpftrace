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
pftrace_writer_t *pftrace_init(const char *file_path);
void pftrace_destroy(pftrace_writer_t *w);

// --- Packet Lifecycle ---
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
