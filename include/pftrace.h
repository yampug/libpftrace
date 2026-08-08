#ifndef PFTRACE_H
#define PFTRACE_H

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
  PFTRACE_OK = 0, PFTRACE_INVALID_ARGUMENT = 1, PFTRACE_INVALID_STATE = 2,
  PFTRACE_CAPACITY_EXCEEDED = 3, PFTRACE_MESSAGE_TOO_LARGE = 4,
  PFTRACE_IO_ERROR = 5, PFTRACE_DISABLED = 6,
} pftrace_status_t;

typedef struct { const char *data; size_t size; } pftrace_string_t;

typedef enum {
  PFTRACE_TRACK_EVENT_TYPE_UNSPECIFIED = 0, PFTRACE_TRACK_EVENT_TYPE_SLICE_BEGIN = 1,
  PFTRACE_TRACK_EVENT_TYPE_SLICE_END = 2, PFTRACE_TRACK_EVENT_TYPE_INSTANT = 3,
  PFTRACE_TRACK_EVENT_TYPE_COUNTER = 4,
} pftrace_track_event_type_t;

/* All mutations return PFTRACE_OK only after their promised mutation commits.
 * `data == NULL` is valid only with size zero. Empty byte strings are valid;
 * length-bearing inputs may contain embedded NUL bytes. Legacy `const char *`
 * wrappers scan at most 1 MiB plus its terminator and reject unterminated input.
 * Invalid enums are PFTRACE_INVALID_ARGUMENT. No array-taking APIs exist yet. */
const char *pftrace_status_string(pftrace_status_t status);
pftrace_status_t pftrace_writer_status(const pftrace_writer_t *writer);

/* One thread exclusively owns a writer. Each writer permits one active packet
 * and one active track event. Handles belong to their creating writer; event
 * must end before packet. Ended handles immediately become invalid. Retaining
 * an ended handle through a later reuse of writer's slot is outside C contract.
 * destroy rejects active construction and leaves writer usable. */
pftrace_writer_t *pftrace_init_string(pftrace_string_t file_path);
pftrace_writer_t *pftrace_init(const char *file_path);
pftrace_status_t pftrace_destroy(pftrace_writer_t *writer);
pftrace_status_t pftrace_flush(pftrace_writer_t *writer);

pftrace_packet_t *pftrace_packet_begin(pftrace_writer_t *writer);
pftrace_status_t pftrace_packet_end(pftrace_writer_t *writer, pftrace_packet_t *packet);
pftrace_status_t pftrace_packet_commit(pftrace_packet_t *packet);
pftrace_status_t pftrace_packet_set_timestamp(pftrace_packet_t *packet, uint64_t timestamp_ns);
pftrace_status_t pftrace_packet_set_trusted_packet_sequence_id(pftrace_packet_t *packet, uint32_t seq_id);

pftrace_status_t pftrace_write_process_track_descriptor_string(pftrace_writer_t *, uint64_t, int32_t, pftrace_string_t);
pftrace_status_t pftrace_write_process_track_descriptor(pftrace_writer_t *, uint64_t, int32_t, const char *);
pftrace_status_t pftrace_write_thread_track_descriptor_string(pftrace_writer_t *, uint64_t, uint64_t, int32_t, int32_t, pftrace_string_t);
pftrace_status_t pftrace_write_thread_track_descriptor(pftrace_writer_t *, uint64_t, uint64_t, int32_t, int32_t, const char *);
pftrace_status_t pftrace_write_clock_snapshot(pftrace_writer_t *, uint64_t);

pftrace_track_event_t *pftrace_packet_begin_track_event(pftrace_packet_t *packet);
pftrace_status_t pftrace_track_event_end(pftrace_track_event_t *event);
pftrace_status_t pftrace_track_event_set_type(pftrace_track_event_t *, uint32_t);
pftrace_status_t pftrace_track_event_set_track_uuid(pftrace_track_event_t *, uint64_t);
pftrace_status_t pftrace_track_event_set_counter_value(pftrace_track_event_t *, int64_t);
pftrace_status_t pftrace_track_event_add_flow_id(pftrace_track_event_t *, uint64_t);
pftrace_status_t pftrace_track_event_add_terminating_flow_id(pftrace_track_event_t *, uint64_t);

pftrace_status_t pftrace_track_event_set_name_string(pftrace_track_event_t *, pftrace_string_t);
pftrace_status_t pftrace_track_event_set_name(pftrace_track_event_t *, const char *);
pftrace_status_t pftrace_track_event_add_category_string(pftrace_track_event_t *, pftrace_string_t);
pftrace_status_t pftrace_track_event_add_category(pftrace_track_event_t *, const char *);
pftrace_status_t pftrace_track_event_set_log_message_string(pftrace_track_event_t *, pftrace_string_t);
pftrace_status_t pftrace_track_event_set_log_message(pftrace_track_event_t *, const char *);
pftrace_status_t pftrace_track_event_set_task_execution_string(pftrace_track_event_t *, pftrace_string_t, pftrace_string_t, uint32_t);
pftrace_status_t pftrace_track_event_set_task_execution(pftrace_track_event_t *, const char *, const char *, uint32_t);

pftrace_status_t pftrace_track_event_add_arg_string_string(pftrace_track_event_t *, pftrace_string_t, pftrace_string_t);
pftrace_status_t pftrace_track_event_add_arg_string(pftrace_track_event_t *, const char *, const char *);
pftrace_status_t pftrace_track_event_add_arg_int_string(pftrace_track_event_t *, pftrace_string_t, int64_t);
pftrace_status_t pftrace_track_event_add_arg_int(pftrace_track_event_t *, const char *, int64_t);
pftrace_status_t pftrace_track_event_add_arg_uint_string(pftrace_track_event_t *, pftrace_string_t, uint64_t);
pftrace_status_t pftrace_track_event_add_arg_uint(pftrace_track_event_t *, const char *, uint64_t);
pftrace_status_t pftrace_track_event_add_arg_double_string(pftrace_track_event_t *, pftrace_string_t, double);
pftrace_status_t pftrace_track_event_add_arg_double(pftrace_track_event_t *, const char *, double);
pftrace_status_t pftrace_track_event_add_arg_bool_string(pftrace_track_event_t *, pftrace_string_t, bool);
pftrace_status_t pftrace_track_event_add_arg_bool(pftrace_track_event_t *, const char *, bool);
pftrace_status_t pftrace_track_event_add_arg_ptr_string(pftrace_track_event_t *, pftrace_string_t, uint64_t);
pftrace_status_t pftrace_track_event_add_arg_ptr(pftrace_track_event_t *, const char *, uint64_t);

#ifdef __cplusplus
}
#endif
#endif
