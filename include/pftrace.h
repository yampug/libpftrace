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

/* Return PFTRACE_OK only after consuming all `size` bytes. `context` and the
 * callback remain caller-owned; a non-OK return becomes sticky IO_ERROR. */
typedef pftrace_status_t (*pftrace_write_fn)(void *context,
                                              const uint8_t *bytes,
                                              size_t size);

typedef struct { const char *data; size_t size; } pftrace_string_t;

/* Version 1 options. Defaults: 1 MiB packet scratch/output batch/maximum
 * packet/string bytes; 1024 arguments, categories, and each flow kind; 64
 * nested messages; unlimited trace bytes; and flush_each_packet false. Call
 * pftrace_writer_options_init before changing fields.
 * `struct_size` permits a newer library to accept an older caller's prefix;
 * fields beyond it retain their documented defaults. Memory reserved during
 * initialization is fixed writer bookkeeping plus packet_scratch_capacity +
 * output_batch_capacity. */
typedef struct {
  uint32_t struct_size;
  uint32_t version;
  size_t packet_scratch_capacity;
  size_t output_batch_capacity;
  size_t maximum_packet_bytes;
  size_t maximum_trace_bytes; /* 0 means no trace-byte limit. */
  size_t maximum_string_bytes;
  size_t maximum_arguments;
  size_t maximum_categories;
  size_t maximum_flow_ids;
  size_t maximum_terminating_flow_ids;
  uint32_t maximum_nesting_depth;
  bool flush_each_packet;
} pftrace_writer_options_t;

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
/* Initializes `options` to stable version-1 defaults. */
pftrace_status_t pftrace_writer_options_init(pftrace_writer_options_t *options);
/* Validates options before creating or truncating file_path. On success stores
 * a writer in out_writer; on failure out_writer is set to NULL. */
pftrace_status_t pftrace_init_string_with_options(
    pftrace_string_t file_path, const pftrace_writer_options_t *options,
    pftrace_writer_t **out_writer);
pftrace_status_t pftrace_init_with_options(
    const char *file_path, const pftrace_writer_options_t *options,
    pftrace_writer_t **out_writer);
/* Explicit path constructors. Path writers own and close their file. */
pftrace_status_t pftrace_init_path_string_with_options(
    pftrace_string_t file_path, const pftrace_writer_options_t *options,
    pftrace_writer_t **out_writer);
pftrace_status_t pftrace_init_path_with_options(
    const char *file_path, const pftrace_writer_options_t *options,
    pftrace_writer_t **out_writer);
/* fd is borrowed: libpftrace neither reopens nor closes it. */
pftrace_status_t pftrace_init_fd_with_options(
    int fd, const pftrace_writer_options_t *options, pftrace_writer_t **out_writer);
/* Callback receives each complete committed output span in order. */
pftrace_status_t pftrace_init_callback_with_options(
    pftrace_write_fn write_fn, void *context, const pftrace_writer_options_t *options,
    pftrace_writer_t **out_writer);
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
