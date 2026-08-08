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
 * nested messages; unlimited trace bytes; and flush_each_packet false.
 * Complete packets batch until output_batch_capacity; a packet that would not
 * fit first flushes existing batch, then appends whole packet. A full batch
 * flushes automatically. flush_each_packet instead flushes each commit. Call
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

/* Direct-event argument tag and payload. `key` and string values follow the
 * pftrace_string_t null/size rule. Pointer values are represented as integers;
 * libpftrace never dereferences them. */
typedef enum {
  PFTRACE_ARG_TYPE_STRING = 0, PFTRACE_ARG_TYPE_INT64 = 1,
  PFTRACE_ARG_TYPE_UINT64 = 2, PFTRACE_ARG_TYPE_DOUBLE = 3,
  PFTRACE_ARG_TYPE_BOOL = 4, PFTRACE_ARG_TYPE_POINTER = 5,
} pftrace_arg_type_t;

typedef union {
  pftrace_string_t string_value;
  int64_t int64_value;
  uint64_t uint64_value;
  double double_value;
  bool bool_value;
  uint64_t pointer_value;
} pftrace_arg_value_t;

typedef struct {
  pftrace_string_t key;
  pftrace_arg_type_t type;
  pftrace_arg_value_t value;
} pftrace_arg_t;

/* Direct event input for pftrace_write_event. `timestamp_clock_id` uses the
 * Perfetto clock-id namespace; zero is the default/unspecified clock. A zero
 * sequence ID is likewise omitted by the encoder. `counter_value` is used by
 * counter events and ignored by other event types.
 *
 * Each pointer/count pair is valid when count is zero, or when pointer is
 * non-NULL. Every referenced string uses pftrace_string_t's null/size rule.
 * Writer borrows event, its arrays, and all strings only for duration of
 * pftrace_write_event; it never retains caller pointers. */
typedef struct {
  uint64_t timestamp_ns;
  uint32_t timestamp_clock_id;
  uint32_t trusted_packet_sequence_id;
  uint64_t track_uuid;
  pftrace_track_event_type_t type;
  pftrace_string_t name;
  int64_t counter_value;
  const uint64_t *flow_ids;
  size_t flow_id_count;
  const uint64_t *terminating_flow_ids;
  size_t terminating_flow_id_count;
  const pftrace_string_t *categories;
  size_t category_count;
  const pftrace_arg_t *arguments;
  size_t argument_count;
} pftrace_event_t;

/* Common input for direct-event convenience calls. Timestamp is nanoseconds.
 * Pointer/count pairs use the same rules as pftrace_event_t. Categories and
 * unusual event combinations require direct pftrace_event_t construction. */
typedef struct {
  uint64_t timestamp_ns;
  uint32_t timestamp_clock_id;
  uint32_t trusted_packet_sequence_id;
  uint64_t track_uuid;
  const uint64_t *flow_ids;
  size_t flow_id_count;
  const uint64_t *terminating_flow_ids;
  size_t terminating_flow_id_count;
  const pftrace_arg_t *arguments;
  size_t argument_count;
} pftrace_event_common_t;

/* All mutations return PFTRACE_OK only after their promised mutation commits.
 * `data == NULL` is valid only with size zero. Empty byte strings are valid;
 * length-bearing inputs may contain embedded NUL bytes. Legacy `const char *`
 * wrappers scan at most 1 MiB plus its terminator and reject unterminated input.
 * Invalid enums are PFTRACE_INVALID_ARGUMENT. */
const char *pftrace_status_string(pftrace_status_t status);
pftrace_status_t pftrace_writer_status(const pftrace_writer_t *writer);

/* One thread exclusively owns a writer. Each writer permits one active packet
 * and one active track event. Handles belong to their creating writer; event
 * must end before packet. Ended handles immediately become invalid. Retaining
 * an ended handle through a later reuse of writer's slot is outside C contract.
 * finalize and destroy reject active construction and leave writer usable.
 * finalize flushes then seals writer; it is idempotent and later mutations
 * return PFTRACE_INVALID_STATE (unless sticky PFTRACE_IO_ERROR dominates).
 * destroy finalizes, releases writer, and returns final status; do not reuse
 * writer pointer after destroy. */
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
/* Flushes every complete packet currently buffered. Empty/repeated successful
 * flushes are no-ops. A successful flush leaves writer usable. */
pftrace_status_t pftrace_flush(pftrace_writer_t *writer);
pftrace_status_t pftrace_finalize(pftrace_writer_t *writer);

/* Encodes one complete TracePacket/TrackEvent transaction from `event`. It
 * borrows every input only for this call, performs no allocation after writer
 * initialization, and either commits a complete packet or leaves the output
 * batch unchanged. */
pftrace_status_t pftrace_write_event(pftrace_writer_t *writer,
                                     const pftrace_event_t *event);
/* Small direct-event convenience surface. Each call delegates to
 * pftrace_write_event; construct pftrace_event_t directly for categories or
 * combinations not represented here. */
pftrace_status_t pftrace_write_slice_begin(
    pftrace_writer_t *writer, const pftrace_event_common_t *common,
    pftrace_string_t name);
pftrace_status_t pftrace_write_slice_end(
    pftrace_writer_t *writer, const pftrace_event_common_t *common,
    pftrace_string_t name);
pftrace_status_t pftrace_write_instant(
    pftrace_writer_t *writer, const pftrace_event_common_t *common,
    pftrace_string_t name);
pftrace_status_t pftrace_write_counter(
    pftrace_writer_t *writer, const pftrace_event_common_t *common,
    pftrace_string_t name, int64_t value);

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
