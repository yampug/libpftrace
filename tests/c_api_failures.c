#include "pftrace.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct sink_state {
  size_t calls;
  size_t bytes;
  size_t fail_on_call;
  uint8_t retained[8192];
  size_t retained_size;
};

static pftrace_status_t memory_sink(void *context, const uint8_t *bytes,
                                    size_t size) {
  struct sink_state *const state = context;
  ++state->calls;
  if (state->fail_on_call != 0 && state->calls == state->fail_on_call) {
    return PFTRACE_INVALID_ARGUMENT;
  }
  if (bytes == NULL || size == 0 || size > sizeof(state->retained) - state->retained_size) {
    return PFTRACE_INVALID_ARGUMENT;
  }
  memcpy(state->retained + state->retained_size, bytes, size);
  state->retained_size += size;
  state->bytes += size;
  return PFTRACE_OK;
}

static int check(pftrace_status_t actual, pftrace_status_t expected) {
  return actual == expected ? 0 : 1;
}

static pftrace_event_t valid_event(void) {
  static const char name[] = "event";
  return (pftrace_event_t){
      .timestamp_ns = 1,
      .timestamp_clock_id = PFTRACE_CLOCK_ID_CUSTOM_FIRST,
      .trusted_packet_sequence_id = 1,
      .track_uuid = 1,
      .type = PFTRACE_TRACK_EVENT_TYPE_INSTANT,
      .name = {name, sizeof(name) - 1},
  };
}

static int init_writer(struct sink_state *state, pftrace_writer_options_t *options,
                       pftrace_writer_t **writer) {
  *writer = NULL;
  return check(pftrace_init_callback_with_options(memory_sink, state, options, writer),
               PFTRACE_OK) || *writer == NULL;
}

static int recover_after_invalid_input(void) {
  struct sink_state state = {0};
  pftrace_writer_t *writer;
  pftrace_event_t event = valid_event();
  const size_t retained_before = state.retained_size;
  if (init_writer(&state, NULL, &writer) ||
      check(pftrace_write_event(NULL, &event), PFTRACE_INVALID_ARGUMENT) ||
      check(pftrace_write_event(writer, NULL), PFTRACE_INVALID_ARGUMENT)) {
    return 1;
  }

  event.name = (pftrace_string_t){NULL, 1};
  if (check(pftrace_write_event(writer, &event), PFTRACE_INVALID_ARGUMENT) ||
      state.retained_size != retained_before) {
    return 1;
  }
  event = valid_event();
  event.type = (pftrace_track_event_type_t)99;
  if (check(pftrace_write_event(writer, &event), PFTRACE_INVALID_ARGUMENT)) return 1;
  event = valid_event();
  event.flow_ids = NULL;
  event.flow_id_count = 1;
  if (check(pftrace_write_event(writer, &event), PFTRACE_INVALID_ARGUMENT)) return 1;
  event = valid_event();
  if (check(pftrace_write_event(writer, &event), PFTRACE_OK) ||
      check(pftrace_finalize(writer), PFTRACE_OK) || state.retained_size == 0 ||
      check(pftrace_destroy(writer), PFTRACE_OK)) {
    return 1;
  }
  return 0;
}

static int unterminated_string_is_rejected(void) {
  char *const text = malloc((1024 * 1024) + 1);
  struct sink_state state = {0};
  pftrace_writer_t *writer;
  int failed = text == NULL;
  if (!failed) memset(text, 'x', (1024 * 1024) + 1);
  if (!failed && init_writer(&state, NULL, &writer)) failed = 1;
  if (!failed && check(pftrace_write_process_track_descriptor(writer, 1, 1, text),
                       PFTRACE_INVALID_ARGUMENT)) failed = 1;
  if (!failed && check(pftrace_write_linux_boottime_clock_snapshot(writer, 1), PFTRACE_OK)) failed = 1;
  if (!failed && check(pftrace_destroy(writer), PFTRACE_OK)) failed = 1;
  free(text);
  return failed;
}

static int bound_matrix(void) {
  const uint64_t flows[] = {1, 2, 3};
  const pftrace_string_t categories[] = {{"a", 1}, {"b", 1}, {"c", 1}};
  const pftrace_arg_t args[] = {
      {{"a", 1}, PFTRACE_ARG_TYPE_INT64, {.int64_value = 1}},
      {{"b", 1}, PFTRACE_ARG_TYPE_INT64, {.int64_value = 2}},
      {{"c", 1}, PFTRACE_ARG_TYPE_INT64, {.int64_value = 3}},
  };
  pftrace_writer_options_t options;
  struct sink_state state = {0};
  pftrace_writer_t *writer;
  pftrace_event_t event = valid_event();
  if (check(pftrace_writer_options_init(&options), PFTRACE_OK)) return 1;
  options.maximum_flow_ids = 2;
  options.maximum_terminating_flow_ids = 2;
  options.maximum_categories = 2;
  options.maximum_arguments = 2;
  options.maximum_string_bytes = 2;
  if (init_writer(&state, &options, &writer)) return 1;

  event.name = (pftrace_string_t){"x", 1};
  if (check(pftrace_write_event(writer, &event), PFTRACE_OK)) return 1; /* below */
  event.name = (pftrace_string_t){"xx", 2};
  event.flow_ids = flows;
  event.flow_id_count = 2;
  event.terminating_flow_ids = flows;
  event.terminating_flow_id_count = 2;
  event.categories = categories;
  event.category_count = 2;
  event.arguments = args;
  event.argument_count = 2;
  if (check(pftrace_write_event(writer, &event), PFTRACE_OK)) return 1; /* at */
  event.name = (pftrace_string_t){"xxx", 3};
  if (check(pftrace_write_event(writer, &event), PFTRACE_CAPACITY_EXCEEDED)) return 1;
  event = valid_event();
  event.flow_ids = flows;
  event.flow_id_count = 3;
  if (check(pftrace_write_event(writer, &event), PFTRACE_CAPACITY_EXCEEDED)) return 1;
  event.flow_id_count = 0;
  event.terminating_flow_ids = flows;
  event.terminating_flow_id_count = 3;
  if (check(pftrace_write_event(writer, &event), PFTRACE_CAPACITY_EXCEEDED)) return 1;
  event.terminating_flow_id_count = 0;
  event.categories = categories;
  event.category_count = 3;
  if (check(pftrace_write_event(writer, &event), PFTRACE_CAPACITY_EXCEEDED)) return 1;
  event.category_count = 0;
  event.arguments = args;
  event.argument_count = 3;
  if (check(pftrace_write_event(writer, &event), PFTRACE_CAPACITY_EXCEEDED)) return 1;
  event = valid_event();
  event.name = (pftrace_string_t){"x", 1};
  if (check(pftrace_write_event(writer, &event), PFTRACE_OK) ||
      check(pftrace_finalize(writer), PFTRACE_OK) || check(pftrace_destroy(writer), PFTRACE_OK)) {
    return 1;
  }
  return 0;
}

static int lifecycle_matrix(void) {
  struct sink_state first = {0};
  struct sink_state second = {0};
  pftrace_writer_t *writer_a;
  pftrace_writer_t *writer_b;
  if (init_writer(&first, NULL, &writer_a) || init_writer(&second, NULL, &writer_b)) return 1;
  pftrace_packet_t *packet = pftrace_packet_begin(writer_a);
  if (packet == NULL || pftrace_packet_begin_track_event(NULL) != NULL ||
      check(pftrace_packet_end(writer_b, packet), PFTRACE_INVALID_STATE) ||
      check(pftrace_finalize(writer_a), PFTRACE_INVALID_STATE) ||
      check(pftrace_destroy(writer_a), PFTRACE_INVALID_STATE)) return 1;
  pftrace_track_event_t *event = pftrace_packet_begin_track_event(packet);
  if (event == NULL || check(pftrace_packet_commit(packet), PFTRACE_INVALID_STATE) ||
      check(pftrace_track_event_set_type(event, 99), PFTRACE_INVALID_ARGUMENT) ||
      check(pftrace_track_event_end(event), PFTRACE_INVALID_ARGUMENT) ||
      check(pftrace_packet_commit(packet), PFTRACE_INVALID_ARGUMENT)) return 1;

  packet = pftrace_packet_begin(writer_a);
  event = packet == NULL ? NULL : pftrace_packet_begin_track_event(packet);
  if (event == NULL ||
      check(pftrace_track_event_set_task_execution(event, "file", "function", 1), PFTRACE_OK) ||
      check(pftrace_track_event_set_task_execution(event, "file", "function", 2), PFTRACE_INVALID_STATE) ||
      check(pftrace_track_event_end(event), PFTRACE_INVALID_STATE) ||
      check(pftrace_packet_commit(packet), PFTRACE_INVALID_STATE)) return 1;

  if (check(pftrace_write_linux_boottime_clock_snapshot(writer_a, 7), PFTRACE_OK) ||
      check(pftrace_finalize(writer_a), PFTRACE_OK) ||
      check(pftrace_write_linux_boottime_clock_snapshot(writer_a, 8), PFTRACE_INVALID_STATE) ||
      check(pftrace_flush(writer_a), PFTRACE_INVALID_STATE) ||
      check(pftrace_destroy(writer_a), PFTRACE_OK) || check(pftrace_destroy(writer_b), PFTRACE_OK)) return 1;
  return 0;
}

static int trace_saturation_recovers(void) {
  pftrace_writer_options_t options;
  struct sink_state state = {0};
  pftrace_writer_t *writer;
  if (check(pftrace_writer_options_init(&options), PFTRACE_OK)) return 1;
  options.maximum_trace_bytes = 3;
  if (init_writer(&state, &options, &writer)) return 1;
  if (check(pftrace_write_linux_boottime_clock_snapshot(writer, 1), PFTRACE_CAPACITY_EXCEEDED) ||
      state.calls != 0 || state.retained_size != 0 ||
      check(pftrace_destroy(writer), PFTRACE_OK)) return 1;
  return 0;
}

static int sink_failure_matrix(void) {
  struct {
    size_t fail_on_call;
    int explicit_flush;
    int final_flush;
  } cases[] = {{1, 1, 0}, {2, 0, 0}, {1, 0, 1}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    pftrace_writer_options_t options;
    struct sink_state state = {.fail_on_call = cases[i].fail_on_call};
    pftrace_writer_t *writer;
    if (check(pftrace_writer_options_init(&options), PFTRACE_OK)) return (int)(61 + i);
    options.flush_each_packet = !cases[i].final_flush && !cases[i].explicit_flush;
    if (init_writer(&state, &options, &writer)) return (int)(71 + i);
    if (cases[i].final_flush) {
      if (check(pftrace_write_linux_boottime_clock_snapshot(writer, 1), PFTRACE_OK) ||
          check(pftrace_finalize(writer), PFTRACE_IO_ERROR)) return (int)(81 + i);
    } else if (cases[i].explicit_flush) {
      if (check(pftrace_write_linux_boottime_clock_snapshot(writer, 1), PFTRACE_OK) ||
          check(pftrace_flush(writer), PFTRACE_IO_ERROR)) return (int)(91 + i);
    } else {
      if (check(pftrace_write_linux_boottime_clock_snapshot(writer, 1), PFTRACE_OK) ||
          state.calls != 1 || state.retained_size == 0 ||
          check(pftrace_write_linux_boottime_clock_snapshot(writer, 2), PFTRACE_IO_ERROR)) return (int)(101 + i);
    }
    const size_t calls = state.calls;
    const size_t retained = state.retained_size;
    if (check(pftrace_writer_status(writer), PFTRACE_IO_ERROR) ||
        check(pftrace_write_linux_boottime_clock_snapshot(writer, 3), PFTRACE_IO_ERROR) ||
        check(pftrace_flush(writer), PFTRACE_IO_ERROR) || state.calls != calls ||
        state.retained_size != retained || check(pftrace_destroy(writer), PFTRACE_IO_ERROR)) return (int)(111 + i);
  }
  return 0;
}

int main(void) {
  if (recover_after_invalid_input()) return 11;
  if (unterminated_string_is_rejected()) return 12;
  if (bound_matrix()) return 13;
  if (lifecycle_matrix()) return 14;
  if (trace_saturation_recovers()) return 15;
  {
    const int sink_failure = sink_failure_matrix();
    if (sink_failure) return sink_failure;
  }
  return 0;
}
