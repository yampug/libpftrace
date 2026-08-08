#include "pftrace.h"

#include <stddef.h>

#define ASSERT_SIZE(type, expected) _Static_assert(sizeof(type) == (expected), #type " size")
#define ASSERT_OFFSET(type, field, expected) \
  _Static_assert(offsetof(type, field) == (expected), #type "." #field " offset")

_Static_assert(PFTRACE_OK == 0, "PFTRACE_OK value");
_Static_assert(PFTRACE_INVALID_ARGUMENT == 1, "PFTRACE_INVALID_ARGUMENT value");
_Static_assert(PFTRACE_INVALID_STATE == 2, "PFTRACE_INVALID_STATE value");
_Static_assert(PFTRACE_CAPACITY_EXCEEDED == 3, "PFTRACE_CAPACITY_EXCEEDED value");
_Static_assert(PFTRACE_MESSAGE_TOO_LARGE == 4, "PFTRACE_MESSAGE_TOO_LARGE value");
_Static_assert(PFTRACE_IO_ERROR == 5, "PFTRACE_IO_ERROR value");
_Static_assert(PFTRACE_DISABLED == 6, "PFTRACE_DISABLED value");
_Static_assert(PFTRACE_TRACK_EVENT_TYPE_COUNTER == 4, "track event enum value");
_Static_assert(PFTRACE_ARG_TYPE_POINTER == 5, "argument enum value");
_Static_assert(PFTRACE_CLOCK_ID_UNSPECIFIED == 0, "clock unspecified value");
_Static_assert(PFTRACE_CLOCK_ID_LINUX_BOOTTIME == 6, "clock boottime value");
_Static_assert(PFTRACE_CLOCK_ID_CUSTOM_FIRST == 64, "clock custom value");

ASSERT_SIZE(pftrace_status_t, 4);
ASSERT_SIZE(pftrace_string_t, 16);
ASSERT_OFFSET(pftrace_string_t, data, 0);
ASSERT_OFFSET(pftrace_string_t, size, 8);
ASSERT_SIZE(pftrace_writer_options_t, 88);
ASSERT_OFFSET(pftrace_writer_options_t, struct_size, 0);
ASSERT_OFFSET(pftrace_writer_options_t, packet_scratch_capacity, 8);
ASSERT_OFFSET(pftrace_writer_options_t, maximum_nesting_depth, 80);
ASSERT_OFFSET(pftrace_writer_options_t, flush_each_packet, 84);
ASSERT_SIZE(pftrace_arg_value_t, 16);
ASSERT_SIZE(pftrace_arg_t, 40);
ASSERT_OFFSET(pftrace_arg_t, key, 0);
ASSERT_OFFSET(pftrace_arg_t, type, 16);
ASSERT_OFFSET(pftrace_arg_t, value, 24);
ASSERT_SIZE(pftrace_event_common_t, 72);
ASSERT_OFFSET(pftrace_event_common_t, timestamp_ns, 0);
ASSERT_OFFSET(pftrace_event_common_t, timestamp_clock_id, 8);
ASSERT_OFFSET(pftrace_event_common_t, track_uuid, 16);
ASSERT_OFFSET(pftrace_event_common_t, flow_ids, 24);
ASSERT_OFFSET(pftrace_event_common_t, arguments, 56);
ASSERT_SIZE(pftrace_event_t, 120);
ASSERT_OFFSET(pftrace_event_t, timestamp_ns, 0);
ASSERT_OFFSET(pftrace_event_t, type, 24);
ASSERT_OFFSET(pftrace_event_t, name, 32);
ASSERT_OFFSET(pftrace_event_t, counter_value, 48);
ASSERT_OFFSET(pftrace_event_t, arguments, 104);

static pftrace_status_t check_write_callback(void *context, const uint8_t *bytes,
                                             size_t size) {
  (void)context;
  (void)bytes;
  (void)size;
  return PFTRACE_OK;
}

static pftrace_write_fn const check_callback_signature = check_write_callback;

void pftrace_public_layout_compile_only(void) {
  (void)check_callback_signature;
}
