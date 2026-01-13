// Field IDs for Perfetto Trace Packets
// Source: https://github.com/google/perfetto/blob/master/protos/perfetto/trace/trace_packet.proto

pub const TracePacket = struct {
    pub const TIMESTAMP = 8;
    pub const TIMESTAMP_CLOCK_ID = 58;
    pub const TRUSTED_PACKET_SEQUENCE_ID = 10;
    pub const FTRACE_EVENTS = 1;
    pub const PROCESS_TREE = 2;
    pub const TRACE_CONFIG = 33;
    pub const TRACE_STATS = 35;
    pub const INTERNED_DATA = 12;
    pub const TRACK_EVENT = 11;
    pub const TRACK_DESCRIPTOR = 60;
    pub const CLOCK_SNAPSHOT = 6;
};

// https://github.com/google/perfetto/blob/master/protos/perfetto/trace/ftrace/ftrace_event_bundle.proto
pub const FtraceEventBundle = struct {
    pub const CPU = 1;
    pub const EVENT = 2;
    pub const LOST_EVENTS = 3;
    pub const COMPACT_SCHED = 4;
};

// https://github.com/google/perfetto/blob/master/protos/perfetto/trace/ftrace/ftrace_event.proto
pub const FtraceEvent = struct {
    pub const TIMESTAMP = 1;
    pub const PID = 2;
    pub const SCHED_SWITCH = 8;
    pub const SCHED_WAKEUP = 9;
};

// https://github.com/google/perfetto/blob/master/protos/perfetto/trace/track_event/track_event.proto
pub const TrackEvent = struct {
    pub const CATEGORIES = 22;
    pub const NAME = 23;
    pub const TYPE = 9;
    pub const TRACK_UUID = 11;
    pub const COUNTER_VALUE = 30;
    pub const EXTRA_COUNTER_VALUES = 12;
    pub const DEBUG_ANNOTATIONS = 4;
    pub const TASK_EXECUTION = 5;
    pub const LOG_MESSAGE = 21;
    pub const TIMESTAMP_DELTA_U64 = 1;
    pub const TIMESTAMP_ABSOLUTE_U64 = 16;
    pub const FLOW_IDS = 36;
    pub const TERMINATING_FLOW_IDS = 42;
};

pub const TrackEventType = enum(u32) {
    TYPE_UNSPECIFIED = 0,
    TYPE_SLICE_BEGIN = 1,
    TYPE_SLICE_END = 2,
    TYPE_INSTANT = 3,
    TYPE_COUNTER = 4,
};

// https://github.com/google/perfetto/blob/master/protos/perfetto/trace/track_event/debug_annotation.proto
pub const DebugAnnotation = struct {
    pub const NAME_IID = 1;
    pub const NAME = 10;
    pub const BOOL_VALUE = 2;
    pub const UINT_VALUE = 3;
    pub const INT_VALUE = 4;
    pub const DOUBLE_VALUE = 5;
    pub const STRING_VALUE = 6;
    pub const POINTER_VALUE = 7;
};

// https://github.com/google/perfetto/blob/master/protos/perfetto/trace/track_event/track_descriptor.proto
pub const TrackDescriptor = struct {
    pub const UUID = 1;
    pub const PARENT_UUID = 5;
    pub const NAME = 2;
    pub const PROCESS = 3;
    pub const THREAD = 4;
};

pub const ProcessDescriptor = struct {
    pub const PID = 1;
    pub const CMDLINE = 2;
    pub const PROCESS_NAME = 6;
};

pub const ThreadDescriptor = struct {
    pub const PID = 1;
    pub const TID = 2;
    pub const THREAD_NAME = 5;
};

// https://github.com/google/perfetto/blob/master/protos/perfetto/trace/clock_snapshot.proto
pub const ClockSnapshot = struct {
    pub const CLOCKS = 1;
};

pub const Clock = struct {
    pub const CLOCK_ID = 1;
    pub const TIMESTAMP = 2;
};

pub const SourceLocation = struct {
    pub const IID = 1;
    pub const FILE_NAME = 2;
    pub const FUNCTION_NAME = 3;
    pub const LINE_NUMBER = 4;
};

pub const TaskExecution = struct {
    pub const POSTED_FROM_IID = 1;
};

// https://github.com/google/perfetto/blob/master/protos/perfetto/trace/interned_data/interned_data.proto
pub const InternedData = struct {
    pub const EVENT_CATEGORIES = 1;
    pub const LOG_MESSAGE_BODY = 20;
    pub const DEBUG_ANNOTATION_NAMES = 5;
    pub const SOURCE_LOCATIONS = 4;
};

pub const LogMessageBody = struct {
    pub const IID = 1;
    pub const BODY = 2;
};

pub const LogMessage = struct {
    pub const SOURCE_LOCATION_IID = 1;
    pub const BODY_IID = 2;
    pub const PRIO = 3;
};
