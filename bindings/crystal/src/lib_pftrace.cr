# Generated-by-hand C ABI mirror for include/pftrace.h. Keep field order and
# numeric values stable with public header; high-level wrapper lives in pftrace.cr.
@[Link(ldflags: "-L#{__DIR__}/../../../zig-out/lib -lpftrace")]
lib LibPftrace
  type Writer = Void*
  type Packet = Void*
  type TrackEvent = Void*

  enum Status : Int32
    Ok = 0; InvalidArgument = 1; InvalidState = 2; CapacityExceeded = 3
    MessageTooLarge = 4; IoError = 5; Disabled = 6
  end
  enum TrackEventType : UInt32
    Unspecified = 0; SliceBegin = 1; SliceEnd = 2; Instant = 3; Counter = 4
  end
  enum ArgType : Int32
    String = 0; Int64 = 1; UInt64 = 2; Double = 3; Bool = 4; Pointer = 5
  end

  CLOCK_ID_UNSPECIFIED = 0_u32
  CLOCK_ID_LINUX_BOOTTIME = 6_u32
  CLOCK_ID_CUSTOM_FIRST = 64_u32

  struct String
    data : LibC::Char*
    size : LibC::SizeT
  end
  struct WriterOptions
    struct_size : UInt32
    version : UInt32
    packet_scratch_capacity : LibC::SizeT
    output_batch_capacity : LibC::SizeT
    maximum_packet_bytes : LibC::SizeT
    maximum_trace_bytes : LibC::SizeT
    maximum_string_bytes : LibC::SizeT
    maximum_arguments : LibC::SizeT
    maximum_categories : LibC::SizeT
    maximum_flow_ids : LibC::SizeT
    maximum_terminating_flow_ids : LibC::SizeT
    maximum_nesting_depth : UInt32
    flush_each_packet : Bool
  end
  union ArgValue
    string_value : String
    int64_value : Int64
    uint64_value : UInt64
    double_value : Float64
    bool_value : Bool
    pointer_value : UInt64
  end
  struct Arg
    key : String
    type : ArgType
    value : ArgValue
  end
  struct Event
    timestamp_ns : UInt64
    timestamp_clock_id : UInt32
    trusted_packet_sequence_id : UInt32
    track_uuid : UInt64
    type : TrackEventType
    name : String
    counter_value : Int64
    flow_ids : UInt64*
    flow_id_count : LibC::SizeT
    terminating_flow_ids : UInt64*
    terminating_flow_id_count : LibC::SizeT
    categories : String*
    category_count : LibC::SizeT
    arguments : Arg*
    argument_count : LibC::SizeT
  end
  struct EventCommon
    timestamp_ns : UInt64
    timestamp_clock_id : UInt32
    trusted_packet_sequence_id : UInt32
    track_uuid : UInt64
    flow_ids : UInt64*
    flow_id_count : LibC::SizeT
    terminating_flow_ids : UInt64*
    terminating_flow_id_count : LibC::SizeT
    arguments : Arg*
    argument_count : LibC::SizeT
  end
  alias WriteFn = (Void*, UInt8*, LibC::SizeT -> Status)

  fun status_string = pftrace_status_string(status : Status) : LibC::Char*
  fun writer_status = pftrace_writer_status(writer : Writer) : Status
  fun writer_options_init = pftrace_writer_options_init(options : WriterOptions*) : Status
  fun init_path_with_options = pftrace_init_path_with_options(path : LibC::Char*, options : WriterOptions*, out_writer : Writer*) : Status
  fun init_fd_with_options = pftrace_init_fd_with_options(fd : Int32, options : WriterOptions*, out_writer : Writer*) : Status
  fun init_callback_with_options = pftrace_init_callback_with_options(write_fn : WriteFn, context : Void*, options : WriterOptions*, out_writer : Writer*) : Status
  fun destroy = pftrace_destroy(writer : Writer) : Status
  fun flush = pftrace_flush(writer : Writer) : Status
  fun finalize = pftrace_finalize(writer : Writer) : Status
  fun write_event = pftrace_write_event(writer : Writer, event : Event*) : Status
  fun write_slice_begin = pftrace_write_slice_begin(writer : Writer, common : EventCommon*, name : String) : Status
  fun write_slice_end = pftrace_write_slice_end(writer : Writer, common : EventCommon*, name : String) : Status
  fun write_instant = pftrace_write_instant(writer : Writer, common : EventCommon*, name : String) : Status
  fun write_counter = pftrace_write_counter(writer : Writer, common : EventCommon*, name : String, value : Int64) : Status
  fun packet_begin = pftrace_packet_begin(writer : Writer) : Packet
  fun packet_end = pftrace_packet_end(writer : Writer, packet : Packet) : Status
  fun packet_commit = pftrace_packet_commit(packet : Packet) : Status
  fun packet_set_timestamp = pftrace_packet_set_timestamp(packet : Packet, timestamp_ns : UInt64) : Status
  fun packet_set_timestamp_clock_id = pftrace_packet_set_timestamp_clock_id(packet : Packet, clock_id : UInt32) : Status
  fun packet_set_trusted_packet_sequence_id = pftrace_packet_set_trusted_packet_sequence_id(packet : Packet, seq_id : UInt32) : Status
  fun write_process_track_descriptor = pftrace_write_process_track_descriptor(writer : Writer, uuid : UInt64, pid : Int32, name : LibC::Char*) : Status
  fun write_thread_track_descriptor = pftrace_write_thread_track_descriptor(writer : Writer, uuid : UInt64, parent_uuid : UInt64, pid : Int32, tid : Int32, name : LibC::Char*) : Status
  fun write_clock_snapshot = pftrace_write_clock_snapshot(writer : Writer, clock_id : UInt32, timestamp_ns : UInt64) : Status
  fun write_linux_boottime_clock_snapshot = pftrace_write_linux_boottime_clock_snapshot(writer : Writer, boottime_ns : UInt64) : Status
  fun packet_begin_track_event = pftrace_packet_begin_track_event(packet : Packet) : TrackEvent
  fun track_event_end = pftrace_track_event_end(event : TrackEvent) : Status
  fun track_event_set_type = pftrace_track_event_set_type(event : TrackEvent, type : UInt32) : Status
  fun track_event_set_track_uuid = pftrace_track_event_set_track_uuid(event : TrackEvent, uuid : UInt64) : Status
  fun track_event_set_counter_value = pftrace_track_event_set_counter_value(event : TrackEvent, value : Int64) : Status
  fun track_event_add_flow_id = pftrace_track_event_add_flow_id(event : TrackEvent, flow_id : UInt64) : Status
  fun track_event_add_terminating_flow_id = pftrace_track_event_add_terminating_flow_id(event : TrackEvent, flow_id : UInt64) : Status
  fun track_event_set_name = pftrace_track_event_set_name(event : TrackEvent, name : LibC::Char*) : Status
  fun track_event_add_category = pftrace_track_event_add_category(event : TrackEvent, category : LibC::Char*) : Status
  fun track_event_set_log_message = pftrace_track_event_set_log_message(event : TrackEvent, body : LibC::Char*) : Status
  fun track_event_set_task_execution = pftrace_track_event_set_task_execution(event : TrackEvent, file : LibC::Char*, func : LibC::Char*, line : UInt32) : Status
  fun track_event_add_arg_string = pftrace_track_event_add_arg_string(event : TrackEvent, key : LibC::Char*, value : LibC::Char*) : Status
  fun track_event_add_arg_int = pftrace_track_event_add_arg_int(event : TrackEvent, key : LibC::Char*, value : Int64) : Status
  fun track_event_add_arg_uint = pftrace_track_event_add_arg_uint(event : TrackEvent, key : LibC::Char*, value : UInt64) : Status
  fun track_event_add_arg_double = pftrace_track_event_add_arg_double(event : TrackEvent, key : LibC::Char*, value : Float64) : Status
  fun track_event_add_arg_bool = pftrace_track_event_add_arg_bool(event : TrackEvent, key : LibC::Char*, value : Bool) : Status
  fun track_event_add_arg_ptr = pftrace_track_event_add_arg_ptr(event : TrackEvent, key : LibC::Char*, value : UInt64) : Status
end
