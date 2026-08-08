# Link against the local static library.
# We assume the library is built in ../../zig-out/lib relative to this file's location in src/
@[Link(ldflags: "-L#{__DIR__}/../../../zig-out/lib -lpftrace")]
lib LibPftrace
  type Writer = Void*
  type Packet = Void*
  type TrackEvent = Void*

  enum Status : Int32
    Ok = 0
    InvalidArgument = 1
    InvalidState = 2
    CapacityExceeded = 3
    MessageTooLarge = 4
    IoError = 5
    Disabled = 6
  end

  struct String
    data : LibC::Char*
    size : LibC::SizeT
  end

  # --- Lifecycle ---
  fun init = pftrace_init(file_path : LibC::Char*) : Writer
  fun destroy = pftrace_destroy(w : Writer)

  # --- Packet Lifecycle ---
  fun packet_begin = pftrace_packet_begin(w : Writer) : Packet
  fun packet_end = pftrace_packet_end(w : Writer, packet : Packet) : Status

  # --- Core Features ---
  fun packet_set_timestamp = pftrace_packet_set_timestamp(p : Packet, timestamp_ns : UInt64) : Status
  fun packet_set_trusted_packet_sequence_id = pftrace_packet_set_trusted_packet_sequence_id(p : Packet, seq_id : UInt32) : Status

  # --- Domain Objects ---
  fun write_process_track_descriptor = pftrace_write_process_track_descriptor(w : Writer, uuid : UInt64, pid : Int32, name : LibC::Char*) : Status
  fun write_thread_track_descriptor = pftrace_write_thread_track_descriptor(w : Writer, uuid : UInt64, parent_uuid : UInt64, pid : Int32, tid : Int32, name : LibC::Char*) : Status
  fun write_clock_snapshot = pftrace_write_clock_snapshot(w : Writer, clock_id : UInt32, timestamp_ns : UInt64) : Status
  fun write_linux_boottime_clock_snapshot = pftrace_write_linux_boottime_clock_snapshot(w : Writer, boottime_ns : UInt64) : Status

  # --- Track Events ---
  fun packet_begin_track_event = pftrace_packet_begin_track_event(p : Packet) : TrackEvent
  fun track_event_end = pftrace_track_event_end(te : TrackEvent) : Status

  fun track_event_set_type = pftrace_track_event_set_type(te : TrackEvent, type : UInt32) : Status
  fun track_event_set_name = pftrace_track_event_set_name(te : TrackEvent, name : LibC::Char*) : Status
  fun track_event_set_track_uuid = pftrace_track_event_set_track_uuid(te : TrackEvent, uuid : UInt64) : Status
  fun track_event_add_category = pftrace_track_event_add_category(te : TrackEvent, category : LibC::Char*) : Status
  fun track_event_set_counter_value = pftrace_track_event_set_counter_value(te : TrackEvent, value : Int64) : Status
  fun track_event_add_flow_id = pftrace_track_event_add_flow_id(te : TrackEvent, flow_id : UInt64) : Status
  fun track_event_add_terminating_flow_id = pftrace_track_event_add_terminating_flow_id(te : TrackEvent, flow_id : UInt64) : Status

  # --- Structured Features ---
  fun track_event_set_log_message = pftrace_track_event_set_log_message(te : TrackEvent, body : LibC::Char*) : Status
  fun track_event_set_task_execution = pftrace_track_event_set_task_execution(te : TrackEvent, file : LibC::Char*, func : LibC::Char*, line : UInt32) : Status

  # --- Arguments ---
  fun track_event_add_arg_string = pftrace_track_event_add_arg_string(te : TrackEvent, key : LibC::Char*, value : LibC::Char*) : Status
  fun track_event_add_arg_int = pftrace_track_event_add_arg_int(te : TrackEvent, key : LibC::Char*, value : Int64) : Status
  fun track_event_add_arg_uint = pftrace_track_event_add_arg_uint(te : TrackEvent, key : LibC::Char*, value : UInt64) : Status
  fun track_event_add_arg_double = pftrace_track_event_add_arg_double(te : TrackEvent, key : LibC::Char*, value : Float64) : Status
  fun track_event_add_arg_bool = pftrace_track_event_add_arg_bool(te : TrackEvent, key : LibC::Char*, value : Bool) : Status
  fun track_event_add_arg_ptr = pftrace_track_event_add_arg_ptr(te : TrackEvent, key : LibC::Char*, value : UInt64) : Status
end
