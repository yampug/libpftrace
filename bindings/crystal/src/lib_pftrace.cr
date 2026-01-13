# Link against the local static library.
# We assume the library is built in ../../zig-out/lib relative to this file's location in src/
@[Link(ldflags: "-L#{__DIR__}/../../../zig-out/lib -lpftrace")]
lib LibPftrace
  type Writer = Void*
  type Packet = Void*
  type TrackEvent = Void*

  # --- Lifecycle ---
  fun init = pftrace_init(file_path : LibC::Char*) : Writer
  fun destroy = pftrace_destroy(w : Writer)

  # --- Packet Lifecycle ---
  fun packet_begin = pftrace_packet_begin(w : Writer) : Packet
  fun packet_end = pftrace_packet_end(w : Writer, packet : Packet)

  # --- Core Features ---
  fun packet_set_timestamp = pftrace_packet_set_timestamp(p : Packet, timestamp_ns : UInt64)
  fun packet_set_trusted_packet_sequence_id = pftrace_packet_set_trusted_packet_sequence_id(p : Packet, seq_id : UInt32)

  # --- Domain Objects ---
  fun write_process_track_descriptor = pftrace_write_process_track_descriptor(w : Writer, uuid : UInt64, pid : Int32, name : LibC::Char*)
  fun write_thread_track_descriptor = pftrace_write_thread_track_descriptor(w : Writer, uuid : UInt64, parent_uuid : UInt64, pid : Int32, tid : Int32, name : LibC::Char*)
  fun write_clock_snapshot = pftrace_write_clock_snapshot(w : Writer, boottime_ns : UInt64)

  # --- Track Events ---
  fun packet_begin_track_event = pftrace_packet_begin_track_event(p : Packet) : TrackEvent
  fun track_event_end = pftrace_track_event_end(te : TrackEvent)

  fun track_event_set_type = pftrace_track_event_set_type(te : TrackEvent, type : UInt32)
  fun track_event_set_name = pftrace_track_event_set_name(te : TrackEvent, name : LibC::Char*)
  fun track_event_set_track_uuid = pftrace_track_event_set_track_uuid(te : TrackEvent, uuid : UInt64)
  fun track_event_add_category = pftrace_track_event_add_category(te : TrackEvent, category : LibC::Char*)
  fun track_event_set_counter_value = pftrace_track_event_set_counter_value(te : TrackEvent, value : Int64)
  fun track_event_add_flow_id = pftrace_track_event_add_flow_id(te : TrackEvent, flow_id : UInt64)
  fun track_event_add_terminating_flow_id = pftrace_track_event_add_terminating_flow_id(te : TrackEvent, flow_id : UInt64)

  # --- Structured Features ---
  fun track_event_set_log_message = pftrace_track_event_set_log_message(te : TrackEvent, body : LibC::Char*)
  fun track_event_set_task_execution = pftrace_track_event_set_task_execution(te : TrackEvent, file : LibC::Char*, func : LibC::Char*, line : UInt32)

  # --- Arguments ---
  fun track_event_add_arg_string = pftrace_track_event_add_arg_string(te : TrackEvent, key : LibC::Char*, value : LibC::Char*)
  fun track_event_add_arg_int = pftrace_track_event_add_arg_int(te : TrackEvent, key : LibC::Char*, value : Int64)
  fun track_event_add_arg_uint = pftrace_track_event_add_arg_uint(te : TrackEvent, key : LibC::Char*, value : UInt64)
  fun track_event_add_arg_double = pftrace_track_event_add_arg_double(te : TrackEvent, key : LibC::Char*, value : Float64)
  fun track_event_add_arg_bool = pftrace_track_event_add_arg_bool(te : TrackEvent, key : LibC::Char*, value : Bool)
  fun track_event_add_arg_ptr = pftrace_track_event_add_arg_ptr(te : TrackEvent, key : LibC::Char*, value : UInt64)
end
