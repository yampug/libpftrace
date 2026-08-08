require "./lib_pftrace"

module Pftrace
  enum EventType : UInt32
    Unspecified = 0; SliceBegin = 1; SliceEnd = 2; Instant = 3; Counter = 4
  end

  class Error < Exception
    getter status : LibPftrace::Status
    def initialize(@status : LibPftrace::Status, operation : String)
      super("#{operation}: #{status}")
    end
  end

  def self.check!(status : LibPftrace::Status, operation : String)
    raise Error.new(status, operation) unless status == LibPftrace::Status::Ok
  end

  class Trace
    @writer : LibPftrace::Writer
    @closed = false

    def initialize(path : String, options : LibPftrace::WriterOptions? = nil)
      writer = Pointer(Void).null.as(LibPftrace::Writer)
      opts = options || self.class.default_options
      Pftrace.check!(LibPftrace.init_path_with_options(path, pointerof(opts), pointerof(writer)), "pftrace init")
      @writer = writer
    end

    def self.default_options
      options = uninitialized LibPftrace::WriterOptions
      Pftrace.check!(LibPftrace.writer_options_init(pointerof(options)), "options init")
      options
    end

    def status : LibPftrace::Status
      @closed ? LibPftrace::Status::InvalidState : LibPftrace.writer_status(@writer)
    end

    def flush
      ensure_open!
      Pftrace.check!(LibPftrace.flush(@writer), "flush")
    end

    def finalize
      ensure_open!
      Pftrace.check!(LibPftrace.finalize(@writer), "finalize")
    end

    def close
      return if @closed
      Pftrace.check!(LibPftrace.destroy(@writer), "destroy")
      @writer = Pointer(Void).null.as(LibPftrace::Writer)
      @closed = true
    end

    def write_process_descriptor(pid : Int32, name : String, uuid : UInt64 = pid.to_u64)
      ensure_open!; Pftrace.check!(LibPftrace.write_process_track_descriptor(@writer, uuid, pid, name), "process descriptor")
    end
    def write_thread_descriptor(pid : Int32, tid : Int32, name : String, uuid : UInt64 = tid.to_u64, parent_uuid : UInt64 = pid.to_u64)
      ensure_open!; Pftrace.check!(LibPftrace.write_thread_track_descriptor(@writer, uuid, parent_uuid, pid, tid, name), "thread descriptor")
    end
    def write_clock_snapshot(clock_id : UInt32, timestamp_ns : UInt64)
      ensure_open!; Pftrace.check!(LibPftrace.write_clock_snapshot(@writer, clock_id, timestamp_ns), "clock snapshot")
    end
    def write_linux_boottime_clock_snapshot(timestamp_ns : UInt64)
      ensure_open!; Pftrace.check!(LibPftrace.write_linux_boottime_clock_snapshot(@writer, timestamp_ns), "boottime clock snapshot")
    end

    def trace(name : String? = nil, type : EventType = EventType::SliceBegin, track_uuid : UInt64? = nil, timestamp : UInt64? = nil, timestamp_clock_id : UInt32? = nil, trusted_packet_sequence_id : UInt32? = nil)
      ensure_open!
      packet = LibPftrace.packet_begin(@writer)
      raise Error.new(status, "packet begin") if packet.null?
      event : LibPftrace::TrackEvent = Pointer(Void).null.as(LibPftrace::TrackEvent)
      wrapper : Event? = nil
      begin
        Pftrace.check!(LibPftrace.packet_set_timestamp(packet, timestamp.not_nil!), "timestamp") if timestamp
        Pftrace.check!(LibPftrace.packet_set_timestamp_clock_id(packet, timestamp_clock_id.not_nil!), "timestamp clock") if timestamp_clock_id
        Pftrace.check!(LibPftrace.packet_set_trusted_packet_sequence_id(packet, trusted_packet_sequence_id.not_nil!), "sequence id") if trusted_packet_sequence_id
        event = LibPftrace.packet_begin_track_event(packet)
        raise Error.new(status, "event begin") if event.null?
        wrapper = Event.new(event)
        Pftrace.check!(LibPftrace.track_event_set_type(event, type.value), "event type")
        Pftrace.check!(LibPftrace.track_event_set_name(event, name.not_nil!), "event name") if name
        Pftrace.check!(LibPftrace.track_event_set_track_uuid(event, track_uuid.not_nil!), "track uuid") if track_uuid
        yield wrapper
        Pftrace.check!(LibPftrace.track_event_end(event), "event end")
        event = Pointer(Void).null.as(LibPftrace::TrackEvent)
        Pftrace.check!(LibPftrace.packet_commit(packet), "packet commit")
        packet = Pointer(Void).null.as(LibPftrace::Packet)
      ensure
        wrapper.try &.invalidate!
        unless event.null?
          LibPftrace.track_event_end(event)
        end
        unless packet.null?
          LibPftrace.packet_commit(packet)
        end
      end
    end

    private def ensure_open!
      raise Error.new(LibPftrace::Status::InvalidState, "writer closed") if @closed
    end
  end

  class Event
    @handle : LibPftrace::TrackEvent
    def initialize(@handle : LibPftrace::TrackEvent); end
    def invalidate!; @handle = Pointer(Void).null.as(LibPftrace::TrackEvent); end
    private def alive!; raise Error.new(LibPftrace::Status::InvalidState, "event handle invalid") if @handle.null?; end
    def category=(value : String); alive!; Pftrace.check!(LibPftrace.track_event_add_category(@handle, value), "category"); end
    def log_message=(value : String); alive!; Pftrace.check!(LibPftrace.track_event_set_log_message(@handle, value), "log message"); end
    def counter=(value : Int64); alive!; Pftrace.check!(LibPftrace.track_event_set_counter_value(@handle, value), "counter"); end
    def flow_begin(value : UInt64); alive!; Pftrace.check!(LibPftrace.track_event_add_flow_id(@handle, value), "flow"); end
    def flow_end(value : UInt64); alive!; Pftrace.check!(LibPftrace.track_event_add_terminating_flow_id(@handle, value), "terminating flow"); end
    def task_execution(file : String, func : String, line : Int32); alive!; Pftrace.check!(LibPftrace.track_event_set_task_execution(@handle, file, func, line.to_u32), "task execution"); end
    def arg(key : String, value : String); alive!; Pftrace.check!(LibPftrace.track_event_add_arg_string(@handle, key, value), "string argument"); end
    def arg(key : String, value : Int); alive!; Pftrace.check!(LibPftrace.track_event_add_arg_int(@handle, key, value.to_i64), "integer argument"); end
    def arg(key : String, value : UInt64); alive!; Pftrace.check!(LibPftrace.track_event_add_arg_uint(@handle, key, value), "unsigned argument"); end
    def arg(key : String, value : Float64); alive!; Pftrace.check!(LibPftrace.track_event_add_arg_double(@handle, key, value), "double argument"); end
    def arg(key : String, value : Bool); alive!; Pftrace.check!(LibPftrace.track_event_add_arg_bool(@handle, key, value), "bool argument"); end
    def arg_ptr(key : String, value : UInt64); alive!; Pftrace.check!(LibPftrace.track_event_add_arg_ptr(@handle, key, value), "pointer argument"); end
  end

  def self.open(path : String, options : LibPftrace::WriterOptions? = nil, &block)
    trace = Trace.new(path, options)
    begin
      yield trace
      trace.finalize
    ensure
      trace.close
    end
  end
end
