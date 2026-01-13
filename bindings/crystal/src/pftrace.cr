require "./lib_pftrace"

module Pftrace
  enum EventType : UInt32
    Unspecified = 0
    SliceBegin = 1
    SliceEnd = 2
    Instant = 3
    Counter = 4
  end

  class Trace
    @writer : LibPftrace::Writer

    def initialize(path : String)
      @writer = LibPftrace.init(path)
      raise "Failed to initialize pftrace writer" if @writer.null?
    end

    def finalize
      LibPftrace.destroy(@writer)
    end

    def close
      LibPftrace.destroy(@writer)
      @writer = Pointer(Void).null.as(LibPftrace::Writer)
    end

    # Metadata
    def write_process_descriptor(pid : Int32, name : String, uuid : UInt64 = pid.to_u64)
      LibPftrace.write_process_track_descriptor(@writer, uuid, pid, name)
    end

    def write_thread_descriptor(pid : Int32, tid : Int32, name : String, uuid : UInt64 = tid.to_u64, parent_uuid : UInt64 = pid.to_u64)
      LibPftrace.write_thread_track_descriptor(@writer, uuid, parent_uuid, pid, tid, name)
    end

    def write_clock_snapshot(boottime_ns : UInt64)
      LibPftrace.write_clock_snapshot(@writer, boottime_ns)
    end

    # Event Tracing
    def trace(name : String? = nil, type : EventType = EventType::SliceBegin, track_uuid : UInt64? = nil, timestamp : UInt64? = nil, trusted_packet_sequence_id : UInt32? = nil)
      packet = LibPftrace.packet_begin(@writer)
      return if packet.null?

      begin
        LibPftrace.packet_set_timestamp(packet, timestamp) if timestamp
        LibPftrace.packet_set_trusted_packet_sequence_id(packet, trusted_packet_sequence_id) if trusted_packet_sequence_id

        event_handle = LibPftrace.packet_begin_track_event(packet)
        unless event_handle.null?
          # Create a managed wrapper class
          wrapper = Event.new(event_handle)
          begin
            LibPftrace.track_event_set_type(event_handle, type.value)
            LibPftrace.track_event_set_name(event_handle, name) if name
            LibPftrace.track_event_set_track_uuid(event_handle, track_uuid) if track_uuid
            
            yield wrapper
          ensure
            LibPftrace.track_event_end(event_handle)
            # CRITICAL: Invalidate the wrapper so user cannot use it after block returns
            wrapper.invalidate!
          end
        end
      ensure
        LibPftrace.packet_end(@writer, packet)
      end
    end
  end

  class Event
    @handle : LibPftrace::TrackEvent

    def initialize(@handle : LibPftrace::TrackEvent)
    end

    def invalidate!
      @handle = Pointer(Void).null.as(LibPftrace::TrackEvent)
    end

    private def check_alive!
      if @handle.null?
        raise "Use-After-Free detected: Event object accessed after trace block ended"
      end
    end

    def category=(cat : String)
      check_alive!
      LibPftrace.track_event_add_category(@handle, cat)
    end

    def log_message=(msg : String)
      check_alive!
      LibPftrace.track_event_set_log_message(@handle, msg)
    end

    def counter=(val : Int64)
      check_alive!
      LibPftrace.track_event_set_counter_value(@handle, val)
    end

    def flow_begin(id : UInt64)
      check_alive!
      LibPftrace.track_event_add_flow_id(@handle, id)
    end

    def flow_end(id : UInt64)
      check_alive!
      LibPftrace.track_event_add_terminating_flow_id(@handle, id)
    end

    def task_execution(file : String, func : String, line : Int32)
      check_alive!
      LibPftrace.track_event_set_task_execution(@handle, file, func, line.to_u32)
    end

    # Arguments
    def arg(key : String, val : String)
      check_alive!
      LibPftrace.track_event_add_arg_string(@handle, key, val)
    end

    def arg(key : String, val : Int)
      check_alive!
      LibPftrace.track_event_add_arg_int(@handle, key, val.to_i64)
    end

    def arg(key : String, val : UInt64)
      check_alive!
      LibPftrace.track_event_add_arg_uint(@handle, key, val)
    end
    
    def arg(key : String, val : Float64)
      check_alive!
      LibPftrace.track_event_add_arg_double(@handle, key, val)
    end

    def arg(key : String, val : Bool)
      check_alive!
      LibPftrace.track_event_add_arg_bool(@handle, key, val)
    end

    def arg_ptr(key : String, val : UInt64)
      check_alive!
      LibPftrace.track_event_add_arg_ptr(@handle, key, val)
    end
  end

  def self.open(path : String, &block)
    trace = Trace.new(path)
    begin
      yield trace
    ensure
      trace.close
    end
  end
end
