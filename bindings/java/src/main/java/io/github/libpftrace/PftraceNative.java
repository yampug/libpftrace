package io.github.libpftrace;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Union;
import com.sun.jna.Callback;
import com.sun.jna.ptr.PointerByReference;

/**
 * Low-level C ABI mirror. Most applications should use {@link Trace}; this is
 * public for applications that need the builder API or a custom callback sink.
 */
public interface PftraceNative extends Library {
  static PftraceNative instance() {
    return Holder.INSTANCE;
  }
  final class Holder {
    private static final String LIBRARY = System.getProperty("pftrace.library", "pftrace");
    private static final PftraceNative INSTANCE = Native.load(LIBRARY, PftraceNative.class);
  }

  int pftrace_writer_status(Pointer writer);
  int pftrace_writer_options_init(WriterOptions options);
  int pftrace_init_path_with_options(String path, WriterOptions options, PointerByReference writer);
  int pftrace_init_fd_with_options(int fd, WriterOptions options, PointerByReference writer);
  int pftrace_init_callback_with_options(WriteCallback callback, Pointer context, WriterOptions options, PointerByReference writer);
  int pftrace_destroy(Pointer writer);
  int pftrace_flush(Pointer writer);
  int pftrace_finalize(Pointer writer);
  int pftrace_write_event(Pointer writer, DirectEvent event);
  int pftrace_write_slice_begin(Pointer writer, EventCommon common, NativeString name);
  int pftrace_write_slice_end(Pointer writer, EventCommon common, NativeString name);
  int pftrace_write_instant(Pointer writer, EventCommon common, NativeString name);
  int pftrace_write_counter(Pointer writer, EventCommon common, NativeString name, long value);
  int pftrace_write_process_track_descriptor(Pointer writer, long uuid, int pid, String name);
  int pftrace_write_thread_track_descriptor(Pointer writer, long uuid, long parentUuid, int pid, int tid, String name);
  int pftrace_write_clock_snapshot(Pointer writer, int clockId, long timestampNs);
  int pftrace_write_linux_boottime_clock_snapshot(Pointer writer, long timestampNs);

  Pointer pftrace_packet_begin(Pointer writer);
  int pftrace_packet_end(Pointer writer, Pointer packet);
  int pftrace_packet_commit(Pointer packet);
  int pftrace_packet_set_timestamp(Pointer packet, long timestampNs);
  int pftrace_packet_set_timestamp_clock_id(Pointer packet, int clockId);
  int pftrace_packet_set_trusted_packet_sequence_id(Pointer packet, int sequenceId);
  Pointer pftrace_packet_begin_track_event(Pointer packet);
  int pftrace_track_event_end(Pointer event);
  int pftrace_track_event_set_type(Pointer event, int type);
  int pftrace_track_event_set_track_uuid(Pointer event, long uuid);
  int pftrace_track_event_set_counter_value(Pointer event, long value);
  int pftrace_track_event_add_flow_id(Pointer event, long flowId);
  int pftrace_track_event_add_terminating_flow_id(Pointer event, long flowId);
  int pftrace_track_event_set_name(Pointer event, String name);
  int pftrace_track_event_add_category(Pointer event, String category);
  int pftrace_track_event_set_log_message(Pointer event, String message);
  int pftrace_track_event_set_task_execution(Pointer event, String file, String function, int line);
  int pftrace_track_event_add_arg_string(Pointer event, String key, String value);
  int pftrace_track_event_add_arg_int(Pointer event, String key, long value);
  int pftrace_track_event_add_arg_uint(Pointer event, String key, long value);
  int pftrace_track_event_add_arg_double(Pointer event, String key, double value);
  int pftrace_track_event_add_arg_bool(Pointer event, String key, byte value);
  int pftrace_track_event_add_arg_ptr(Pointer event, String key, long value);

  /** C callback sink; return {@link Status#OK} only after consuming every byte. */
  interface WriteCallback extends Callback { int invoke(Pointer context, Pointer bytes, long size); }

  @Structure.FieldOrder({"data", "size"})
  class NativeString extends Structure {
    public Pointer data; public long size;
  }
  @Structure.FieldOrder({"stringValue", "int64Value", "uint64Value", "doubleValue", "boolValue", "pointerValue"})
  class ArgValue extends Union {
    public NativeString stringValue; public long int64Value; public long uint64Value;
    public double doubleValue; public byte boolValue; public long pointerValue;
  }
  @Structure.FieldOrder({"key", "type", "value"})
  class Arg extends Structure { public NativeString key; public int type; public ArgValue value; }
  @Structure.FieldOrder({"timestampNs", "timestampClockId", "trustedPacketSequenceId", "trackUuid",
      "type", "name", "counterValue", "flowIds", "flowIdCount", "terminatingFlowIds",
      "terminatingFlowIdCount", "categories", "categoryCount", "arguments", "argumentCount"})
  class DirectEvent extends Structure {
    public long timestampNs; public int timestampClockId; public int trustedPacketSequenceId; public long trackUuid;
    public int type; public NativeString name; public long counterValue; public Pointer flowIds; public long flowIdCount;
    public Pointer terminatingFlowIds; public long terminatingFlowIdCount; public Pointer categories; public long categoryCount;
    public Pointer arguments; public long argumentCount;
  }
  @Structure.FieldOrder({"timestampNs", "timestampClockId", "trustedPacketSequenceId", "trackUuid",
      "flowIds", "flowIdCount", "terminatingFlowIds", "terminatingFlowIdCount", "arguments", "argumentCount"})
  class EventCommon extends Structure {
    public long timestampNs; public int timestampClockId; public int trustedPacketSequenceId; public long trackUuid;
    public Pointer flowIds; public long flowIdCount; public Pointer terminatingFlowIds; public long terminatingFlowIdCount;
    public Pointer arguments; public long argumentCount;
  }
}
