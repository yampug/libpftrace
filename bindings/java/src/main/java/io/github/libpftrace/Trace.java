package io.github.libpftrace;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Consumer;

/** A single-writer, AutoCloseable Perfetto trace. */
public final class Trace implements AutoCloseable {
  private Pointer writer;

  public Trace(String path) { this(path, WriterOptions.defaults()); }
  public Trace(Path path) { this(path.toString()); }
  public Trace(Path path, WriterOptions options) { this(path.toString(), options); }
  public Trace(String path, WriterOptions options) {
    Objects.requireNonNull(path, "path");
    Objects.requireNonNull(options, "options");
    options.write();
    PointerByReference output = new PointerByReference();
    Pftrace.check(PftraceNative.instance().pftrace_init_path_with_options(path, options, output), "pftrace init");
    writer = output.getValue();
  }

  public Status status() { return writer == null ? Status.INVALID_STATE : Status.from(PftraceNative.instance().pftrace_writer_status(writer)); }
  public void flush() { Pftrace.check(PftraceNative.instance().pftrace_flush(open()), "flush"); }
  public void finalizeTrace() { Pftrace.check(PftraceNative.instance().pftrace_finalize(open()), "finalize"); }

  public void writeProcessDescriptor(int pid, String name) { writeProcessDescriptor(pid, name, Integer.toUnsignedLong(pid)); }
  public void writeProcessDescriptor(int pid, String name, long uuid) {
    Pftrace.check(PftraceNative.instance().pftrace_write_process_track_descriptor(open(), uuid, pid, name), "process descriptor");
  }
  public void writeThreadDescriptor(int pid, int tid, String name) {
    writeThreadDescriptor(pid, tid, name, Integer.toUnsignedLong(tid), Integer.toUnsignedLong(pid));
  }
  public void writeThreadDescriptor(int pid, int tid, String name, long uuid, long parentUuid) {
    Pftrace.check(PftraceNative.instance().pftrace_write_thread_track_descriptor(open(), uuid, parentUuid, pid, tid, name), "thread descriptor");
  }
  public void writeClockSnapshot(int clockId, long timestampNs) {
    Pftrace.check(PftraceNative.instance().pftrace_write_clock_snapshot(open(), clockId, timestampNs), "clock snapshot");
  }
  public void writeLinuxBoottimeClockSnapshot(long timestampNs) {
    Pftrace.check(PftraceNative.instance().pftrace_write_linux_boottime_clock_snapshot(open(), timestampNs), "boottime clock snapshot");
  }

  public void trace(String name, Consumer<Event> action) { trace(name, EventType.SLICE_BEGIN, null, null, null, null, action); }
  public void trace(String name, EventType type, Consumer<Event> action) { trace(name, type, null, null, null, null, action); }
  public void trace(String name, EventType type, Long trackUuid, Long timestampNs,
                    Integer timestampClockId, Integer sequenceId, Consumer<Event> action) {
    Objects.requireNonNull(type, "type"); Objects.requireNonNull(action, "action");
    Pointer packet = PftraceNative.instance().pftrace_packet_begin(open());
    if (packet == null) throw new PftraceException(status(), "packet begin");
    Pointer nativeEvent = null;
    Event event = null;
    try {
      if (timestampNs != null) Pftrace.check(PftraceNative.instance().pftrace_packet_set_timestamp(packet, timestampNs), "timestamp");
      if (timestampClockId != null) Pftrace.check(PftraceNative.instance().pftrace_packet_set_timestamp_clock_id(packet, timestampClockId), "timestamp clock");
      if (sequenceId != null) Pftrace.check(PftraceNative.instance().pftrace_packet_set_trusted_packet_sequence_id(packet, sequenceId), "sequence id");
      nativeEvent = PftraceNative.instance().pftrace_packet_begin_track_event(packet);
      if (nativeEvent == null) throw new PftraceException(status(), "event begin");
      event = new Event(nativeEvent);
      Pftrace.check(PftraceNative.instance().pftrace_track_event_set_type(nativeEvent, type.value()), "event type");
      if (name != null) Pftrace.check(PftraceNative.instance().pftrace_track_event_set_name(nativeEvent, name), "event name");
      if (trackUuid != null) Pftrace.check(PftraceNative.instance().pftrace_track_event_set_track_uuid(nativeEvent, trackUuid), "track uuid");
      action.accept(event);
      Pftrace.check(PftraceNative.instance().pftrace_track_event_end(nativeEvent), "event end");
      nativeEvent = null;
      Pftrace.check(PftraceNative.instance().pftrace_packet_commit(packet), "packet commit");
      packet = null;
    } finally {
      if (event != null) event.invalidate();
      if (nativeEvent != null) PftraceNative.instance().pftrace_track_event_end(nativeEvent);
      if (packet != null) PftraceNative.instance().pftrace_packet_commit(packet);
    }
  }

  /** Finalizes then releases the native writer. Closing an already closed trace is a no-op. */
  @Override public void close() {
    if (writer == null) return;
    Pointer current = writer;
    writer = null;
    Pftrace.check(PftraceNative.instance().pftrace_destroy(current), "destroy");
  }
  private Pointer open() {
    if (writer == null) throw new PftraceException(Status.INVALID_STATE, "writer closed");
    return writer;
  }
}
