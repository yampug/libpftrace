package io.github.libpftrace;

import com.sun.jna.Pointer;

/** Mutable builder available only during a {@link Trace#trace} callback. */
public final class Event {
  private Pointer handle;
  Event(Pointer handle) { this.handle = handle; }
  void invalidate() { handle = null; }
  private Pointer alive() {
    if (handle == null) throw new PftraceException(Status.INVALID_STATE, "event handle invalid");
    return handle;
  }
  public Event category(String value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_category(alive(), value), "category"); return this;
  }
  public Event logMessage(String value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_set_log_message(alive(), value), "log message"); return this;
  }
  public Event counter(long value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_set_counter_value(alive(), value), "counter"); return this;
  }
  public Event flowBegin(long value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_flow_id(alive(), value), "flow"); return this;
  }
  public Event flowEnd(long value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_terminating_flow_id(alive(), value), "terminating flow"); return this;
  }
  public Event taskExecution(String file, String function, int line) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_set_task_execution(alive(), file, function, line), "task execution"); return this;
  }
  public Event arg(String key, String value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_arg_string(alive(), key, value), "string argument"); return this;
  }
  public Event arg(String key, long value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_arg_int(alive(), key, value), "integer argument"); return this;
  }
  public Event arg(String key, double value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_arg_double(alive(), key, value), "double argument"); return this;
  }
  public Event arg(String key, boolean value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_arg_bool(alive(), key, (byte) (value ? 1 : 0)), "bool argument"); return this;
  }
  /** Adds a uint64 value; Java's long carries the unsigned bits unchanged. */
  public Event argUnsigned(String key, long value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_arg_uint(alive(), key, value), "unsigned argument"); return this;
  }
  /** Adds an address as an unsigned 64-bit integer; libpftrace never dereferences it. */
  public Event argPointer(String key, long value) {
    Pftrace.check(PftraceNative.instance().pftrace_track_event_add_arg_ptr(alive(), key, value), "pointer argument"); return this;
  }
}
