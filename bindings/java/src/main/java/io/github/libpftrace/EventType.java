package io.github.libpftrace;

/** Perfetto track-event types. */
public enum EventType {
  UNSPECIFIED(0), SLICE_BEGIN(1), SLICE_END(2), INSTANT(3), COUNTER(4);
  private final int value;
  EventType(int value) { this.value = value; }
  int value() { return value; }
}
