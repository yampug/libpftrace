package io.github.libpftrace;

/** Stable result codes returned by libpftrace. */
public enum Status {
  OK(0), INVALID_ARGUMENT(1), INVALID_STATE(2), CAPACITY_EXCEEDED(3),
  MESSAGE_TOO_LARGE(4), IO_ERROR(5), DISABLED(6);

  private final int value;
  Status(int value) { this.value = value; }
  public int value() { return value; }
  static Status from(int value) {
    for (Status status : values()) if (status.value == value) return status;
    throw new IllegalArgumentException("unknown pftrace status: " + value);
  }
}
