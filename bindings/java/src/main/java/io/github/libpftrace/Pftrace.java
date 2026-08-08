package io.github.libpftrace;

/** Shared constants and error conversion for the Java binding. */
public final class Pftrace {
  public static final int CLOCK_ID_UNSPECIFIED = 0;
  public static final int CLOCK_ID_LINUX_BOOTTIME = 6;
  public static final int CLOCK_ID_CUSTOM_FIRST = 64;
  private Pftrace() {}
  static void check(int status, String operation) {
    Status result = Status.from(status);
    if (result != Status.OK) throw new PftraceException(result, operation);
  }
}
