package io.github.libpftrace;

/** A failed libpftrace operation, retaining the original native status. */
public final class PftraceException extends RuntimeException {
  private final Status status;
  PftraceException(Status status, String operation) {
    super(operation + ": " + status);
    this.status = status;
  }
  public Status status() { return status; }
}
