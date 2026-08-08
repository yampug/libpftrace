package io.github.libpftrace;

import com.sun.jna.Structure;

/** Version-1 writer limits. Start with {@link #defaults()} before changing fields. */
@Structure.FieldOrder({"structSize", "version", "packetScratchCapacity", "outputBatchCapacity",
    "maximumPacketBytes", "maximumTraceBytes", "maximumStringBytes", "maximumArguments",
    "maximumCategories", "maximumFlowIds", "maximumTerminatingFlowIds", "maximumNestingDepth",
    "flushEachPacket"})
public class WriterOptions extends Structure {
  public int structSize;
  public int version;
  public long packetScratchCapacity;
  public long outputBatchCapacity;
  public long maximumPacketBytes;
  public long maximumTraceBytes;
  public long maximumStringBytes;
  public long maximumArguments;
  public long maximumCategories;
  public long maximumFlowIds;
  public long maximumTerminatingFlowIds;
  public int maximumNestingDepth;
  /** C bool: use 0 or 1, rather than Java boolean's platform-dependent JNA mapping. */
  public byte flushEachPacket;

  public static WriterOptions defaults() {
    WriterOptions options = new WriterOptions();
    Pftrace.check(PftraceNative.instance().pftrace_writer_options_init(options), "options init");
    options.read();
    return options;
  }
}
