package io.github.libpftrace;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class TraceTest {
  @Test void writesTraceWithTheCrystalBindingFeatureSet() throws Exception {
    Path output = Files.createTempFile("pftrace-java-", ".pftrace");
    try (Trace trace = new Trace(output)) {
      trace.writeLinuxBoottimeClockSnapshot(1_000_000_000L);
      trace.writeProcessDescriptor(100, "JavaApp");
      trace.writeThreadDescriptor(100, 101, "main");
      trace.trace("work", EventType.SLICE_BEGIN, 101L, 1_000_000_100L,
          Pftrace.CLOCK_ID_LINUX_BOOTTIME, 42, event -> event
              .arg("lang", "java").arg("enabled", true).argUnsigned("all-bits", -1L)
              .argPointer("context", 0xDEADBEEFL).flowBegin(99).category("runtime")
              .taskExecution("TraceTest.java", "writesTraceWithTheCrystalBindingFeatureSet", 20));
      trace.finalizeTrace();
    }
    assertTrue(Files.size(output) > 0);
    Files.deleteIfExists(output);
  }

  @Test void preservesNativeStatus() throws Exception {
    Path output = Files.createTempFile("pftrace-java-small-", ".pftrace");
    WriterOptions options = WriterOptions.defaults();
    options.packetScratchCapacity = 64; options.outputBatchCapacity = 64; options.maximumPacketBytes = 64;
    try (Trace trace = new Trace(output, options)) {
      PftraceException failure = assertThrows(PftraceException.class,
          () -> trace.trace("x".repeat(128), ignored -> {}));
      assertEquals(Status.CAPACITY_EXCEEDED, failure.status());
    }
    Files.deleteIfExists(output);
  }
}
