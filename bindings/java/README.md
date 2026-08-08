# libpftrace Java bindings

The Java 17+ binding provides the same safe writer and scoped-event surface as
the Crystal binding. It uses [JNA](https://github.com/java-native-access/jna)
to call libpftrace's C ABI, so no JNI code is required.

## Build and test locally

From the repository root, build the native library (this produces both static
and shared artifacts), then point Java at the shared artifact:

```bash
zig build
mvn -f bindings/java/pom.xml test \
  -Dpftrace.library="$PWD/zig-out/lib/libpftrace.dylib"
```

On Linux use `libpftrace.so`; on Windows use `pftrace.dll`. A packaged
application can instead put that shared library on its normal native-library
path and omit `pftrace.library`.

## Usage

```java
import io.github.libpftrace.*;

try (Trace trace = new Trace("trace.pftrace")) {
  trace.writeProcessDescriptor(100, "MyProcess");
  trace.writeThreadDescriptor(100, 101, "worker");
  trace.trace("work", EventType.SLICE_BEGIN, 101L, 1_000_000_100L,
      Pftrace.CLOCK_ID_LINUX_BOOTTIME, 42, event -> event
          .arg("language", "java")
          .arg("cached", true)
          .argUnsigned("requestId", -1L)
          .argPointer("context", 0xDEADBEEFL)
          .flowBegin(99)
          .taskExecution("Worker.java", "run", 42));
  trace.finalizeTrace();
}
```

Every native status is converted into `PftraceException`, whose `status()` is
the original `Status`. `Trace` is single-writer; do not use it concurrently.
`Event` instances are valid only inside their `trace` callback. `close()`
finalizes and frees the writer; it is idempotent.

`WriterOptions.defaults()` initializes the native versioned options structure.
Change its fields before passing it to `Trace`. `flushEachPacket` is a C bool,
so set it to `(byte) 1` to enable it. Java `long` represents both signed
int64 and unsigned uint64 bit patterns; use `argUnsigned` or `argPointer` for
the latter two C argument types.

For the lower-level builder and direct-event functions, `PftraceNative` is
public and mirrors the C ABI, including fd/callback initialization. Its methods
return the original integer C status; normal applications should prefer `Trace`.
Direct structures borrow their `Pointer`-backed arrays only for the native call,
exactly as documented by the C API.
