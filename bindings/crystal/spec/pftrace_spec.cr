require "spec"
require "../src/pftrace"

describe Pftrace do
  it "generates a trace file with comprehensive features" do
    filename = "crystal_test.pftrace"
    File.delete(filename) if File.exists?(filename)

    Pftrace.open(filename) do |ctx|
      ctx.write_linux_boottime_clock_snapshot(1_000_000_000)
      ctx.write_process_descriptor(100, "CrystalApp")
      ctx.write_thread_descriptor(100, 101, "MainFiber")

      # Test sequence ID
      ctx.trace("Work", track_uuid: 101, timestamp: 1_000_000_100, trusted_packet_sequence_id: 42) do |ev|
        ev.arg("lang", "crystal")
        ev.arg("awesome", true)
        
        # Test UInt64 arg
        ev.arg("big_uint", 18446744073709551615_u64)
        
        # Test Pointer arg
        ev.arg_ptr("ctx_ptr", 0xDEADBEEF)
        
        ev.task_execution(__FILE__, "block_spec", __LINE__)
      end
    end

    File.exists?(filename).should be_true
    File.size(filename).should be > 0
  end

  it "preserves status in invalid-input and capacity errors" do
    expect_raises(Pftrace::Error) { Pftrace::Trace.new("") }.status.should eq(LibPftrace::Status::InvalidArgument)

    options = Pftrace::Trace.default_options
    options.packet_scratch_capacity = 64
    options.output_batch_capacity = 64
    options.maximum_packet_bytes = 64
    trace = Pftrace::Trace.new("crystal_capacity.pftrace", options)
    begin
      error = expect_raises(Pftrace::Error) do
        trace.trace("x" * 128) { |_| }
      end
      error.status.should eq(LibPftrace::Status::CapacityExceeded)
    ensure
      trace.close
    end
  end

  it "reports idempotent finalize and rejects mutation after finalization" do
    trace = Pftrace::Trace.new("crystal_finalize.pftrace")
    begin
      trace.finalize
      trace.finalize
      error = expect_raises(Pftrace::Error) { trace.write_process_descriptor(1, "after-finalize") }
      error.status.should eq(LibPftrace::Status::InvalidState)
    ensure
      trace.close
    end
  end

  it "returns sticky io status from failing callback sink" do
    options = Pftrace::Trace.default_options
    options.flush_each_packet = true
    writer = Pointer(Void).null.as(LibPftrace::Writer)
    failing_sink = ->(context : Void*, bytes : UInt8*, size : LibC::SizeT) { LibPftrace::Status::IoError }
    LibPftrace.init_callback_with_options(failing_sink, Pointer(Void).null, pointerof(options), pointerof(writer)).should eq(LibPftrace::Status::Ok)
    begin
      LibPftrace.write_process_track_descriptor(writer, 1, 1, "callback").should eq(LibPftrace::Status::IoError)
      LibPftrace.writer_status(writer).should eq(LibPftrace::Status::IoError)
      LibPftrace.flush(writer).should eq(LibPftrace::Status::IoError)
    ensure
      LibPftrace.destroy(writer).should eq(LibPftrace::Status::IoError)
    end
  end
end
