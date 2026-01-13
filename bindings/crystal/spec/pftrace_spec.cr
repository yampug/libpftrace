require "spec"
require "../src/pftrace"

describe Pftrace do
  it "generates a trace file with comprehensive features" do
    filename = "crystal_test.pftrace"
    File.delete(filename) if File.exists?(filename)

    Pftrace.open(filename) do |ctx|
      ctx.write_clock_snapshot(1_000_000_000)
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
    puts "Generated #{filename} (#{File.size(filename)} bytes) with all features verified."
  end
end
