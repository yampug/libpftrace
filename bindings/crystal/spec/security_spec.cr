require "spec"
require "../src/pftrace"

describe Pftrace do
  it "RAISES on Use-After-Free (Event escape)" do
    filename = "security_test.pftrace"
    escaped_ev : Pftrace::Event? = nil

    Pftrace.open(filename) do |ctx|
      ctx.trace("Escapee") do |ev|
        escaped_ev = ev
        ev.arg("inside", "safe")
      end
    end

    # At this point, the stack event is closed/destroyed in C.
    # AND the Crystal wrapper has been invalidated.
    # Accessing it should raise a Crystal Exception.
    
    if ev = escaped_ev
      puts "\n[TEST] Attempting UAF from Crystal..."
      expect_raises(Exception, "Use-After-Free detected") do
        ev.arg("outside", "dangerous") 
      end
      puts "[TEST] Successfully caught UAF!"
    end
    
    File.exists?(filename).should be_true
  end
end
