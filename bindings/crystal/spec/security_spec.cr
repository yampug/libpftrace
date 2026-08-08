require "spec"
require "../src/pftrace"

describe Pftrace do
  it "raises typed invalid-state error for invalidated event handle" do
    filename = "security_test.pftrace"
    escaped_ev : Pftrace::Event? = nil

    Pftrace.open(filename) do |ctx|
      ctx.trace("Escapee") do |ev|
        escaped_ev = ev
        ev.arg("inside", "safe")
      end
    end

    if ev = escaped_ev
      error = expect_raises(Pftrace::Error) do
        ev.arg("outside", "dangerous") 
      end
      error.status.should eq(LibPftrace::Status::InvalidState)
    end
    
    File.exists?(filename).should be_true
  end
end
