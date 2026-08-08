const std = @import("std");
const pf = @import("pftrace");

const C = struct {
    extern fn pftrace_writer_options_init(*pf.pftrace_writer_options_t) pf.pftrace_status_t;
    extern fn pftrace_init_callback_with_options(
        pf.pftrace_write_fn,
        ?*anyopaque,
        ?*const pf.pftrace_writer_options_t,
        *?*pf.pftrace_writer_t,
    ) pf.pftrace_status_t;
    extern fn pftrace_write_linux_boottime_clock_snapshot(*pf.pftrace_writer_t, u64) pf.pftrace_status_t;
    extern fn pftrace_flush(*pf.pftrace_writer_t) pf.pftrace_status_t;
    extern fn pftrace_finalize(*pf.pftrace_writer_t) pf.pftrace_status_t;
    extern fn pftrace_destroy(*pf.pftrace_writer_t) pf.pftrace_status_t;
};

var calls: usize = 0;
var fail_on_call: usize = 0;
var acknowledged_bytes: usize = 0;

fn callback(_: ?*anyopaque, bytes: ?[*]const u8, size: usize) callconv(.c) c_int {
    calls += 1;
    if (fail_on_call != 0 and calls == fail_on_call) return @intFromEnum(pf.pftrace_status_t.invalid_argument);
    if (bytes == null or size == 0) return @intFromEnum(pf.pftrace_status_t.invalid_argument);
    acknowledged_bytes += size;
    return 0;
}

fn initWriter(flush_each_packet: bool) !*pf.pftrace_writer_t {
    var options: pf.pftrace_writer_options_t = undefined;
    try std.testing.expectEqual(pf.pftrace_status_t.ok, C.pftrace_writer_options_init(&options));
    options.flush_each_packet = flush_each_packet;
    var writer: ?*pf.pftrace_writer_t = null;
    try std.testing.expectEqual(pf.pftrace_status_t.ok, C.pftrace_init_callback_with_options(callback, null, &options, &writer));
    return writer orelse error.TestUnexpectedResult;
}

test "callback failures preserve acknowledged prefix and become sticky" {
    calls = 0;
    fail_on_call = 2;
    acknowledged_bytes = 0;
    const writer = try initWriter(true);
    try std.testing.expectEqual(pf.pftrace_status_t.ok, C.pftrace_write_linux_boottime_clock_snapshot(writer, 1));
    const prefix = acknowledged_bytes;
    try std.testing.expect(prefix > 0);
    try std.testing.expectEqual(pf.pftrace_status_t.io_error, C.pftrace_write_linux_boottime_clock_snapshot(writer, 2));
    try std.testing.expectEqual(@as(usize, 2), calls);
    try std.testing.expectEqual(prefix, acknowledged_bytes);
    try std.testing.expectEqual(pf.pftrace_status_t.io_error, C.pftrace_flush(writer));
    try std.testing.expectEqual(@as(usize, 2), calls);
    try std.testing.expectEqual(pf.pftrace_status_t.io_error, C.pftrace_destroy(writer));
}

test "explicit and final flush failures are sticky" {
    inline for ([_]bool{ false, true }) |final_flush| {
        calls = 0;
        fail_on_call = 1;
        acknowledged_bytes = 0;
        const writer = try initWriter(false);
        try std.testing.expectEqual(pf.pftrace_status_t.ok, C.pftrace_write_linux_boottime_clock_snapshot(writer, 1));
        const status = if (final_flush) C.pftrace_finalize(writer) else C.pftrace_flush(writer);
        try std.testing.expectEqual(pf.pftrace_status_t.io_error, status);
        try std.testing.expectEqual(@as(usize, 1), calls);
        try std.testing.expectEqual(@as(usize, 0), acknowledged_bytes);
        try std.testing.expectEqual(pf.pftrace_status_t.io_error, C.pftrace_write_linux_boottime_clock_snapshot(writer, 2));
        try std.testing.expectEqual(@as(usize, 1), calls);
        try std.testing.expectEqual(pf.pftrace_status_t.io_error, C.pftrace_destroy(writer));
    }
}
