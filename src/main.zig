const std = @import("std");
const proto = @import("proto.zig");
const schema = @import("schema.zig");

const allocator = std.heap.page_allocator;

/// This limit applies only to legacy NUL-terminated convenience APIs. Length
/// bearing APIs accept a supplied length and do not scan their input.
pub const max_c_string_scan: usize = 1024 * 1024;

pub const pftrace_status_t = enum(c_int) {
    ok = 0,
    invalid_argument = 1,
    invalid_state = 2,
    capacity_exceeded = 3,
    message_too_large = 4,
    io_error = 5,
    disabled = 6,
};

pub const pftrace_string_t = extern struct { data: ?[*]const u8, size: usize };

const BuilderPhase = enum { idle, packet, event };

/// Opaque, writer-owned builder slot. A pointer remains valid only until its
/// packet ends; retaining it through a later slot reuse is outside C contract.
pub const pftrace_packet_t = struct {
    writer: *pftrace_writer_t = undefined,
    bookmark: proto.Bookmark = undefined,
    generation: u64 = 0,
    active: bool = false,
    checkpoint: usize = 0,
    phase: BuilderPhase = .idle,
};

/// Opaque, writer-owned track-event slot. It can only belong to active packet.
pub const pftrace_track_event_t = struct {
    writer: *pftrace_writer_t = undefined,
    bookmark: proto.Bookmark = undefined,
    generation: u64 = 0,
    active: bool = false,
    packet_generation: u64 = 0,
    checkpoint: usize = 0,
    phase: BuilderPhase = .idle,
    argument_count: usize = 0,
    category_count: usize = 0,
    flow_count: usize = 0,
    terminating_flow_count: usize = 0,
    task_metadata_assigned: bool = false,
};

pub const pftrace_writer_t = struct {
    pb: proto.PbWriter,
    pb_storage: []u8,
    file_path: []u8,
    file: std.Io.File,
    io_threaded: std.Io.Threaded,
    terminal_status: pftrace_status_t = .ok,
    active_packet: pftrace_packet_t = undefined,
    active_event: pftrace_track_event_t = undefined,
    packet_generation: u64 = 0,
    event_generation: u64 = 0,

    pub fn init(path: []const u8) !*pftrace_writer_t {
        const ptr = try allocator.create(pftrace_writer_t);
        errdefer allocator.destroy(ptr);
        ptr.pb_storage = try allocator.alloc(u8, 1024 * 1024);
        errdefer allocator.free(ptr.pb_storage);
        ptr.pb = proto.PbWriter.init(ptr.pb_storage);
        ptr.terminal_status = .ok;
        ptr.active_packet.active = false;
        ptr.active_event.active = false;
        ptr.file_path = try allocator.dupe(u8, path);
        errdefer allocator.free(ptr.file_path);
        ptr.io_threaded = std.Io.Threaded.init(allocator, .{});
        ptr.file = try std.Io.Dir.createFile(.cwd(), ptr.io_threaded.io(), path, .{});
        return ptr;
    }

    pub fn deinit(self: *pftrace_writer_t) void {
        _ = self.flush();
        self.file.close(self.io_threaded.io());
        self.io_threaded.deinit();
        allocator.free(self.file_path);
        allocator.free(self.pb_storage);
        allocator.destroy(self);
    }

    pub fn flush(self: *pftrace_writer_t) pftrace_status_t {
        if (self.terminal_status != .ok) return self.terminal_status;
        if (self.pb.written().len == 0) return .ok;
        self.file.writeStreamingAll(self.io_threaded.io(), self.pb.written()) catch {
            self.terminal_status = .io_error;
            return .io_error;
        };
        self.pb.reset();
        return .ok;
    }
};

fn mapError(err: proto.Error) pftrace_status_t {
    return switch (err) {
        error.CapacityExceeded, error.InjectedFailure, error.IntegerOverflow => .capacity_exceeded,
        error.MessageTooLarge => .message_too_large,
        error.InvalidBookmark => .invalid_state,
    };
}

fn mutationStatus(writer: *pftrace_writer_t, result: proto.Error!void) pftrace_status_t {
    if (writer.terminal_status != .ok) return writer.terminal_status;
    result catch |err| return mapError(err);
    return .ok;
}

fn encodeProcess(writer: *pftrace_writer_t, uuid: u64, pid: i32, name: []const u8) proto.Error!void {
    const packet = try writer.pb.beginNested(1);
    const descriptor = try writer.pb.beginNested(schema.TracePacket.TRACK_DESCRIPTOR);
    try writer.pb.writeInt(schema.TrackDescriptor.UUID, uuid);
    const process = try writer.pb.beginNested(schema.TrackDescriptor.PROCESS);
    try writer.pb.writeInt(schema.ProcessDescriptor.PID, pid);
    try writer.pb.writeString(schema.ProcessDescriptor.PROCESS_NAME, name);
    try writer.pb.endNested(process);
    try writer.pb.endNested(descriptor);
    try writer.pb.endNested(packet);
}
fn encodeThread(writer: *pftrace_writer_t, uuid: u64, parent_uuid: u64, pid: i32, tid: i32, name: []const u8) proto.Error!void {
    const packet = try writer.pb.beginNested(1);
    const descriptor = try writer.pb.beginNested(schema.TracePacket.TRACK_DESCRIPTOR);
    try writer.pb.writeInt(schema.TrackDescriptor.UUID, uuid);
    try writer.pb.writeInt(schema.TrackDescriptor.PARENT_UUID, parent_uuid);
    const thread = try writer.pb.beginNested(schema.TrackDescriptor.THREAD);
    try writer.pb.writeInt(schema.ThreadDescriptor.PID, pid);
    try writer.pb.writeInt(schema.ThreadDescriptor.TID, tid);
    try writer.pb.writeString(schema.ThreadDescriptor.THREAD_NAME, name);
    try writer.pb.endNested(thread);
    try writer.pb.endNested(descriptor);
    try writer.pb.endNested(packet);
}
fn encodeClockSnapshot(writer: *pftrace_writer_t, boottime_ns: u64) proto.Error!void {
    const packet = try writer.pb.beginNested(1);
    const snapshot = try writer.pb.beginNested(schema.TracePacket.CLOCK_SNAPSHOT);
    const clock = try writer.pb.beginNested(schema.ClockSnapshot.CLOCKS);
    try writer.pb.writeInt(schema.Clock.CLOCK_ID, 6);
    try writer.pb.writeInt(schema.Clock.TIMESTAMP, boottime_ns);
    try writer.pb.endNested(clock);
    try writer.pb.endNested(snapshot);
    try writer.pb.endNested(packet);
}
const AnnotationValue = union(enum) { string: []const u8, int: i64, uint: u64, double: f64, boolean: bool };
fn encodeAnnotation(writer: *pftrace_writer_t, key: []const u8, field: u32, value: AnnotationValue) proto.Error!void {
    const bookmark = try writer.pb.beginNested(schema.TrackEvent.DEBUG_ANNOTATIONS);
    try writer.pb.writeString(schema.DebugAnnotation.NAME, key);
    switch (value) {
        .string => |v| try writer.pb.writeString(field, v),
        .int => |v| try writer.pb.writeSignedInt64(field, v),
        .uint => |v| try writer.pb.writeInt(field, v),
        .double => |v| {
            try writer.pb.writeTag(field, .Fixed64);
            try writer.pb.writeFixed64(@bitCast(v));
        },
        .boolean => |v| try writer.pb.writeInt(field, @as(u64, if (v) 1 else 0)),
    }
    try writer.pb.endNested(bookmark);
}
fn encodeTaskExecution(writer: *pftrace_writer_t, iid: u64) proto.Error!void {
    const bookmark = try writer.pb.beginNested(schema.TrackEvent.TASK_EXECUTION);
    try writer.pb.writeInt(schema.TaskExecution.POSTED_FROM_IID, iid);
    try writer.pb.endNested(bookmark);
}

fn stringSlice(value: pftrace_string_t) ?[]const u8 {
    if (value.size == 0) return "";
    const data = value.data orelse return null;
    return data[0..value.size];
}

fn cString(ptr: ?[*]const u8) ?[]const u8 {
    const data = ptr orelse return null;
    var len: usize = 0;
    while (len <= max_c_string_scan) : (len += 1) {
        if (data[len] == 0) return data[0..len];
    }
    return null;
}

fn stringArg(ptr: ?[*]const u8) ?pftrace_string_t {
    const value = cString(ptr) orelse return null;
    return .{ .data = value.ptr, .size = value.len };
}

fn packetValid(packet: ?*pftrace_packet_t) ?*pftrace_packet_t {
    const value = packet orelse return null;
    const writer = value.writer;
    if (!value.active or value.phase != .packet or !writer.active_packet.active or value != &writer.active_packet) return null;
    if (writer.terminal_status != .ok) return null;
    return value;
}
fn eventValid(event: ?*pftrace_track_event_t) ?*pftrace_track_event_t {
    const value = event orelse return null;
    const writer = value.writer;
    if (!value.active or value.phase != .event or !writer.active_event.active or value != &writer.active_event) return null;
    if (!writer.active_packet.active or writer.active_packet.generation != value.packet_generation) return null;
    if (writer.terminal_status != .ok) return null;
    return value;
}

export fn pftrace_status_string(status: c_int) [*:0]const u8 {
    return switch (status) {
        0 => "ok",
        1 => "invalid argument",
        2 => "invalid state",
        3 => "capacity exceeded",
        4 => "message too large",
        5 => "i/o error",
        6 => "disabled",
        else => "unknown status",
    };
}
export fn pftrace_writer_status(writer: ?*const pftrace_writer_t) pftrace_status_t {
    return if (writer) |w| w.terminal_status else .invalid_argument;
}

export fn pftrace_init_string(path_value: pftrace_string_t) ?*pftrace_writer_t {
    const path = stringSlice(path_value) orelse return null;
    if (path.len == 0) return null;
    return pftrace_writer_t.init(path) catch null;
}
export fn pftrace_init(path_ptr: ?[*]const u8) ?*pftrace_writer_t {
    return pftrace_init_string(stringArg(path_ptr) orelse return null);
}
export fn pftrace_destroy(writer: ?*pftrace_writer_t) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    if (w.active_packet.active or w.active_event.active) return .invalid_state;
    const status = w.terminal_status;
    w.deinit();
    return status;
}
export fn pftrace_flush(writer: ?*pftrace_writer_t) pftrace_status_t {
    return if (writer) |w| w.flush() else .invalid_argument;
}

export fn pftrace_packet_begin(writer: ?*pftrace_writer_t) ?*pftrace_packet_t {
    const w = writer orelse return null;
    if (w.terminal_status != .ok or w.active_packet.active) return null;
    const checkpoint = w.pb.checkpoint();
    const bookmark = w.pb.beginNested(1) catch return null;
    w.packet_generation +%= 1;
    if (w.packet_generation == 0) w.packet_generation = 1;
    w.active_packet = .{ .writer = w, .bookmark = bookmark, .generation = w.packet_generation, .active = true, .checkpoint = checkpoint, .phase = .packet };
    return &w.active_packet;
}
export fn pftrace_packet_end(writer: ?*pftrace_writer_t, packet: ?*pftrace_packet_t) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    const p = packetValid(packet) orelse return .invalid_state;
    if (p.writer != w) return .invalid_state;
    if (w.active_event.active) return .invalid_state;
    const status = mutationStatus(w, w.pb.endNested(p.bookmark));
    if (status != .ok) return status;
    p.active = false;
    p.phase = .idle;
    return w.flush();
}
/// Preferred packet completion API: ownership comes from packet slot itself.
export fn pftrace_packet_commit(packet: ?*pftrace_packet_t) pftrace_status_t {
    const p = packetValid(packet) orelse return .invalid_state;
    return pftrace_packet_end(p.writer, p);
}
export fn pftrace_packet_set_timestamp(packet: ?*pftrace_packet_t, value: u64) pftrace_status_t {
    const p = packetValid(packet) orelse return .invalid_state;
    return mutationStatus(p.writer, p.writer.pb.writeInt(schema.TracePacket.TIMESTAMP, value));
}
export fn pftrace_packet_set_trusted_packet_sequence_id(packet: ?*pftrace_packet_t, value: u32) pftrace_status_t {
    const p = packetValid(packet) orelse return .invalid_state;
    return mutationStatus(p.writer, p.writer.pb.writeInt(schema.TracePacket.TRUSTED_PACKET_SEQUENCE_ID, value));
}

fn descriptorProcess(writer: *pftrace_writer_t, uuid: u64, pid: i32, name: []const u8) pftrace_status_t {
    const checkpoint = writer.pb.checkpoint();
    const result = encodeProcess(writer, uuid, pid, name);
    const status = mutationStatus(writer, result);
    if (status != .ok) {
        writer.pb.rollback(checkpoint) catch {};
        return status;
    }
    return writer.flush();
}
export fn pftrace_write_process_track_descriptor_string(writer: ?*pftrace_writer_t, uuid: u64, pid: i32, name: pftrace_string_t) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    const value = stringSlice(name) orelse return .invalid_argument;
    return descriptorProcess(w, uuid, pid, value);
}
export fn pftrace_write_process_track_descriptor(writer: ?*pftrace_writer_t, uuid: u64, pid: i32, name: ?[*]const u8) pftrace_status_t {
    return pftrace_write_process_track_descriptor_string(writer, uuid, pid, stringArg(name) orelse return .invalid_argument);
}

fn descriptorThread(writer: *pftrace_writer_t, uuid: u64, parent_uuid: u64, pid: i32, tid: i32, name: []const u8) pftrace_status_t {
    const checkpoint = writer.pb.checkpoint();
    const result = encodeThread(writer, uuid, parent_uuid, pid, tid, name);
    const status = mutationStatus(writer, result);
    if (status != .ok) {
        writer.pb.rollback(checkpoint) catch {};
        return status;
    }
    return writer.flush();
}
export fn pftrace_write_thread_track_descriptor_string(writer: ?*pftrace_writer_t, uuid: u64, parent_uuid: u64, pid: i32, tid: i32, name: pftrace_string_t) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    const value = stringSlice(name) orelse return .invalid_argument;
    return descriptorThread(w, uuid, parent_uuid, pid, tid, value);
}
export fn pftrace_write_thread_track_descriptor(writer: ?*pftrace_writer_t, uuid: u64, parent_uuid: u64, pid: i32, tid: i32, name: ?[*]const u8) pftrace_status_t {
    return pftrace_write_thread_track_descriptor_string(writer, uuid, parent_uuid, pid, tid, stringArg(name) orelse return .invalid_argument);
}

export fn pftrace_write_clock_snapshot(writer: ?*pftrace_writer_t, boottime_ns: u64) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    const checkpoint = w.pb.checkpoint();
    const result = encodeClockSnapshot(w, boottime_ns);
    const status = mutationStatus(w, result);
    if (status != .ok) {
        w.pb.rollback(checkpoint) catch {};
        return status;
    }
    return w.flush();
}

export fn pftrace_packet_begin_track_event(packet: ?*pftrace_packet_t) ?*pftrace_track_event_t {
    const p = packetValid(packet) orelse return null;
    if (p.writer.active_event.active) return null;
    const checkpoint = p.writer.pb.checkpoint();
    const bookmark = p.writer.pb.beginNested(schema.TracePacket.TRACK_EVENT) catch return null;
    p.writer.event_generation +%= 1;
    if (p.writer.event_generation == 0) p.writer.event_generation = 1;
    p.writer.active_event = .{ .writer = p.writer, .bookmark = bookmark, .generation = p.writer.event_generation, .active = true, .packet_generation = p.generation, .checkpoint = checkpoint, .phase = .event };
    return &p.writer.active_event;
}
export fn pftrace_track_event_end(event: ?*pftrace_track_event_t) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    const status = mutationStatus(e.writer, e.writer.pb.endNested(e.bookmark));
    if (status != .ok) return status;
    e.active = false;
    e.phase = .idle;
    return .ok;
}

fn eventMutation(event: ?*pftrace_track_event_t, result: proto.Error!void) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    return mutationStatus(e.writer, result);
}
export fn pftrace_track_event_set_type(event: ?*pftrace_track_event_t, event_type: u32) pftrace_status_t {
    if (event_type > 4) return .invalid_argument;
    const e = eventValid(event) orelse return .invalid_state;
    return eventMutation(event, e.writer.pb.writeInt(schema.TrackEvent.TYPE, event_type));
}
export fn pftrace_track_event_set_track_uuid(event: ?*pftrace_track_event_t, uuid: u64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    return eventMutation(event, e.writer.pb.writeInt(schema.TrackEvent.TRACK_UUID, uuid));
}
export fn pftrace_track_event_set_counter_value(event: ?*pftrace_track_event_t, value: i64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    return eventMutation(event, e.writer.pb.writeSignedInt64(schema.TrackEvent.COUNTER_VALUE, value));
}
export fn pftrace_track_event_add_flow_id(event: ?*pftrace_track_event_t, flow_id: u64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    const status = eventMutation(event, e.writer.pb.writeInt(schema.TrackEvent.FLOW_IDS, flow_id));
    if (status == .ok) e.flow_count += 1;
    return status;
}
export fn pftrace_track_event_add_terminating_flow_id(event: ?*pftrace_track_event_t, flow_id: u64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    const status = eventMutation(event, e.writer.pb.writeInt(schema.TrackEvent.TERMINATING_FLOW_IDS, flow_id));
    if (status == .ok) e.terminating_flow_count += 1;
    return status;
}

fn writeEventString(event: ?*pftrace_track_event_t, field: u32, value: pftrace_string_t) pftrace_status_t {
    const text = stringSlice(value) orelse return .invalid_argument;
    const e = eventValid(event) orelse return .invalid_state;
    return eventMutation(event, e.writer.pb.writeString(field, text));
}
export fn pftrace_track_event_set_name_string(event: ?*pftrace_track_event_t, name: pftrace_string_t) pftrace_status_t {
    return writeEventString(event, schema.TrackEvent.NAME, name);
}
export fn pftrace_track_event_set_name(event: ?*pftrace_track_event_t, name: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_set_name_string(event, stringArg(name) orelse return .invalid_argument);
}
export fn pftrace_track_event_add_category_string(event: ?*pftrace_track_event_t, category: pftrace_string_t) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    const status = writeEventString(event, schema.TrackEvent.CATEGORIES, category);
    if (status == .ok) e.category_count += 1;
    return status;
}
export fn pftrace_track_event_add_category(event: ?*pftrace_track_event_t, category: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_add_category_string(event, stringArg(category) orelse return .invalid_argument);
}

fn annotation(event: ?*pftrace_track_event_t, key: pftrace_string_t, field: u32, value: union(enum) { string: pftrace_string_t, int: i64, uint: u64, double: f64, boolean: bool }) pftrace_status_t {
    const k = stringSlice(key) orelse return .invalid_argument;
    const e = eventValid(event) orelse return .invalid_state;
    const encoded: AnnotationValue = switch (value) {
        .string => |v| .{ .string = stringSlice(v) orelse return .invalid_argument },
        .int => |v| .{ .int = v },
        .uint => |v| .{ .uint = v },
        .double => |v| .{ .double = v },
        .boolean => |v| .{ .boolean = v },
    };
    const result = encodeAnnotation(e.writer, k, field, encoded);
    const status = eventMutation(event, result);
    if (status == .ok and field != schema.DebugAnnotation.STRING_VALUE) e.argument_count += 1;
    return status;
}
export fn pftrace_track_event_set_log_message_string(event: ?*pftrace_track_event_t, body: pftrace_string_t) pftrace_status_t {
    return annotation(event, .{ .data = "log_message".ptr, .size = 11 }, schema.DebugAnnotation.STRING_VALUE, .{ .string = body });
}
export fn pftrace_track_event_set_log_message(event: ?*pftrace_track_event_t, body: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_set_log_message_string(event, stringArg(body) orelse return .invalid_argument);
}
export fn pftrace_track_event_add_arg_string_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: pftrace_string_t) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.STRING_VALUE, .{ .string = value });
}
export fn pftrace_track_event_add_arg_string(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_add_arg_string_string(event, stringArg(key) orelse return .invalid_argument, stringArg(value) orelse return .invalid_argument);
}
export fn pftrace_track_event_add_arg_int_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: i64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.INT_VALUE, .{ .int = value });
}
export fn pftrace_track_event_add_arg_int(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: i64) pftrace_status_t {
    return pftrace_track_event_add_arg_int_string(event, stringArg(key) orelse return .invalid_argument, value);
}
export fn pftrace_track_event_add_arg_uint_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: u64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.UINT_VALUE, .{ .uint = value });
}
export fn pftrace_track_event_add_arg_uint(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: u64) pftrace_status_t {
    return pftrace_track_event_add_arg_uint_string(event, stringArg(key) orelse return .invalid_argument, value);
}
export fn pftrace_track_event_add_arg_double_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: f64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.DOUBLE_VALUE, .{ .double = value });
}
export fn pftrace_track_event_add_arg_double(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: f64) pftrace_status_t {
    return pftrace_track_event_add_arg_double_string(event, stringArg(key) orelse return .invalid_argument, value);
}
export fn pftrace_track_event_add_arg_bool_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: bool) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.BOOL_VALUE, .{ .boolean = value });
}
export fn pftrace_track_event_add_arg_bool(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: bool) pftrace_status_t {
    return pftrace_track_event_add_arg_bool_string(event, stringArg(key) orelse return .invalid_argument, value);
}
export fn pftrace_track_event_add_arg_ptr_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: u64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.POINTER_VALUE, .{ .uint = value });
}
export fn pftrace_track_event_add_arg_ptr(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: u64) pftrace_status_t {
    return pftrace_track_event_add_arg_ptr_string(event, stringArg(key) orelse return .invalid_argument, value);
}

export fn pftrace_track_event_set_task_execution_string(event: ?*pftrace_track_event_t, file: pftrace_string_t, func: pftrace_string_t, line: u32) pftrace_status_t {
    const f = stringSlice(file) orelse return .invalid_argument;
    const fn_name = stringSlice(func) orelse return .invalid_argument;
    const e = eventValid(event) orelse return .invalid_state;
    if (e.task_metadata_assigned) return .invalid_state;
    var iid: u64 = 5381;
    for (f) |c| iid = ((iid << 5) +% iid) +% c;
    for (fn_name) |c| iid = ((iid << 5) +% iid) +% c;
    iid = ((iid << 5) +% iid) +% line;
    if (iid == 0) iid = 1;
    const result = encodeTaskExecution(e.writer, iid);
    const status = eventMutation(event, result);
    if (status != .ok) return status;
    e.task_metadata_assigned = true;
    return status;
}
export fn pftrace_track_event_set_task_execution(event: ?*pftrace_track_event_t, file: ?[*]const u8, func: ?[*]const u8, line: u32) pftrace_status_t {
    return pftrace_track_event_set_task_execution_string(event, stringArg(file) orelse return .invalid_argument, stringArg(func) orelse return .invalid_argument, line);
}
