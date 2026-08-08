const std = @import("std");
const proto = @import("proto.zig");
const schema = @import("schema.zig");
const sink = @import("sink.zig");

const allocator = std.heap.page_allocator;
const default_packet_capacity = 1024 * 1024;
const default_collection_limit = 1024;

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
pub const pftrace_write_fn = *const fn (?*anyopaque, ?[*]const u8, usize) callconv(.c) c_int;
pub const pftrace_track_event_type_t = enum(c_int) {
    unspecified = 0,
    slice_begin = 1,
    slice_end = 2,
    instant = 3,
    counter = 4,
    _,
};

pub const pftrace_arg_type_t = enum(c_int) {
    string = 0,
    int64 = 1,
    uint64 = 2,
    double = 3,
    bool = 4,
    pointer = 5,
    _,
};
pub const pftrace_arg_value_t = extern union {
    string_value: pftrace_string_t,
    int64_value: i64,
    uint64_value: u64,
    double_value: f64,
    bool_value: bool,
    pointer_value: u64,
};
pub const pftrace_arg_t = extern struct {
    key: pftrace_string_t,
    type: pftrace_arg_type_t,
    value: pftrace_arg_value_t,
};
pub const pftrace_event_t = extern struct {
    timestamp_ns: u64,
    timestamp_clock_id: u32,
    trusted_packet_sequence_id: u32,
    track_uuid: u64,
    type: pftrace_track_event_type_t,
    name: pftrace_string_t,
    counter_value: i64,
    flow_ids: ?[*]const u64,
    flow_id_count: usize,
    terminating_flow_ids: ?[*]const u64,
    terminating_flow_id_count: usize,
    categories: ?[*]const pftrace_string_t,
    category_count: usize,
    arguments: ?[*]const pftrace_arg_t,
    argument_count: usize,
};

pub const pftrace_writer_options_t = extern struct {
    struct_size: u32,
    version: u32,
    packet_scratch_capacity: usize,
    output_batch_capacity: usize,
    maximum_packet_bytes: usize,
    maximum_trace_bytes: usize,
    maximum_string_bytes: usize,
    maximum_arguments: usize,
    maximum_categories: usize,
    maximum_flow_ids: usize,
    maximum_terminating_flow_ids: usize,
    maximum_nesting_depth: u32,
    flush_each_packet: bool,
};

const WriterOptions = struct {
    packet_scratch_capacity: usize = default_packet_capacity,
    output_batch_capacity: usize = default_packet_capacity,
    maximum_packet_bytes: usize = default_packet_capacity,
    maximum_trace_bytes: usize = 0,
    maximum_string_bytes: usize = max_c_string_scan,
    maximum_arguments: usize = default_collection_limit,
    maximum_categories: usize = default_collection_limit,
    maximum_flow_ids: usize = default_collection_limit,
    maximum_terminating_flow_ids: usize = default_collection_limit,
    maximum_nesting_depth: usize = proto.max_nested_depth,
    flush_each_packet: bool = false,
};

const writer_options_version: u32 = 1;

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
    first_error: pftrace_status_t = .ok,
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
    packet_pb: proto.PbWriter,
    packet_storage: []u8,
    sink: sink.Sink,
    io_threaded: std.Io.Threaded,
    options: WriterOptions,
    terminal_status: pftrace_status_t = .ok,
    finalized: bool = false,
    accepted_trace_bytes: u64 = 0,
    active_packet: pftrace_packet_t = undefined,
    active_event: pftrace_track_event_t = undefined,
    packet_generation: u64 = 0,
    event_generation: u64 = 0,
    next_source_iid: u64 = 1,

    fn initBase(options: WriterOptions) !*pftrace_writer_t {
        const ptr = try allocator.create(pftrace_writer_t);
        errdefer allocator.destroy(ptr);
        ptr.pb_storage = try allocator.alloc(u8, options.output_batch_capacity);
        errdefer allocator.free(ptr.pb_storage);
        ptr.pb = proto.PbWriter.initWithLimits(ptr.pb_storage, @intCast(options.maximum_packet_bytes), options.maximum_nesting_depth);
        ptr.packet_storage = try allocator.alloc(u8, options.packet_scratch_capacity);
        errdefer allocator.free(ptr.packet_storage);
        ptr.packet_pb = proto.PbWriter.initWithLimits(ptr.packet_storage, @intCast(options.maximum_packet_bytes), options.maximum_nesting_depth);
        ptr.options = options;
        ptr.terminal_status = .ok;
        ptr.active_packet.active = false;
        ptr.active_event.active = false;
        ptr.io_threaded = std.Io.Threaded.init(allocator, .{});
        return ptr;
    }

    pub fn initPath(path: []const u8, options: WriterOptions) !*pftrace_writer_t {
        const ptr = try initBase(options);
        errdefer ptr.deinitWithoutSink();
        ptr.sink = .{ .owned_file = try std.Io.Dir.createFile(.cwd(), ptr.io_threaded.io(), path, .{}) };
        return ptr;
    }

    pub fn initWithSink(value: sink.Sink, options: WriterOptions) !*pftrace_writer_t {
        const ptr = try initBase(options);
        ptr.sink = value;
        return ptr;
    }

    fn deinitWithoutSink(self: *pftrace_writer_t) void {
        self.io_threaded.deinit();
        allocator.free(self.pb_storage);
        allocator.free(self.packet_storage);
        allocator.destroy(self);
    }

    pub fn deinit(self: *pftrace_writer_t) pftrace_status_t {
        const status = self.finalize();
        self.sink.deinit(self.io_threaded.io());
        self.deinitWithoutSink();
        return status;
    }

    fn flushBuffered(self: *pftrace_writer_t) pftrace_status_t {
        if (self.terminal_status != .ok) return self.terminal_status;
        if (self.pb.written().len == 0) return .ok;
        self.sink.writeAll(self.io_threaded.io(), self.pb.written()) catch {
            self.terminal_status = .io_error;
            return .io_error;
        };
        self.pb.reset();
        return .ok;
    }

    pub fn flush(self: *pftrace_writer_t) pftrace_status_t {
        if (self.terminal_status != .ok) return self.terminal_status;
        if (self.finalized) return .invalid_state;
        return self.flushBuffered();
    }

    pub fn finalize(self: *pftrace_writer_t) pftrace_status_t {
        if (self.terminal_status != .ok) return self.terminal_status;
        if (self.finalized) return .ok;
        const status = self.flushBuffered();
        self.finalized = true;
        return status;
    }

    /// Adds one complete Trace.packet field to output batch. Never exposes a
    /// packet prefix to sink and never flushes for a rejected trace-cap packet.
    pub fn commitPacket(self: *pftrace_writer_t, packet: []const u8) pftrace_status_t {
        if (self.terminal_status != .ok) return self.terminal_status;
        if (self.finalized) return .invalid_state;
        const packet_len: u64 = @intCast(packet.len);
        const next_trace_bytes = std.math.add(u64, self.accepted_trace_bytes, packet_len) catch return .capacity_exceeded;
        if (self.options.maximum_trace_bytes != 0 and next_trace_bytes > @as(u64, @intCast(self.options.maximum_trace_bytes))) return .capacity_exceeded;

        if (packet.len > self.pb.remaining()) {
            const status = self.flushBuffered();
            if (status != .ok) return status;
        }
        // Options require maximum_packet_bytes <= output_batch_capacity, so a
        // complete validated packet always fits after at most one flush.
        const status = mutationStatus(self, self.pb.appendEncoded(packet));
        if (status != .ok) return status;
        self.accepted_trace_bytes = next_trace_bytes;
        if (self.options.flush_each_packet or self.pb.remaining() == 0) return self.flushBuffered();
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

fn defaultOptions() WriterOptions {
    return .{};
}

fn optionPresent(struct_size: u32, comptime field: []const u8) bool {
    return struct_size >= @offsetOf(pftrace_writer_options_t, field) + @sizeOf(@FieldType(pftrace_writer_options_t, field));
}

fn optionsFromC(value: ?*const pftrace_writer_options_t) error{InvalidArgument}!WriterOptions {
    const source = value orelse return defaultOptions();
    if (!optionPresent(source.struct_size, "version") or source.version != writer_options_version) return error.InvalidArgument;
    var options = defaultOptions();
    if (optionPresent(source.struct_size, "packet_scratch_capacity")) options.packet_scratch_capacity = source.packet_scratch_capacity;
    if (optionPresent(source.struct_size, "output_batch_capacity")) options.output_batch_capacity = source.output_batch_capacity;
    if (optionPresent(source.struct_size, "maximum_packet_bytes")) options.maximum_packet_bytes = source.maximum_packet_bytes;
    if (optionPresent(source.struct_size, "maximum_trace_bytes")) options.maximum_trace_bytes = source.maximum_trace_bytes;
    if (optionPresent(source.struct_size, "maximum_string_bytes")) options.maximum_string_bytes = source.maximum_string_bytes;
    if (optionPresent(source.struct_size, "maximum_arguments")) options.maximum_arguments = source.maximum_arguments;
    if (optionPresent(source.struct_size, "maximum_categories")) options.maximum_categories = source.maximum_categories;
    if (optionPresent(source.struct_size, "maximum_flow_ids")) options.maximum_flow_ids = source.maximum_flow_ids;
    if (optionPresent(source.struct_size, "maximum_terminating_flow_ids")) options.maximum_terminating_flow_ids = source.maximum_terminating_flow_ids;
    if (optionPresent(source.struct_size, "maximum_nesting_depth")) options.maximum_nesting_depth = source.maximum_nesting_depth;
    if (optionPresent(source.struct_size, "flush_each_packet")) options.flush_each_packet = source.flush_each_packet;

    if (options.packet_scratch_capacity == 0 or options.output_batch_capacity == 0 or options.maximum_packet_bytes == 0 or options.maximum_packet_bytes > options.packet_scratch_capacity or options.maximum_packet_bytes > options.output_batch_capacity or options.maximum_packet_bytes > std.math.maxInt(u32) or options.maximum_nesting_depth == 0 or options.maximum_nesting_depth > proto.max_nested_depth) return error.InvalidArgument;
    _ = std.math.add(usize, @sizeOf(pftrace_writer_t), options.packet_scratch_capacity) catch return error.InvalidArgument;
    _ = std.math.add(usize, @sizeOf(pftrace_writer_t), options.output_batch_capacity) catch return error.InvalidArgument;
    _ = std.math.add(usize, options.packet_scratch_capacity, options.output_batch_capacity) catch return error.InvalidArgument;
    return options;
}

fn mutationStatus(writer: *pftrace_writer_t, result: proto.Error!void) pftrace_status_t {
    if (writer.terminal_status != .ok) return writer.terminal_status;
    if (writer.finalized) return .invalid_state;
    result catch |err| return mapError(err);
    return .ok;
}

fn latchPacketError(packet: *pftrace_packet_t, status: pftrace_status_t) pftrace_status_t {
    if (packet.first_error == .ok and status != .ok) packet.first_error = status;
    return packet.first_error;
}

fn packetMutation(packet: *pftrace_packet_t, result: proto.Error!void) pftrace_status_t {
    if (packet.first_error != .ok) return packet.first_error;
    return latchPacketError(packet, mutationStatus(packet.writer, result));
}

fn encodeProcess(pb: *proto.PbWriter, uuid: u64, pid: i32, name: []const u8) proto.Error!void {
    const packet = try pb.beginNested(1);
    const descriptor = try pb.beginNested(schema.TracePacket.TRACK_DESCRIPTOR);
    try pb.writeInt(schema.TrackDescriptor.UUID, uuid);
    const process = try pb.beginNested(schema.TrackDescriptor.PROCESS);
    try pb.writeInt(schema.ProcessDescriptor.PID, pid);
    try pb.writeString(schema.ProcessDescriptor.PROCESS_NAME, name);
    try pb.endNested(process);
    try pb.endNested(descriptor);
    try pb.endNested(packet);
}
fn encodeThread(pb: *proto.PbWriter, uuid: u64, parent_uuid: u64, pid: i32, tid: i32, name: []const u8) proto.Error!void {
    const packet = try pb.beginNested(1);
    const descriptor = try pb.beginNested(schema.TracePacket.TRACK_DESCRIPTOR);
    try pb.writeInt(schema.TrackDescriptor.UUID, uuid);
    try pb.writeInt(schema.TrackDescriptor.PARENT_UUID, parent_uuid);
    const thread = try pb.beginNested(schema.TrackDescriptor.THREAD);
    try pb.writeInt(schema.ThreadDescriptor.PID, pid);
    try pb.writeInt(schema.ThreadDescriptor.TID, tid);
    try pb.writeString(schema.ThreadDescriptor.THREAD_NAME, name);
    try pb.endNested(thread);
    try pb.endNested(descriptor);
    try pb.endNested(packet);
}
fn encodeClockSnapshot(pb: *proto.PbWriter, boottime_ns: u64) proto.Error!void {
    const packet = try pb.beginNested(1);
    const snapshot = try pb.beginNested(schema.TracePacket.CLOCK_SNAPSHOT);
    const clock = try pb.beginNested(schema.ClockSnapshot.CLOCKS);
    try pb.writeInt(schema.Clock.CLOCK_ID, 6);
    try pb.writeInt(schema.Clock.TIMESTAMP, boottime_ns);
    try pb.endNested(clock);
    try pb.endNested(snapshot);
    try pb.endNested(packet);
}
const AnnotationValue = union(enum) { string: []const u8, int: i64, uint: u64, double: f64, boolean: bool };
fn encodeAnnotation(pb: *proto.PbWriter, key: []const u8, field: u32, value: AnnotationValue) proto.Error!void {
    const bookmark = try pb.beginNested(schema.TrackEvent.DEBUG_ANNOTATIONS);
    try pb.writeString(schema.DebugAnnotation.NAME, key);
    switch (value) {
        .string => |v| try pb.writeString(field, v),
        .int => |v| try pb.writeSignedInt64(field, v),
        .uint => |v| try pb.writeInt(field, v),
        .double => |v| {
            try pb.writeTag(field, .Fixed64);
            try pb.writeFixed64(@bitCast(v));
        },
        .boolean => |v| try pb.writeInt(field, @as(u64, if (v) 1 else 0)),
    }
    try pb.endNested(bookmark);
}
fn encodeTaskExecution(pb: *proto.PbWriter, iid: u64) proto.Error!void {
    const bookmark = try pb.beginNested(schema.TrackEvent.TASK_EXECUTION);
    try pb.writeInt(schema.TaskExecution.POSTED_FROM_IID, iid);
    try pb.endNested(bookmark);
}
fn encodeSourceLocation(pb: *proto.PbWriter, iid: u64, file: []const u8, func: []const u8, line: u32) proto.Error!void {
    const interned = try pb.beginNested(schema.TracePacket.INTERNED_DATA);
    const source = try pb.beginNested(schema.InternedData.SOURCE_LOCATIONS);
    try pb.writeInt(schema.SourceLocation.IID, iid);
    try pb.writeString(schema.SourceLocation.FILE_NAME, file);
    try pb.writeString(schema.SourceLocation.FUNCTION_NAME, func);
    try pb.writeInt(schema.SourceLocation.LINE_NUMBER, line);
    try pb.endNested(source);
    try pb.endNested(interned);
}
fn encodeTaskMetadata(pb: *proto.PbWriter, iid: u64, file: []const u8, func: []const u8, line: u32) proto.Error!void {
    try encodeSourceLocation(pb, iid, file, func, line);
    try encodeTaskExecution(pb, iid);
}

fn stringSlice(value: pftrace_string_t) ?[]const u8 {
    if (value.size == 0) return "";
    const data = value.data orelse return null;
    return data[0..value.size];
}

fn countedSpanValid(comptime T: type, data: ?[*]const T, count: usize) bool {
    return count == 0 or data != null;
}

/// Validates all direct input before its future encoder starts a packet
/// transaction. Kept separate from encoding so E5.S2 cannot accidentally
/// expose a scratch prefix while discovering bad caller input.
fn validateDirectEvent(writer: *const pftrace_writer_t, event: ?*const pftrace_event_t) pftrace_status_t {
    const value = event orelse return .invalid_argument;
    if (@intFromEnum(value.type) > @intFromEnum(pftrace_track_event_type_t.counter)) return .invalid_argument;
    const name = stringSlice(value.name) orelse return .invalid_argument;
    if (name.len > writer.options.maximum_string_bytes) return .capacity_exceeded;
    if (!countedSpanValid(u64, value.flow_ids, value.flow_id_count) or
        !countedSpanValid(u64, value.terminating_flow_ids, value.terminating_flow_id_count) or
        !countedSpanValid(pftrace_string_t, value.categories, value.category_count) or
        !countedSpanValid(pftrace_arg_t, value.arguments, value.argument_count)) return .invalid_argument;
    if (value.flow_id_count > writer.options.maximum_flow_ids or
        value.terminating_flow_id_count > writer.options.maximum_terminating_flow_ids or
        value.category_count > writer.options.maximum_categories or
        value.argument_count > writer.options.maximum_arguments) return .capacity_exceeded;

    if (value.categories) |categories| {
        for (categories[0..value.category_count]) |category| {
            const text = stringSlice(category) orelse return .invalid_argument;
            if (text.len > writer.options.maximum_string_bytes) return .capacity_exceeded;
        }
    }
    if (value.arguments) |arguments| {
        for (arguments[0..value.argument_count]) |argument| {
            const key = stringSlice(argument.key) orelse return .invalid_argument;
            if (key.len > writer.options.maximum_string_bytes) return .capacity_exceeded;
            switch (argument.type) {
                .string => {
                    const text = stringSlice(argument.value.string_value) orelse return .invalid_argument;
                    if (text.len > writer.options.maximum_string_bytes) return .capacity_exceeded;
                },
                .int64, .uint64, .double, .bool, .pointer => {},
                else => return .invalid_argument,
            }
        }
    }
    return .ok;
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

export fn pftrace_writer_options_init(options: ?*pftrace_writer_options_t) pftrace_status_t {
    const value = options orelse return .invalid_argument;
    value.* = .{
        .struct_size = @sizeOf(pftrace_writer_options_t),
        .version = writer_options_version,
        .packet_scratch_capacity = default_packet_capacity,
        .output_batch_capacity = default_packet_capacity,
        .maximum_packet_bytes = default_packet_capacity,
        .maximum_trace_bytes = 0,
        .maximum_string_bytes = max_c_string_scan,
        .maximum_arguments = default_collection_limit,
        .maximum_categories = default_collection_limit,
        .maximum_flow_ids = default_collection_limit,
        .maximum_terminating_flow_ids = default_collection_limit,
        .maximum_nesting_depth = proto.max_nested_depth,
        .flush_each_packet = false,
    };
    return .ok;
}

export fn pftrace_init_path_string_with_options(path_value: pftrace_string_t, option_value: ?*const pftrace_writer_options_t, out_writer: ?*?*pftrace_writer_t) pftrace_status_t {
    const output = out_writer orelse return .invalid_argument;
    output.* = null;
    const path = stringSlice(path_value) orelse return .invalid_argument;
    if (path.len == 0) return .invalid_argument;
    const options = optionsFromC(option_value) catch return .invalid_argument;
    output.* = pftrace_writer_t.initPath(path, options) catch return .io_error;
    return .ok;
}
export fn pftrace_init_path_with_options(path_ptr: ?[*]const u8, option_value: ?*const pftrace_writer_options_t, out_writer: ?*?*pftrace_writer_t) pftrace_status_t {
    return pftrace_init_path_string_with_options(stringArg(path_ptr) orelse return .invalid_argument, option_value, out_writer);
}
/// Legacy path constructor retained for source compatibility.
export fn pftrace_init_string_with_options(path_value: pftrace_string_t, option_value: ?*const pftrace_writer_options_t, out_writer: ?*?*pftrace_writer_t) pftrace_status_t {
    return pftrace_init_path_string_with_options(path_value, option_value, out_writer);
}
export fn pftrace_init_with_options(path_ptr: ?[*]const u8, option_value: ?*const pftrace_writer_options_t, out_writer: ?*?*pftrace_writer_t) pftrace_status_t {
    return pftrace_init_path_with_options(path_ptr, option_value, out_writer);
}
export fn pftrace_init_fd_with_options(fd: c_int, option_value: ?*const pftrace_writer_options_t, out_writer: ?*?*pftrace_writer_t) pftrace_status_t {
    const output = out_writer orelse return .invalid_argument;
    output.* = null;
    const options = optionsFromC(option_value) catch return .invalid_argument;
    const value = sink.Sink.borrowedFd(fd) orelse return .invalid_argument;
    output.* = pftrace_writer_t.initWithSink(value, options) catch return .io_error;
    return .ok;
}
export fn pftrace_init_callback_with_options(write_fn: ?pftrace_write_fn, context: ?*anyopaque, option_value: ?*const pftrace_writer_options_t, out_writer: ?*?*pftrace_writer_t) pftrace_status_t {
    const output = out_writer orelse return .invalid_argument;
    output.* = null;
    const callback = write_fn orelse return .invalid_argument;
    const options = optionsFromC(option_value) catch return .invalid_argument;
    output.* = pftrace_writer_t.initWithSink(.{ .callback = .{ .write = callback, .context = context } }, options) catch return .io_error;
    return .ok;
}

export fn pftrace_init_string(path_value: pftrace_string_t) ?*pftrace_writer_t {
    var writer: ?*pftrace_writer_t = null;
    return if (pftrace_init_path_string_with_options(path_value, null, &writer) == .ok) writer else null;
}
export fn pftrace_init(path_ptr: ?[*]const u8) ?*pftrace_writer_t {
    return pftrace_init_string(stringArg(path_ptr) orelse return null);
}
export fn pftrace_destroy(writer: ?*pftrace_writer_t) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    if (w.active_packet.active or w.active_event.active) return .invalid_state;
    return w.deinit();
}
export fn pftrace_flush(writer: ?*pftrace_writer_t) pftrace_status_t {
    return if (writer) |w| w.flush() else .invalid_argument;
}
export fn pftrace_finalize(writer: ?*pftrace_writer_t) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    if (w.terminal_status != .ok) return w.terminal_status;
    if (w.active_packet.active or w.active_event.active) return .invalid_state;
    return w.finalize();
}

export fn pftrace_packet_begin(writer: ?*pftrace_writer_t) ?*pftrace_packet_t {
    const w = writer orelse return null;
    if (w.terminal_status != .ok or w.active_packet.active) return null;
    w.packet_pb.reset();
    const checkpoint = w.packet_pb.checkpoint();
    const bookmark = w.packet_pb.beginNested(1) catch return null;
    w.packet_generation +%= 1;
    if (w.packet_generation == 0) w.packet_generation = 1;
    w.active_packet = .{ .writer = w, .bookmark = bookmark, .generation = w.packet_generation, .active = true, .checkpoint = checkpoint, .phase = .packet, .first_error = .ok };
    return &w.active_packet;
}
export fn pftrace_packet_end(writer: ?*pftrace_writer_t, packet: ?*pftrace_packet_t) pftrace_status_t {
    const w = writer orelse return .invalid_argument;
    const p = packetValid(packet) orelse return .invalid_state;
    if (p.writer != w) return .invalid_state;
    if (w.active_event.active) return .invalid_state;
    if (p.first_error != .ok) {
        const status = p.first_error;
        w.packet_pb.reset();
        p.active = false;
        p.phase = .idle;
        return status;
    }
    const close_status = packetMutation(p, w.packet_pb.endNested(p.bookmark));
    if (close_status != .ok) {
        w.packet_pb.reset();
        p.active = false;
        p.phase = .idle;
        return close_status;
    }
    if (w.packet_pb.written().len > w.options.maximum_packet_bytes) {
        w.packet_pb.reset();
        p.active = false;
        p.phase = .idle;
        return .message_too_large;
    }
    const copy_status = w.commitPacket(w.packet_pb.written());
    if (copy_status != .ok) {
        w.packet_pb.reset();
        p.active = false;
        p.phase = .idle;
        return copy_status;
    }
    w.packet_pb.reset();
    p.active = false;
    p.phase = .idle;
    return .ok;
}
/// Preferred packet completion API: ownership comes from packet slot itself.
export fn pftrace_packet_commit(packet: ?*pftrace_packet_t) pftrace_status_t {
    const p = packetValid(packet) orelse return .invalid_state;
    return pftrace_packet_end(p.writer, p);
}
export fn pftrace_packet_set_timestamp(packet: ?*pftrace_packet_t, value: u64) pftrace_status_t {
    const p = packetValid(packet) orelse return .invalid_state;
    if (p.first_error != .ok) return p.first_error;
    return packetMutation(p, p.writer.packet_pb.writeInt(schema.TracePacket.TIMESTAMP, value));
}
export fn pftrace_packet_set_trusted_packet_sequence_id(packet: ?*pftrace_packet_t, value: u32) pftrace_status_t {
    const p = packetValid(packet) orelse return .invalid_state;
    if (p.first_error != .ok) return p.first_error;
    return packetMutation(p, p.writer.packet_pb.writeInt(schema.TracePacket.TRUSTED_PACKET_SEQUENCE_ID, value));
}

fn descriptorProcess(writer: *pftrace_writer_t, uuid: u64, pid: i32, name: []const u8) pftrace_status_t {
    if (writer.terminal_status != .ok) return writer.terminal_status;
    if (writer.finalized) return .invalid_state;
    if (name.len > writer.options.maximum_string_bytes) return .capacity_exceeded;
    writer.packet_pb.reset();
    const result = encodeProcess(&writer.packet_pb, uuid, pid, name);
    const status = mutationStatus(writer, result);
    if (status != .ok) {
        writer.packet_pb.reset();
        return status;
    }
    const commit_status = writer.commitPacket(writer.packet_pb.written());
    writer.packet_pb.reset();
    return commit_status;
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
    if (writer.terminal_status != .ok) return writer.terminal_status;
    if (writer.finalized) return .invalid_state;
    if (name.len > writer.options.maximum_string_bytes) return .capacity_exceeded;
    writer.packet_pb.reset();
    const result = encodeThread(&writer.packet_pb, uuid, parent_uuid, pid, tid, name);
    const status = mutationStatus(writer, result);
    if (status != .ok) {
        writer.packet_pb.reset();
        return status;
    }
    const commit_status = writer.commitPacket(writer.packet_pb.written());
    writer.packet_pb.reset();
    return commit_status;
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
    if (w.terminal_status != .ok) return w.terminal_status;
    if (w.finalized) return .invalid_state;
    w.packet_pb.reset();
    const result = encodeClockSnapshot(&w.packet_pb, boottime_ns);
    const status = mutationStatus(w, result);
    if (status != .ok) {
        w.packet_pb.reset();
        return status;
    }
    const commit_status = w.commitPacket(w.packet_pb.written());
    w.packet_pb.reset();
    return commit_status;
}

export fn pftrace_packet_begin_track_event(packet: ?*pftrace_packet_t) ?*pftrace_track_event_t {
    const p = packetValid(packet) orelse return null;
    if (p.first_error != .ok or p.writer.active_event.active) return null;
    const checkpoint = p.writer.packet_pb.checkpoint();
    const bookmark = p.writer.packet_pb.beginNested(schema.TracePacket.TRACK_EVENT) catch |err| {
        _ = latchPacketError(p, mapError(err));
        return null;
    };
    p.writer.event_generation +%= 1;
    if (p.writer.event_generation == 0) p.writer.event_generation = 1;
    p.writer.active_event = .{ .writer = p.writer, .bookmark = bookmark, .generation = p.writer.event_generation, .active = true, .packet_generation = p.generation, .checkpoint = checkpoint, .phase = .event };
    return &p.writer.active_event;
}
export fn pftrace_track_event_end(event: ?*pftrace_track_event_t) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    const packet = &e.writer.active_packet;
    if (packet.first_error != .ok) {
        e.writer.packet_pb.rollback(e.checkpoint) catch unreachable;
        e.active = false;
        e.phase = .idle;
        return packet.first_error;
    }
    const status = packetMutation(packet, e.writer.packet_pb.endNested(e.bookmark));
    if (status != .ok) {
        e.writer.packet_pb.rollback(e.checkpoint) catch unreachable;
        e.active = false;
        e.phase = .idle;
        return status;
    }
    e.active = false;
    e.phase = .idle;
    return .ok;
}

fn eventMutation(event: ?*pftrace_track_event_t, result: proto.Error!void) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    return packetMutation(&e.writer.active_packet, result);
}
fn eventInvalidArgument(event: ?*pftrace_track_event_t) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    return latchPacketError(&e.writer.active_packet, .invalid_argument);
}
export fn pftrace_track_event_set_type(event: ?*pftrace_track_event_t, event_type: u32) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    if (event_type > 4) return latchPacketError(&e.writer.active_packet, .invalid_argument);
    return eventMutation(event, e.writer.packet_pb.writeInt(schema.TrackEvent.TYPE, event_type));
}
export fn pftrace_track_event_set_track_uuid(event: ?*pftrace_track_event_t, uuid: u64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    return eventMutation(event, e.writer.packet_pb.writeInt(schema.TrackEvent.TRACK_UUID, uuid));
}
export fn pftrace_track_event_set_counter_value(event: ?*pftrace_track_event_t, value: i64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    return eventMutation(event, e.writer.packet_pb.writeSignedInt64(schema.TrackEvent.COUNTER_VALUE, value));
}
export fn pftrace_track_event_add_flow_id(event: ?*pftrace_track_event_t, flow_id: u64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    if (e.flow_count >= e.writer.options.maximum_flow_ids) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    const status = eventMutation(event, e.writer.packet_pb.writeInt(schema.TrackEvent.FLOW_IDS, flow_id));
    if (status == .ok) e.flow_count += 1;
    return status;
}
export fn pftrace_track_event_add_terminating_flow_id(event: ?*pftrace_track_event_t, flow_id: u64) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    if (e.terminating_flow_count >= e.writer.options.maximum_terminating_flow_ids) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    const status = eventMutation(event, e.writer.packet_pb.writeInt(schema.TrackEvent.TERMINATING_FLOW_IDS, flow_id));
    if (status == .ok) e.terminating_flow_count += 1;
    return status;
}

fn writeEventString(event: ?*pftrace_track_event_t, field: u32, value: pftrace_string_t) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    const text = stringSlice(value) orelse return latchPacketError(&e.writer.active_packet, .invalid_argument);
    if (text.len > e.writer.options.maximum_string_bytes) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    return eventMutation(event, e.writer.packet_pb.writeString(field, text));
}
export fn pftrace_track_event_set_name_string(event: ?*pftrace_track_event_t, name: pftrace_string_t) pftrace_status_t {
    return writeEventString(event, schema.TrackEvent.NAME, name);
}
export fn pftrace_track_event_set_name(event: ?*pftrace_track_event_t, name: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_set_name_string(event, stringArg(name) orelse return eventInvalidArgument(event));
}
export fn pftrace_track_event_add_category_string(event: ?*pftrace_track_event_t, category: pftrace_string_t) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.category_count >= e.writer.options.maximum_categories) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    const status = writeEventString(event, schema.TrackEvent.CATEGORIES, category);
    if (status == .ok) e.category_count += 1;
    return status;
}
export fn pftrace_track_event_add_category(event: ?*pftrace_track_event_t, category: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_add_category_string(event, stringArg(category) orelse return eventInvalidArgument(event));
}

fn annotation(event: ?*pftrace_track_event_t, key: pftrace_string_t, field: u32, value: union(enum) { string: pftrace_string_t, int: i64, uint: u64, double: f64, boolean: bool }) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    const k = stringSlice(key) orelse return latchPacketError(&e.writer.active_packet, .invalid_argument);
    if (k.len > e.writer.options.maximum_string_bytes) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    const encoded: AnnotationValue = switch (value) {
        .string => |v| blk: {
            const text = stringSlice(v) orelse return latchPacketError(&e.writer.active_packet, .invalid_argument);
            if (text.len > e.writer.options.maximum_string_bytes) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
            break :blk .{ .string = text };
        },
        .int => |v| .{ .int = v },
        .uint => |v| .{ .uint = v },
        .double => |v| .{ .double = v },
        .boolean => |v| .{ .boolean = v },
    };
    if (field != schema.DebugAnnotation.STRING_VALUE and e.argument_count >= e.writer.options.maximum_arguments) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    const result = encodeAnnotation(&e.writer.packet_pb, k, field, encoded);
    const status = eventMutation(event, result);
    if (status == .ok and field != schema.DebugAnnotation.STRING_VALUE) e.argument_count += 1;
    return status;
}
export fn pftrace_track_event_set_log_message_string(event: ?*pftrace_track_event_t, body: pftrace_string_t) pftrace_status_t {
    return annotation(event, .{ .data = "log_message".ptr, .size = 11 }, schema.DebugAnnotation.STRING_VALUE, .{ .string = body });
}
export fn pftrace_track_event_set_log_message(event: ?*pftrace_track_event_t, body: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_set_log_message_string(event, stringArg(body) orelse return eventInvalidArgument(event));
}
export fn pftrace_track_event_add_arg_string_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: pftrace_string_t) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.STRING_VALUE, .{ .string = value });
}
export fn pftrace_track_event_add_arg_string(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: ?[*]const u8) pftrace_status_t {
    return pftrace_track_event_add_arg_string_string(event, stringArg(key) orelse return eventInvalidArgument(event), stringArg(value) orelse return eventInvalidArgument(event));
}
export fn pftrace_track_event_add_arg_int_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: i64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.INT_VALUE, .{ .int = value });
}
export fn pftrace_track_event_add_arg_int(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: i64) pftrace_status_t {
    return pftrace_track_event_add_arg_int_string(event, stringArg(key) orelse return eventInvalidArgument(event), value);
}
export fn pftrace_track_event_add_arg_uint_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: u64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.UINT_VALUE, .{ .uint = value });
}
export fn pftrace_track_event_add_arg_uint(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: u64) pftrace_status_t {
    return pftrace_track_event_add_arg_uint_string(event, stringArg(key) orelse return eventInvalidArgument(event), value);
}
export fn pftrace_track_event_add_arg_double_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: f64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.DOUBLE_VALUE, .{ .double = value });
}
export fn pftrace_track_event_add_arg_double(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: f64) pftrace_status_t {
    return pftrace_track_event_add_arg_double_string(event, stringArg(key) orelse return eventInvalidArgument(event), value);
}
export fn pftrace_track_event_add_arg_bool_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: bool) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.BOOL_VALUE, .{ .boolean = value });
}
export fn pftrace_track_event_add_arg_bool(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: bool) pftrace_status_t {
    return pftrace_track_event_add_arg_bool_string(event, stringArg(key) orelse return eventInvalidArgument(event), value);
}
export fn pftrace_track_event_add_arg_ptr_string(event: ?*pftrace_track_event_t, key: pftrace_string_t, value: u64) pftrace_status_t {
    return annotation(event, key, schema.DebugAnnotation.POINTER_VALUE, .{ .uint = value });
}
export fn pftrace_track_event_add_arg_ptr(event: ?*pftrace_track_event_t, key: ?[*]const u8, value: u64) pftrace_status_t {
    return pftrace_track_event_add_arg_ptr_string(event, stringArg(key) orelse return eventInvalidArgument(event), value);
}

export fn pftrace_track_event_set_task_execution_string(event: ?*pftrace_track_event_t, file: pftrace_string_t, func: pftrace_string_t, line: u32) pftrace_status_t {
    const e = eventValid(event) orelse return .invalid_state;
    if (e.writer.active_packet.first_error != .ok) return e.writer.active_packet.first_error;
    const f = stringSlice(file) orelse return latchPacketError(&e.writer.active_packet, .invalid_argument);
    const fn_name = stringSlice(func) orelse return latchPacketError(&e.writer.active_packet, .invalid_argument);
    if (f.len > e.writer.options.maximum_string_bytes or fn_name.len > e.writer.options.maximum_string_bytes) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    if (e.task_metadata_assigned) return latchPacketError(&e.writer.active_packet, .invalid_state);
    const iid = e.writer.next_source_iid;
    if (iid == 0 or iid == std.math.maxInt(u64)) return latchPacketError(&e.writer.active_packet, .capacity_exceeded);
    const result = encodeTaskMetadata(&e.writer.packet_pb, iid, f, fn_name, line);
    const status = eventMutation(event, result);
    if (status != .ok) return status;
    e.task_metadata_assigned = true;
    e.writer.next_source_iid += 1;
    return status;
}
export fn pftrace_track_event_set_task_execution(event: ?*pftrace_track_event_t, file: ?[*]const u8, func: ?[*]const u8, line: u32) pftrace_status_t {
    return pftrace_track_event_set_task_execution_string(event, stringArg(file) orelse return eventInvalidArgument(event), stringArg(func) orelse return eventInvalidArgument(event), line);
}

fn testWriter(output: []u8, scratch: []u8) pftrace_writer_t {
    return .{
        .pb = proto.PbWriter.init(output),
        .pb_storage = output,
        .packet_pb = proto.PbWriter.init(scratch),
        .packet_storage = scratch,
        .sink = undefined,
        .io_threaded = undefined,
        .options = defaultOptions(),
        .active_packet = .{ .active = false },
        .active_event = .{ .active = false },
    };
}

test "rejected builder packet never changes committed output and recovery works" {
    var output: [128]u8 = undefined;
    var scratch: [128]u8 = undefined;
    var writer = testWriter(&output, &scratch);
    try writer.pb.writeVarint(7);
    const prefix = writer.pb.written();
    var saved: [1]u8 = undefined;
    @memcpy(&saved, prefix);

    const packet = pftrace_packet_begin(&writer).?;
    writer.packet_pb.setAppendFailurePoint(1);
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, pftrace_packet_set_timestamp(packet, 1));
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, pftrace_packet_end(&writer, packet));
    try std.testing.expectEqualSlices(u8, &saved, writer.pb.written());

    const recovered = pftrace_packet_begin(&writer).?;
    try std.testing.expectEqual(pftrace_status_t.ok, pftrace_packet_set_timestamp(recovered, 2));
    try std.testing.expectEqual(pftrace_status_t.ok, pftrace_packet_end(&writer, recovered));
    try std.testing.expect(writer.pb.written().len > saved.len);
}

test "builder collection boundary latches packet error" {
    var output: [32 * 1024]u8 = undefined;
    var scratch: [32 * 1024]u8 = undefined;
    var writer = testWriter(&output, &scratch);
    const packet = pftrace_packet_begin(&writer).?;
    const event = pftrace_packet_begin_track_event(packet).?;
    for (0..default_collection_limit) |_| {
        try std.testing.expectEqual(pftrace_status_t.ok, pftrace_track_event_add_flow_id(event, 1));
    }
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, pftrace_track_event_add_flow_id(event, 2));
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, pftrace_track_event_end(event));
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, pftrace_packet_end(&writer, packet));
    try std.testing.expectEqual(@as(usize, 0), writer.pb.written().len);
}

test "writer options accept older prefixes and reject contradictory values" {
    var raw: pftrace_writer_options_t = undefined;
    try std.testing.expectEqual(pftrace_status_t.ok, pftrace_writer_options_init(&raw));
    try std.testing.expectEqual(@as(u32, @sizeOf(pftrace_writer_options_t)), raw.struct_size);
    try std.testing.expectEqual(@as(u32, writer_options_version), raw.version);

    const prefix_size = @offsetOf(pftrace_writer_options_t, "packet_scratch_capacity");
    raw.struct_size = prefix_size;
    try std.testing.expectEqual(default_packet_capacity, (try optionsFromC(&raw)).packet_scratch_capacity);

    raw.struct_size = @sizeOf(pftrace_writer_options_t);
    raw.packet_scratch_capacity = 64;
    raw.output_batch_capacity = 64;
    raw.maximum_packet_bytes = 65;
    try std.testing.expectError(error.InvalidArgument, optionsFromC(&raw));

    raw.maximum_packet_bytes = 64;
    raw.maximum_nesting_depth = proto.max_nested_depth + 1;
    try std.testing.expectError(error.InvalidArgument, optionsFromC(&raw));
}

test "trace cap rejects before batch mutation and leaves capacity usable" {
    var output: [16]u8 = undefined;
    var scratch: [16]u8 = undefined;
    var writer = testWriter(&output, &scratch);
    writer.options.maximum_trace_bytes = 3;

    try std.testing.expectEqual(pftrace_status_t.ok, writer.commitPacket(&.{ 1, 2 }));
    const prefix = writer.pb.written();
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, writer.commitPacket(&.{ 3, 4 }));
    try std.testing.expectEqualSlices(u8, prefix, writer.pb.written());
    try std.testing.expectEqual(pftrace_status_t.ok, writer.commitPacket(&.{3}));
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, writer.pb.written());
}

test "trace byte accounting rejects overflow" {
    var output: [16]u8 = undefined;
    var scratch: [16]u8 = undefined;
    var writer = testWriter(&output, &scratch);
    writer.accepted_trace_bytes = std.math.maxInt(u64) - 1;
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, writer.commitPacket(&.{ 1, 2 }));
    try std.testing.expectEqual(@as(usize, 0), writer.pb.written().len);
}

test "direct event validation rejects invalid input before scratch mutation" {
    var output: [128]u8 = undefined;
    var scratch: [128]u8 = undefined;
    var writer = testWriter(&output, &scratch);
    try writer.packet_pb.writeVarint(7);
    const prefix = writer.packet_pb.written();

    var event = pftrace_event_t{
        .timestamp_ns = 1,
        .timestamp_clock_id = 0,
        .trusted_packet_sequence_id = 0,
        .track_uuid = 2,
        .type = .instant,
        .name = .{ .data = "event".ptr, .size = 5 },
        .counter_value = 0,
        .flow_ids = null,
        .flow_id_count = 0,
        .terminating_flow_ids = null,
        .terminating_flow_id_count = 0,
        .categories = null,
        .category_count = 0,
        .arguments = null,
        .argument_count = 0,
    };
    try std.testing.expectEqual(pftrace_status_t.ok, validateDirectEvent(&writer, &event));

    event.flow_id_count = 1;
    try std.testing.expectEqual(pftrace_status_t.invalid_argument, validateDirectEvent(&writer, &event));
    event.flow_id_count = 0;
    event.terminating_flow_id_count = 1;
    try std.testing.expectEqual(pftrace_status_t.invalid_argument, validateDirectEvent(&writer, &event));
    event.terminating_flow_id_count = 0;
    event.category_count = 1;
    try std.testing.expectEqual(pftrace_status_t.invalid_argument, validateDirectEvent(&writer, &event));
    event.category_count = 0;
    event.argument_count = 1;
    try std.testing.expectEqual(pftrace_status_t.invalid_argument, validateDirectEvent(&writer, &event));
    event.argument_count = 0;
    event.type = @enumFromInt(99);
    try std.testing.expectEqual(pftrace_status_t.invalid_argument, validateDirectEvent(&writer, &event));
    event.type = .instant;
    writer.options.maximum_categories = 0;
    var categories = [_]pftrace_string_t{.{ .data = "category".ptr, .size = 8 }};
    event.categories = &categories;
    event.category_count = 1;
    try std.testing.expectEqual(pftrace_status_t.capacity_exceeded, validateDirectEvent(&writer, &event));
    writer.options.maximum_categories = default_collection_limit;
    event.category_count = 0;
    var args = [_]pftrace_arg_t{.{
        .key = .{ .data = "key".ptr, .size = 3 },
        .type = @enumFromInt(99),
        .value = undefined,
    }};
    event.arguments = &args;
    event.argument_count = 1;
    try std.testing.expectEqual(pftrace_status_t.invalid_argument, validateDirectEvent(&writer, &event));
    try std.testing.expectEqualSlices(u8, prefix, writer.packet_pb.written());
}
