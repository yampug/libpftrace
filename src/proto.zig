const std = @import("std");
const builtin = @import("builtin");

pub const WireType = enum(u3) {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    Fixed32 = 5,
};

/// Errors deliberately remain internal until the public status API maps them.
pub const Error = error{
    CapacityExceeded,
    InjectedFailure,
    InvalidBookmark,
    IntegerOverflow,
    MessageTooLarge,
};

pub const max_nested_depth = 64;
pub const length_varint_max_bytes = 5;

const Frame = struct {
    length_offset: usize,
    payload_offset: usize,
};

/// Present only in test builds. Keeping it conditional prevents both a layout
/// change and a runtime branch in production encoders.
const FailureInjection = struct {
    append_count: usize = 0,
    fail_on_append: ?usize = null,
};

/// Opaque proof that a particular nested message is currently open in one writer.
pub const Bookmark = struct {
    buffer_address: usize,
    depth: usize,
    length_offset: usize,
};

/// Fixed-capacity protobuf encoder. All state is local to caller-supplied storage.
pub const PbWriter = struct {
    buffer: []u8,
    cursor: usize = 0,
    max_message_size: u32,
    frames: [max_nested_depth]Frame = undefined,
    frame_count: usize = 0,
    failure_injection: if (builtin.is_test) FailureInjection else void = if (builtin.is_test) .{} else {},

    pub fn init(buffer: []u8) PbWriter {
        return initWithMaxMessageSize(buffer, std.math.maxInt(u32));
    }

    pub fn initWithMaxMessageSize(buffer: []u8, max_message_size: u32) PbWriter {
        return .{ .buffer = buffer, .max_message_size = max_message_size };
    }

    /// Reset buffer for reuse without modifying caller-owned storage.
    pub fn reset(self: *PbWriter) void {
        self.cursor = 0;
        self.frame_count = 0;
    }

    pub fn checkpoint(self: *const PbWriter) usize {
        return self.cursor;
    }

    pub fn rollback(self: *PbWriter, checkpoint_value: usize) Error!void {
        if (checkpoint_value > self.cursor) return error.InvalidBookmark;
        // A generic checkpoint may not leave a partially-open message behind.
        while (self.frame_count > 0 and self.frames[self.frame_count - 1].payload_offset > checkpoint_value) {
            self.frame_count -= 1;
        }
        if (self.frame_count > 0 and self.frames[self.frame_count - 1].payload_offset > checkpoint_value) return error.InvalidBookmark;
        self.cursor = checkpoint_value;
    }

    pub fn written(self: *const PbWriter) []const u8 {
        return self.buffer[0..self.cursor];
    }

    pub fn remaining(self: *const PbWriter) usize {
        return self.buffer.len - self.cursor;
    }

    pub fn nestingDepth(self: *const PbWriter) usize {
        return self.frame_count;
    }

    /// Reject exactly one selected append in test builds. Append points are
    /// one-based; null disables injection. This compiles to no production
    /// state or control flow.
    pub fn setAppendFailurePoint(self: *PbWriter, append_point: ?usize) void {
        if (comptime builtin.is_test) {
            self.failure_injection = .{ .fail_on_append = append_point };
        }
    }

    pub fn appendAttemptCount(self: *const PbWriter) usize {
        if (comptime builtin.is_test) return self.failure_injection.append_count;
        return 0;
    }

    fn checkedAdd(a: usize, b: usize) Error!usize {
        return std.math.add(usize, a, b) catch error.IntegerOverflow;
    }

    fn varintLen(value: u64) usize {
        var v = value;
        var len: usize = 1;
        while (v >= 0x80) : (len += 1) v >>= 7;
        return len;
    }

    fn reserve(self: *PbWriter, count: usize) Error![]u8 {
        const end = try checkedAdd(self.cursor, count);
        if (end > self.buffer.len) return error.CapacityExceeded;
        if (comptime builtin.is_test) {
            self.failure_injection.append_count += 1;
            if (self.failure_injection.fail_on_append) |append_point| {
                if (self.failure_injection.append_count == append_point) {
                    self.failure_injection.fail_on_append = null;
                    return error.InjectedFailure;
                }
            }
        }
        const result = self.buffer[self.cursor..end];
        self.cursor = end;
        return result;
    }

    /// Check a compound write before its individual append points begin.
    /// This preserves the pre-existing all-or-nothing capacity behavior while
    /// still permitting test injection between those append points.
    fn ensureCapacity(self: *const PbWriter, count: usize) Error!void {
        const end = try checkedAdd(self.cursor, count);
        if (end > self.buffer.len) return error.CapacityExceeded;
    }

    fn writeVarintUnchecked(destination: []u8, value: u64) void {
        var v = value;
        var index: usize = 0;
        while (v >= 0x80) : (index += 1) {
            destination[index] = @as(u8, @intCast((v & 0x7f) | 0x80));
            v >>= 7;
        }
        destination[index] = @as(u8, @intCast(v));
    }

    fn writeFieldVarint(self: *PbWriter, field_id: u32, value: u64) Error!void {
        const tag = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(WireType.Varint));
        const tag_len = varintLen(tag);
        const value_len = varintLen(value);
        try self.ensureCapacity(try checkedAdd(tag_len, value_len));
        const tag_destination = try self.reserve(tag_len);
        writeVarintUnchecked(tag_destination, tag);
        const value_destination = try self.reserve(value_len);
        writeVarintUnchecked(value_destination, value);
    }

    pub fn writeTag(self: *PbWriter, field_id: u32, wire_type: WireType) Error!void {
        const value = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(wire_type));
        const destination = try self.reserve(varintLen(value));
        writeVarintUnchecked(destination, value);
    }

    /// Encode an unsigned protobuf varint without a field tag.
    pub fn writeVarint(self: *PbWriter, value: u64) Error!void {
        const destination = try self.reserve(varintLen(value));
        writeVarintUnchecked(destination, value);
    }

    pub fn writeUnsignedInt(self: *PbWriter, field_id: u32, value: u64) Error!void {
        try self.writeFieldVarint(field_id, value);
    }

    /// Protobuf int64 uses the bit-preserving two's-complement u64 representation.
    pub fn writeSignedInt64(self: *PbWriter, field_id: u32, value: i64) Error!void {
        try self.writeFieldVarint(field_id, @bitCast(value));
    }

    pub fn writeFixed32(self: *PbWriter, value: u32) Error!void {
        const destination = try self.reserve(@sizeOf(u32));
        std.mem.writeInt(u32, destination[0..@sizeOf(u32)], value, .little);
    }

    pub fn writeFixed64(self: *PbWriter, value: u64) Error!void {
        const destination = try self.reserve(@sizeOf(u64));
        std.mem.writeInt(u64, destination[0..@sizeOf(u64)], value, .little);
    }

    pub fn writeString(self: *PbWriter, field_id: u32, value: []const u8) Error!void {
        const tag = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(WireType.LengthDelimited));
        const tag_len = varintLen(tag);
        const length_len = varintLen(value.len);
        try self.ensureCapacity(try checkedAdd(try checkedAdd(tag_len, length_len), value.len));
        const tag_destination = try self.reserve(tag_len);
        writeVarintUnchecked(tag_destination, tag);
        const length_destination = try self.reserve(length_len);
        writeVarintUnchecked(length_destination, value.len);
        const body_destination = try self.reserve(value.len);
        @memcpy(body_destination, value);
    }

    pub fn writeBytes(self: *PbWriter, field_id: u32, value: []const u8) Error!void {
        try self.writeString(field_id, value);
    }

    /// Compatibility field writer. Signed values are sign-extended before bitcast.
    pub fn writeInt(self: *PbWriter, field_id: u32, value: anytype) Error!void {
        const T = @TypeOf(value);
        const unsigned_value: u64 = switch (@typeInfo(T)) {
            .int => |info| blk: {
                if (info.bits > 64) @compileError("writeInt supports integers up to 64 bits");
                break :blk if (info.signedness == .signed)
                    @bitCast(@as(i64, value))
                else
                    @as(u64, value);
            },
            .comptime_int => if (value < 0) @bitCast(@as(i64, value)) else @as(u64, value),
            else => @compileError("writeInt expects an integer"),
        };
        try self.writeFieldVarint(field_id, unsigned_value);
    }

    /// Begin a length-delimited child message. Five bytes permit every uint32 length.
    pub fn beginNested(self: *PbWriter, field_id: u32) Error!Bookmark {
        if (self.frame_count == max_nested_depth) return error.InvalidBookmark;
        const tag = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(WireType.LengthDelimited));
        const tag_len = varintLen(tag);
        try self.ensureCapacity(try checkedAdd(tag_len, length_varint_max_bytes));
        const tag_destination = try self.reserve(tag_len);
        writeVarintUnchecked(tag_destination, tag);
        const length_destination = try self.reserve(length_varint_max_bytes);
        @memset(length_destination, 0);

        const length_offset = self.cursor - length_varint_max_bytes;
        self.frames[self.frame_count] = .{
            .length_offset = length_offset,
            .payload_offset = self.cursor,
        };
        self.frame_count += 1;
        return .{
            .buffer_address = @intFromPtr(self.buffer.ptr),
            .depth = self.frame_count,
            .length_offset = length_offset,
        };
    }

    /// Canonically encode child length and compact its reserved five-byte slot.
    pub fn endNested(self: *PbWriter, bookmark: Bookmark) Error!void {
        if (bookmark.buffer_address != @intFromPtr(self.buffer.ptr) or bookmark.depth != self.frame_count or self.frame_count == 0) return error.InvalidBookmark;
        const frame = self.frames[self.frame_count - 1];
        if (bookmark.length_offset != frame.length_offset) return error.InvalidBookmark;

        const payload_len = self.cursor - frame.payload_offset;
        if (payload_len > self.max_message_size or payload_len > std.math.maxInt(u32)) return error.MessageTooLarge;
        const encoded_len = varintLen(payload_len);
        const reclaimed = length_varint_max_bytes - encoded_len;
        writeVarintUnchecked(self.buffer[frame.length_offset .. frame.length_offset + encoded_len], payload_len);
        if (reclaimed != 0) {
            std.mem.copyForwards(u8, self.buffer[frame.length_offset + encoded_len .. self.cursor - reclaimed], self.buffer[frame.payload_offset..self.cursor]);
            self.cursor -= reclaimed;
        }
        self.frame_count -= 1;
    }
};

test "PbWriter basic" {
    var storage: [3]u8 = undefined;
    var pb = PbWriter.init(&storage);
    try pb.writeTag(1, .Varint);
    try pb.writeVarint(150);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x08, 0x96, 0x01 }, pb.written());
    try std.testing.expectEqual(@as(usize, 0), pb.remaining());
}

test "signed int64 uses protobuf two's-complement varints" {
    const cases = [_]struct { value: i64, expected: []const u8 }{
        .{ .value = std.math.minInt(i64), .expected = &[_]u8{ 0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 } },
        .{ .value = -1, .expected = &[_]u8{ 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 } },
        .{ .value = 0, .expected = &[_]u8{ 0x08, 0x00 } },
        .{ .value = std.math.maxInt(i64), .expected = &[_]u8{ 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f } },
    };
    for (cases) |case| {
        var storage: [11]u8 = undefined;
        var pb = PbWriter.init(&storage);
        try pb.writeSignedInt64(1, case.value);
        try std.testing.expectEqualSlices(u8, case.expected, pb.written());
    }
}

test "unsigned varint boundaries are byte exact" {
    const cases = [_]struct { value: u64, expected: []const u8 }{
        .{ .value = 0x7f, .expected = &[_]u8{0x7f} },
        .{ .value = 0x80, .expected = &[_]u8{ 0x80, 0x01 } },
        .{ .value = 0x3fff, .expected = &[_]u8{ 0xff, 0x7f } },
        .{ .value = 0x4000, .expected = &[_]u8{ 0x80, 0x80, 0x01 } },
        .{ .value = 0xffffffff, .expected = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x0f } },
    };
    for (cases) |case| {
        var storage: [10]u8 = undefined;
        var pb = PbWriter.init(&storage);
        try pb.writeVarint(case.value);
        try std.testing.expectEqualSlices(u8, case.expected, pb.written());
    }
}

test "length varints cover every uint32 width transition" {
    const cases = [_]struct { value: u32, width: usize }{
        .{ .value = 0x7f, .width = 1 },
        .{ .value = 0x80, .width = 2 },
        .{ .value = 0x3fff, .width = 2 },
        .{ .value = 0x4000, .width = 3 },
        .{ .value = 0x1fffff, .width = 3 },
        .{ .value = 0x200000, .width = 4 },
        .{ .value = 0x0fffffff, .width = 4 },
        .{ .value = 0x10000000, .width = 5 },
        .{ .value = std.math.maxInt(u32), .width = 5 },
    };
    for (cases) |case| {
        var encoded: [length_varint_max_bytes]u8 = undefined;
        const width = PbWriter.varintLen(case.value);
        try std.testing.expectEqual(case.width, width);
        PbWriter.writeVarintUnchecked(encoded[0..width], case.value);
        var decoded: u64 = 0;
        for (encoded[0..width], 0..) |byte, index| {
            decoded |= @as(u64, byte & 0x7f) << @as(u6, @intCast(index * 7));
        }
        try std.testing.expectEqual(@as(u64, case.value), decoded);
    }
}

test "primitive capacity boundaries" {
    const Cases = struct { required: usize, write: *const fn (*PbWriter) Error!void };
    const cases = [_]Cases{
        .{ .required = 2, .write = struct {
            fn f(pb: *PbWriter) Error!void {
                try pb.writeVarint(150);
            }
        }.f },
        .{ .required = 4, .write = struct {
            fn f(pb: *PbWriter) Error!void {
                try pb.writeFixed32(1);
            }
        }.f },
        .{ .required = 8, .write = struct {
            fn f(pb: *PbWriter) Error!void {
                try pb.writeFixed64(1);
            }
        }.f },
        .{ .required = 5, .write = struct {
            fn f(pb: *PbWriter) Error!void {
                try pb.writeString(1, "abc");
            }
        }.f },
    };
    for (cases) |case| {
        var below: [8]u8 = undefined;
        var pb_below = PbWriter.init(below[0 .. case.required - 1]);
        try std.testing.expectError(error.CapacityExceeded, case.write(&pb_below));
        try std.testing.expectEqual(@as(usize, 0), pb_below.written().len);
        var exact: [8]u8 = undefined;
        var pb_exact = PbWriter.init(exact[0..case.required]);
        try case.write(&pb_exact);
        try std.testing.expectEqual(case.required, pb_exact.written().len);
    }
}

test "nested lengths are canonical across all uint32 varint widths" {
    var storage: [32]u8 = undefined;
    var pb = PbWriter.init(&storage);
    const outer = try pb.beginNested(2);
    try pb.writeTag(1, .Varint);
    try pb.writeVarint(1);
    try pb.endNested(outer);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x02, 0x08, 0x01 }, pb.written());
}

test "nested bookmarks reject foreign repeated and out-of-order closes" {
    var first_storage: [32]u8 = undefined;
    var second_storage: [32]u8 = undefined;
    var first = PbWriter.init(&first_storage);
    var second = PbWriter.init(&second_storage);
    const outer = try first.beginNested(1);
    const inner = try first.beginNested(2);
    const before = first.written().len;
    try std.testing.expectError(error.InvalidBookmark, first.endNested(outer));
    try std.testing.expectEqual(before, first.written().len);
    try std.testing.expectError(error.InvalidBookmark, second.endNested(inner));
    try std.testing.expectEqual(before, first.written().len);
    try first.endNested(inner);
    try std.testing.expectError(error.InvalidBookmark, first.endNested(inner));
    try first.endNested(outer);
}

test "nested message limit leaves encoder rollbackable" {
    var storage: [32]u8 = undefined;
    var pb = PbWriter.initWithMaxMessageSize(&storage, 1);
    const checkpoint_value = pb.checkpoint();
    const nested = try pb.beginNested(1);
    try pb.writeVarint(128);
    try std.testing.expectError(error.MessageTooLarge, pb.endNested(nested));
    try pb.rollback(checkpoint_value);
    try std.testing.expectEqual(@as(usize, 0), pb.written().len);
    try pb.writeVarint(1);
    try std.testing.expectEqualSlices(u8, &[_]u8{1}, pb.written());
}
