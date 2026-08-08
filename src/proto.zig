const std = @import("std");

pub const WireType = enum(u3) {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    Fixed32 = 5,
};

/// Errors deliberately remain internal until the public status API maps them.
pub const Error = error{
    CapacityExceeded,
    InvalidBookmark,
    IntegerOverflow,
    MessageTooLarge,
};

/// Cursor position in one writer's caller-owned buffer.
pub const Checkpoint = usize;

pub const PbWriter = struct {
    buffer: []u8,
    cursor: usize = 0,

    pub fn init(buffer: []u8) PbWriter {
        return .{ .buffer = buffer };
    }

    /// Reset buffer for reuse without modifying caller-owned storage.
    pub fn reset(self: *PbWriter) void {
        self.cursor = 0;
    }

    pub fn checkpoint(self: *const PbWriter) Checkpoint {
        return self.cursor;
    }

    pub fn rollback(self: *PbWriter, checkpoint_value: Checkpoint) Error!void {
        if (checkpoint_value > self.cursor) return error.InvalidBookmark;
        self.cursor = checkpoint_value;
    }

    pub fn written(self: *const PbWriter) []const u8 {
        return self.buffer[0..self.cursor];
    }

    pub fn remaining(self: *const PbWriter) usize {
        return self.buffer.len - self.cursor;
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
        const result = self.buffer[self.cursor..end];
        self.cursor = end;
        return result;
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

    pub fn writeTag(self: *PbWriter, field_id: u32, wire_type: WireType) Error!void {
        const value = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(wire_type));
        const destination = try self.reserve(varintLen(value));
        writeVarintUnchecked(destination, value);
    }

    pub fn writeVarint(self: *PbWriter, value: u64) Error!void {
        const destination = try self.reserve(varintLen(value));
        writeVarintUnchecked(destination, value);
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
        const total = try checkedAdd(try checkedAdd(varintLen(tag), varintLen(value.len)), value.len);
        const destination = try self.reserve(total);
        const tag_len = varintLen(tag);
        writeVarintUnchecked(destination[0..tag_len], tag);
        const length_len = varintLen(value.len);
        writeVarintUnchecked(destination[tag_len .. tag_len + length_len], value.len);
        @memcpy(destination[tag_len + length_len ..], value);
    }

    pub fn writeBytes(self: *PbWriter, field_id: u32, value: []const u8) Error!void {
        try self.writeString(field_id, value);
    }

    pub fn writeInt(self: *PbWriter, field_id: u32, value: anytype) Error!void {
        const T = @TypeOf(value);
        const unsigned_value: u64 = switch (@typeInfo(T)) {
            .int => |info| if (info.signedness == .signed) @as(u64, @bitCast(value)) else @intCast(value),
            .comptime_int => @intCast(value),
            else => @compileError("writeInt expects an integer"),
        };
        const tag = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(WireType.Varint));
        const tag_len = varintLen(tag);
        const value_len = varintLen(unsigned_value);
        const destination = try self.reserve(try checkedAdd(tag_len, value_len));
        writeVarintUnchecked(destination[0..tag_len], tag);
        writeVarintUnchecked(destination[tag_len..], unsigned_value);
    }

    // Nested lengths retain current fixed-width representation. E2.S2 replaces
    // this with validated canonical backpatching and nesting frames.
    pub fn beginNested(self: *PbWriter, field_id: u32) Error!usize {
        const tag = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(WireType.LengthDelimited));
        const tag_len = varintLen(tag);
        const destination = try self.reserve(try checkedAdd(tag_len, 4));
        writeVarintUnchecked(destination[0..tag_len], tag);
        @memset(destination[tag_len..], 0);
        return self.cursor - 4;
    }

    pub fn endNested(self: *PbWriter, bookmark: usize) void {
        const end_index = self.cursor;
        const len = end_index - (bookmark + 4);
        var v = len;
        var i: usize = 0;
        const slice = self.buffer[bookmark .. bookmark + 4];
        while (i < 3) : (i += 1) {
            slice[i] = @as(u8, @intCast((v & 0x7f) | 0x80));
            v >>= 7;
        }
        slice[3] = @as(u8, @intCast(v & 0x7f));
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

        var above: [9]u8 = undefined;
        var pb_above = PbWriter.init(above[0 .. case.required + 1]);
        try case.write(&pb_above);
        try std.testing.expectEqual(case.required, pb_above.written().len);
    }
}

test "zero-length buffer rejects writes" {
    var storage: [0]u8 = .{};
    var pb = PbWriter.init(&storage);
    try std.testing.expectError(error.CapacityExceeded, pb.writeVarint(0));
    try std.testing.expectEqual(@as(usize, 0), pb.written().len);
}

test "checkpoints rollback nested writes while preserving committed prefix" {
    var storage: [32]u8 = undefined;
    var pb = PbWriter.init(&storage);
    try pb.writeVarint(1);
    const outer = pb.checkpoint();
    try pb.writeVarint(2);
    const inner = pb.checkpoint();
    try pb.writeVarint(300);
    try pb.rollback(inner);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2 }, pb.written());
    try pb.rollback(outer);
    try std.testing.expectEqualSlices(u8, &[_]u8{1}, pb.written());
    try std.testing.expectError(error.InvalidBookmark, pb.rollback(2));
}

test "writers have independent caller-owned storage" {
    var first_storage: [2]u8 = undefined;
    var second_storage: [2]u8 = undefined;
    var first = PbWriter.init(&first_storage);
    var second = PbWriter.init(&second_storage);
    try first.writeVarint(1);
    try second.writeVarint(2);
    try std.testing.expectEqualSlices(u8, &[_]u8{1}, first.written());
    try std.testing.expectEqualSlices(u8, &[_]u8{2}, second.written());
}

test "PbWriter nested" {
    var storage: [7]u8 = undefined;
    var pb = PbWriter.init(&storage);
    const bm = try pb.beginNested(2);
    try pb.writeTag(1, .Varint);
    try pb.writeVarint(1);
    pb.endNested(bm);
    const expected = &[_]u8{ 0x12, 0x82, 0x80, 0x80, 0x00, 0x08, 0x01 };
    try std.testing.expectEqualSlices(u8, expected, pb.written());
}
