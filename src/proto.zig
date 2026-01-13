const std = @import("std");

pub const WireType = enum(u3) {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    Fixed32 = 5,
};

pub const PbWriter = struct {
    buffer: std.ArrayListUnmanaged(u8) = .{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PbWriter {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PbWriter) void {
        self.buffer.deinit(self.allocator);
    }

    /// Reset buffer for reuse
    pub fn reset(self: *PbWriter) void {
        self.buffer.clearRetainingCapacity();
    }

    pub fn writeTag(self: *PbWriter, field_id: u32, wire_type: WireType) !void {
        const val = (@as(u64, field_id) << 3) | @as(u64, @intFromEnum(wire_type));
        try self.writeVarint(val);
    }

    pub fn writeVarint(self: *PbWriter, value: u64) !void {
        var v = value;
        while (v >= 0x80) {
            try self.buffer.append(self.allocator, @as(u8, @intCast((v & 0x7F) | 0x80)));
            v >>= 7;
        }
        try self.buffer.append(self.allocator, @as(u8, @intCast(v)));
    }

    pub fn writeFixed32(self: *PbWriter, value: u32) !void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, .little);
        try self.buffer.appendSlice(self.allocator, &buf);
    }

    pub fn writeFixed64(self: *PbWriter, value: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .little);
        try self.buffer.appendSlice(self.allocator, &buf);
    }

    pub fn writeString(self: *PbWriter, field_id: u32, value: []const u8) !void {
        try self.writeTag(field_id, .LengthDelimited);
        try self.writeVarint(value.len);
        try self.buffer.appendSlice(self.allocator, value);
    }

    pub fn writeBytes(self: *PbWriter, field_id: u32, value: []const u8) !void {
        try self.writeString(field_id, value);
    }

    pub fn writeInt(self: *PbWriter, field_id: u32, value: anytype) !void {
        try self.writeTag(field_id, .Varint);
        try self.writeVarint(@as(u64, @intCast(value)));
    }

    // --- Nested Messages ---

    pub fn beginNested(self: *PbWriter, field_id: u32) !usize {
        try self.writeTag(field_id, .LengthDelimited);
        const idx = self.buffer.items.len;
        // Reserve 4 bytes for length
        try self.buffer.appendSlice(self.allocator, &[_]u8{ 0, 0, 0, 0 });
        return idx;
    }

    pub fn endNested(self: *PbWriter, bookmark: usize) void {
        const end_idx = self.buffer.items.len;
        const len = end_idx - (bookmark + 4);

        var v = len;
        var i: usize = 0;
        var slice = self.buffer.items[bookmark .. bookmark + 4];

        // Redundant varint encoding (4 bytes fixed)
        while (i < 3) : (i += 1) {
            slice[i] = @as(u8, @intCast((v & 0x7F) | 0x80));
            v >>= 7;
        }
        slice[3] = @as(u8, @intCast(v & 0x7F));
    }
};

test "PbWriter basic" {
    const allocator = std.testing.allocator;
    var pb = PbWriter.init(allocator);
    defer pb.deinit();

    try pb.writeTag(1, .Varint);
    try pb.writeVarint(150);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x08, 0x96, 0x01 }, pb.buffer.items);
}

test "PbWriter nested" {
    const allocator = std.testing.allocator;
    var pb = PbWriter.init(allocator);
    defer pb.deinit();

    const bm = try pb.beginNested(2);
    try pb.writeTag(1, .Varint);
    try pb.writeVarint(1);
    pb.endNested(bm);

    // 12 82 80 80 00 08 01
    const expected = &[_]u8{ 0x12, 0x82, 0x80, 0x80, 0x00, 0x08, 0x01 };
    try std.testing.expectEqualSlices(u8, expected, pb.buffer.items);
}
