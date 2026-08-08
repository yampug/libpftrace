const std = @import("std");

/// Writer-local output destination. Only path-created files are owned.
pub const Sink = union(enum) {
    owned_file: std.Io.File,
    borrowed_file: std.Io.File,
    callback: Callback,

    pub const Callback = struct {
        write: *const fn (?*anyopaque, ?[*]const u8, usize) callconv(.c) c_int,
        context: ?*anyopaque,
    };

    pub const WriteError = error{WriteFailed};

    pub fn borrowedFd(fd: c_int) ?Sink {
        if (fd < 0) return null;
        return .{ .borrowed_file = .{
            .handle = @intCast(fd),
            .flags = .{ .nonblocking = false },
        } };
    }

    pub fn writeAll(self: *const Sink, io: std.Io, bytes: []const u8) WriteError!void {
        switch (self.*) {
            .owned_file => |file| file.writeStreamingAll(io, bytes) catch return error.WriteFailed,
            .borrowed_file => |file| file.writeStreamingAll(io, bytes) catch return error.WriteFailed,
            .callback => |callback| {
                // Callback success has one representation: PFTRACE_OK (zero).
                if (callback.write(callback.context, bytes.ptr, bytes.len) != 0) return error.WriteFailed;
            },
        }
    }

    pub fn deinit(self: *Sink, io: std.Io) void {
        switch (self.*) {
            .owned_file => |file| file.close(io),
            .borrowed_file, .callback => {},
        }
    }
};
