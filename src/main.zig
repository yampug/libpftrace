const std = @import("std");
const proto = @import("proto.zig");
const schema = @import("schema.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

// --- Opaque Types ---

const MAGIC_PACKET = 0x504B5431; // PKT1
const MAGIC_EVENT = 0x45565431; // EVT1
const MAGIC_DEAD = 0xDEADBEEF;

pub const pftrace_writer_t = struct {
    pb: proto.PbWriter,
    file_path: []u8,
    file: std.fs.File,

    pub fn init(path: []const u8) !*pftrace_writer_t {
        const ptr = try allocator.create(pftrace_writer_t);
        errdefer allocator.destroy(ptr);

        ptr.pb = proto.PbWriter.init(allocator);
        errdefer ptr.pb.deinit();

        ptr.file_path = try allocator.dupe(u8, path);
        errdefer allocator.free(ptr.file_path);

        ptr.file = try std.fs.cwd().createFile(path, .{});
        // If file open fails, errdefer chain cleans up path, pb, and ptr.
        return ptr;
    }

    pub fn deinit(self: *pftrace_writer_t) void {
        self.flush() catch {};
        self.file.close();
        allocator.free(self.file_path);
        self.pb.deinit();
        allocator.destroy(self);
    }

    pub fn flush(self: *pftrace_writer_t) !void {
        if (self.pb.buffer.items.len > 0) {
            self.file.writeAll(self.pb.buffer.items) catch |err| {
                std.debug.print("libpftrace: failed to flush trace data: {}\n", .{err});
                return err;
            };
            self.pb.reset();
        }
    }
};

pub const pftrace_packet_t = struct {
    writer: *pftrace_writer_t,
    bookmark: usize,
    magic: u32,
};

const PendingSourceLoc = struct {
    file: []const u8, // Owned slice (duped)
    func: []const u8, // Owned slice (duped)
    line: u32,
    iid: u64,
};

pub const pftrace_track_event_t = struct {
    writer: *pftrace_writer_t,
    bookmark: usize,
    pending_loc: ?PendingSourceLoc = null,
    magic: u32,
};

// Security: Safe handling of C strings.
fn span_c(ptr: ?[*]const u8) []const u8 {
    if (ptr) |p| {
        const ptr0: [*:0]const u8 = @ptrCast(p);
        return std.mem.span(ptr0);
    }
    return ""; // Soft fail
}

// Simple hash for IID (djb2)
fn hash_iid(s1: []const u8, s2: []const u8, val: u32) u64 {
    var h: u64 = 5381;
    for (s1) |c| h = ((h << 5) +% h) +% c;
    for (s2) |c| h = ((h << 5) +% h) +% c;
    h = ((h << 5) +% h) +% val;
    if (h == 0) return 1;
    return h;
}

// --- Exports ---

export fn pftrace_init(path_ptr: ?[*]const u8) ?*pftrace_writer_t {
    if (path_ptr == null) return null;
    const path = span_c(path_ptr);
    if (path.len == 0) return null;
    return pftrace_writer_t.init(path) catch null;
}

export fn pftrace_destroy(w: ?*pftrace_writer_t) void {
    if (w) |ptr| ptr.deinit();
}

export fn pftrace_packet_begin(w: ?*pftrace_writer_t) ?*pftrace_packet_t {
    if (w == null) return null;
    const ptr = w.?;
    const bm = ptr.pb.beginNested(1) catch return null;
    const pkt = allocator.create(pftrace_packet_t) catch {
        ptr.pb.endNested(bm);
        return null;
    };
    pkt.* = .{ .writer = ptr, .bookmark = bm, .magic = MAGIC_PACKET };
    return pkt;
}

export fn pftrace_packet_end(w: ?*pftrace_writer_t, p: ?*pftrace_packet_t) void {
    if (w == null or p == null) return;
    const pkt = p.?;

    // Safety: Double-Free / Use-After-Free detection
    if (pkt.magic != MAGIC_PACKET) {
        if (pkt.magic == MAGIC_DEAD) {
            std.debug.print("libpftrace: Double-free detected on pftrace_packet_end\n", .{});
        } else {
            std.debug.print("libpftrace: Invalid packet handle passed to pftrace_packet_end\n", .{});
        }
        return;
    }
    pkt.magic = MAGIC_DEAD; // Mark as dead

    const ptr = w.?;
    ptr.pb.endNested(pkt.bookmark);
    allocator.destroy(pkt);
    ptr.flush() catch {};
}

export fn pftrace_packet_set_timestamp(p: ?*pftrace_packet_t, val: u64) void {
    if (p) |pkt| {
        if (pkt.magic == MAGIC_PACKET) {
            pkt.writer.pb.writeInt(schema.TracePacket.TIMESTAMP, val) catch {};
        }
    }
}

export fn pftrace_packet_set_trusted_packet_sequence_id(p: ?*pftrace_packet_t, val: u32) void {
    if (p) |pkt| {
        if (pkt.magic == MAGIC_PACKET) {
            pkt.writer.pb.writeInt(schema.TracePacket.TRUSTED_PACKET_SEQUENCE_ID, val) catch {};
        }
    }
}

// --- Domain Objects ---

export fn pftrace_write_process_track_descriptor(w: ?*pftrace_writer_t, uuid: u64, pid: i32, name_ptr: ?[*]const u8) void {
    if (w == null) return;
    const ptr = w.?;
    const name = span_c(name_ptr);

    const bm_pkt = ptr.pb.beginNested(1) catch return;
    const bm_desc = ptr.pb.beginNested(schema.TracePacket.TRACK_DESCRIPTOR) catch return;

    ptr.pb.writeInt(schema.TrackDescriptor.UUID, uuid) catch {};

    const bm_proc = ptr.pb.beginNested(schema.TrackDescriptor.PROCESS) catch return;
    ptr.pb.writeInt(schema.ProcessDescriptor.PID, pid) catch {};
    ptr.pb.writeString(schema.ProcessDescriptor.PROCESS_NAME, name) catch {};
    ptr.pb.endNested(bm_proc);

    ptr.pb.endNested(bm_desc);
    ptr.pb.endNested(bm_pkt);
    ptr.flush() catch {};
}

export fn pftrace_write_thread_track_descriptor(w: ?*pftrace_writer_t, uuid: u64, parent_uuid: u64, pid: i32, tid: i32, name_ptr: ?[*]const u8) void {
    if (w == null) return;
    const ptr = w.?;
    const name = span_c(name_ptr);

    const bm_pkt = ptr.pb.beginNested(1) catch return;
    const bm_desc = ptr.pb.beginNested(schema.TracePacket.TRACK_DESCRIPTOR) catch return;

    ptr.pb.writeInt(schema.TrackDescriptor.UUID, uuid) catch {};
    ptr.pb.writeInt(schema.TrackDescriptor.PARENT_UUID, parent_uuid) catch {};

    const bm_thread = ptr.pb.beginNested(schema.TrackDescriptor.THREAD) catch return;
    ptr.pb.writeInt(schema.ThreadDescriptor.PID, pid) catch {};
    ptr.pb.writeInt(schema.ThreadDescriptor.TID, tid) catch {};
    ptr.pb.writeString(schema.ThreadDescriptor.THREAD_NAME, name) catch {};
    ptr.pb.endNested(bm_thread);

    ptr.pb.endNested(bm_desc);
    ptr.pb.endNested(bm_pkt);
    ptr.flush() catch {};
}

export fn pftrace_write_clock_snapshot(w: ?*pftrace_writer_t, boottime_ns: u64) void {
    if (w == null) return;
    const ptr = w.?;
    const bm_pkt = ptr.pb.beginNested(1) catch return;
    const bm_snap = ptr.pb.beginNested(schema.TracePacket.CLOCK_SNAPSHOT) catch return;

    const bm_clock = ptr.pb.beginNested(schema.ClockSnapshot.CLOCKS) catch return;
    ptr.pb.writeInt(schema.Clock.CLOCK_ID, 6) catch {}; // BOOTTIME
    ptr.pb.writeInt(schema.Clock.TIMESTAMP, boottime_ns) catch {};
    ptr.pb.endNested(bm_clock);

    ptr.pb.endNested(bm_snap);
    ptr.pb.endNested(bm_pkt);
    ptr.flush() catch {};
}

// --- Track Events ---

export fn pftrace_packet_begin_track_event(p: ?*pftrace_packet_t) ?*pftrace_track_event_t {
    if (p == null) return null;
    const pkt = p.?;
    if (pkt.magic != MAGIC_PACKET) return null;

    const w = pkt.writer;
    const bm = w.pb.beginNested(schema.TracePacket.TRACK_EVENT) catch return null;
    const te = allocator.create(pftrace_track_event_t) catch {
        w.pb.endNested(bm);
        return null;
    };
    te.* = .{ .writer = w, .bookmark = bm, .pending_loc = null, .magic = MAGIC_EVENT };
    return te;
}

export fn pftrace_track_event_end(te: ?*pftrace_track_event_t) void {
    if (te == null) return;
    const ptr = te.?;

    if (ptr.magic != MAGIC_EVENT) {
        if (ptr.magic == MAGIC_DEAD) {
            std.debug.print("libpftrace: Double-free on pftrace_track_event_end\n", .{});
        }
        return;
    }
    ptr.magic = MAGIC_DEAD;

    // End the TrackEvent message (so we are back at TracePacket level)
    ptr.writer.pb.endNested(ptr.bookmark);

    // If there is pending source loc data to intern, write it now (still inside TracePacket)
    if (ptr.pending_loc) |loc| {
        if (ptr.writer.pb.beginNested(schema.TracePacket.INTERNED_DATA)) |bm_intern| {
            if (ptr.writer.pb.beginNested(schema.InternedData.SOURCE_LOCATIONS)) |bm_sl| {
                ptr.writer.pb.writeInt(schema.SourceLocation.IID, loc.iid) catch {};
                ptr.writer.pb.writeString(schema.SourceLocation.FILE_NAME, loc.file) catch {};
                ptr.writer.pb.writeString(schema.SourceLocation.FUNCTION_NAME, loc.func) catch {};
                ptr.writer.pb.writeInt(schema.SourceLocation.LINE_NUMBER, loc.line) catch {};
                ptr.writer.pb.endNested(bm_sl);
            } else |_| {}
            ptr.writer.pb.endNested(bm_intern);
        } else |_| {}

        allocator.free(loc.file);
        allocator.free(loc.func);
    }

    allocator.destroy(ptr);
}

export fn pftrace_track_event_set_type(te: ?*pftrace_track_event_t, type_enum: u32) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) t.writer.pb.writeInt(schema.TrackEvent.TYPE, type_enum) catch {};
    }
}

export fn pftrace_track_event_set_name(te: ?*pftrace_track_event_t, name_ptr: ?[*]const u8) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const name = span_c(name_ptr);
            t.writer.pb.writeString(schema.TrackEvent.NAME, name) catch {};
        }
    }
}

export fn pftrace_track_event_set_track_uuid(te: ?*pftrace_track_event_t, uuid: u64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) t.writer.pb.writeInt(schema.TrackEvent.TRACK_UUID, uuid) catch {};
    }
}

export fn pftrace_track_event_add_category(te: ?*pftrace_track_event_t, cat_ptr: ?[*]const u8) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const cat = span_c(cat_ptr);
            t.writer.pb.writeString(schema.TrackEvent.CATEGORIES, cat) catch {};
        }
    }
}

export fn pftrace_track_event_set_counter_value(te: ?*pftrace_track_event_t, value: i64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) t.writer.pb.writeInt(schema.TrackEvent.COUNTER_VALUE, value) catch {};
    }
}

export fn pftrace_track_event_add_flow_id(te: ?*pftrace_track_event_t, flow_id: u64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) t.writer.pb.writeInt(schema.TrackEvent.FLOW_IDS, flow_id) catch {};
    }
}

export fn pftrace_track_event_add_terminating_flow_id(te: ?*pftrace_track_event_t, flow_id: u64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) t.writer.pb.writeInt(schema.TrackEvent.TERMINATING_FLOW_IDS, flow_id) catch {};
    }
}

// --- Structured Features ---

fn begin_debug_annotation(te: *pftrace_track_event_t, key: []const u8) !usize {
    const bm = try te.writer.pb.beginNested(schema.TrackEvent.DEBUG_ANNOTATIONS);
    try te.writer.pb.writeString(schema.DebugAnnotation.NAME, key);
    return bm;
}

export fn pftrace_track_event_set_log_message(te: ?*pftrace_track_event_t, body_ptr: ?[*]const u8) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const body = span_c(body_ptr);
            if (begin_debug_annotation(t, "log_message")) |bm| {
                t.writer.pb.writeString(schema.DebugAnnotation.STRING_VALUE, body) catch {};
                t.writer.pb.endNested(bm);
            } else |_| {}
        }
    }
}

export fn pftrace_track_event_set_task_execution(te: ?*pftrace_track_event_t, file_ptr: ?[*]const u8, func_ptr: ?[*]const u8, line: u32) void {
    if (te == null) return;
    const ptr = te.?;
    if (ptr.magic != MAGIC_EVENT) return;

    const file = span_c(file_ptr);
    const func = span_c(func_ptr);

    // Dupe strings to ensure lifetime safety until track_event_end
    // If alloc fails, we just don't record task execution for now.
    const file_dupe = allocator.dupe(u8, file) catch return;
    const func_dupe = allocator.dupe(u8, func) catch {
        allocator.free(file_dupe);
        return;
    };

    const iid = hash_iid(file, func, line);

    ptr.pending_loc = .{
        .file = file_dupe,
        .func = func_dupe,
        .line = line,
        .iid = iid,
    };

    if (ptr.writer.pb.beginNested(schema.TrackEvent.TASK_EXECUTION)) |bm| {
        ptr.writer.pb.writeInt(schema.TaskExecution.POSTED_FROM_IID, iid) catch {};
        ptr.writer.pb.endNested(bm);
    } else |_| {}
}

// --- Arguments ---

export fn pftrace_track_event_add_arg_string(te: ?*pftrace_track_event_t, key_ptr: ?[*]const u8, val_ptr: ?[*]const u8) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const key = span_c(key_ptr);
            const val = span_c(val_ptr);
            if (begin_debug_annotation(t, key)) |bm| {
                t.writer.pb.writeString(schema.DebugAnnotation.STRING_VALUE, val) catch {};
                t.writer.pb.endNested(bm);
            } else |_| {}
        }
    }
}

export fn pftrace_track_event_add_arg_int(te: ?*pftrace_track_event_t, key_ptr: ?[*]const u8, value: i64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const key = span_c(key_ptr);
            if (begin_debug_annotation(t, key)) |bm| {
                t.writer.pb.writeInt(schema.DebugAnnotation.INT_VALUE, value) catch {};
                t.writer.pb.endNested(bm);
            } else |_| {}
        }
    }
}

export fn pftrace_track_event_add_arg_uint(te: ?*pftrace_track_event_t, key_ptr: ?[*]const u8, value: u64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const key = span_c(key_ptr);
            if (begin_debug_annotation(t, key)) |bm| {
                t.writer.pb.writeInt(schema.DebugAnnotation.UINT_VALUE, value) catch {};
                t.writer.pb.endNested(bm);
            } else |_| {}
        }
    }
}

export fn pftrace_track_event_add_arg_double(te: ?*pftrace_track_event_t, key_ptr: ?[*]const u8, value: f64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const key = span_c(key_ptr);
            if (begin_debug_annotation(t, key)) |bm| {
                t.writer.pb.writeTag(schema.DebugAnnotation.DOUBLE_VALUE, .Fixed64) catch {};
                const bits = @as(u64, @bitCast(value));
                t.writer.pb.writeFixed64(bits) catch {};
                t.writer.pb.endNested(bm);
            } else |_| {}
        }
    }
}

export fn pftrace_track_event_add_arg_bool(te: ?*pftrace_track_event_t, key_ptr: ?[*]const u8, value: bool) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const key = span_c(key_ptr);
            if (begin_debug_annotation(t, key)) |bm| {
                t.writer.pb.writeInt(schema.DebugAnnotation.BOOL_VALUE, @as(u64, if (value) 1 else 0)) catch {};
                t.writer.pb.endNested(bm);
            } else |_| {}
        }
    }
}

export fn pftrace_track_event_add_arg_ptr(te: ?*pftrace_track_event_t, key_ptr: ?[*]const u8, value: u64) void {
    if (te) |t| {
        if (t.magic == MAGIC_EVENT) {
            const key = span_c(key_ptr);
            if (begin_debug_annotation(t, key)) |bm| {
                t.writer.pb.writeInt(schema.DebugAnnotation.POINTER_VALUE, value) catch {};
                t.writer.pb.endNested(bm);
            } else |_| {}
        }
    }
}
