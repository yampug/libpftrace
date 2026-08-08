const std = @import("std");
const proto = @import("proto");

const EncodeFn = *const fn (*proto.PbWriter) proto.Error!void;

fn simpleField(pb: *proto.PbWriter) proto.Error!void {
    try pb.writeUnsignedInt(1, 150);
}

fn rawTagAndVarint(pb: *proto.PbWriter) proto.Error!void {
    try pb.writeTag(3, .Varint);
    try pb.writeVarint(150);
}

fn signedAndFixedFields(pb: *proto.PbWriter) proto.Error!void {
    try pb.writeSignedInt64(1, -1);
    try pb.writeFixed32(0x11223344);
    try pb.writeFixed64(0x1122334455667788);
}

fn stringField(pb: *proto.PbWriter) proto.Error!void {
    try pb.writeBytes(2, "body");
}

fn nestedDescriptor(pb: *proto.PbWriter) proto.Error!void {
    const descriptor = try pb.beginNested(60);
    try pb.writeUnsignedInt(1, 42);
    try pb.writeString(2, "descriptor");
    try pb.endNested(descriptor);
}

fn trackEvent(pb: *proto.PbWriter) proto.Error!void {
    const event = try pb.beginNested(11);
    try pb.writeUnsignedInt(9, 1);
    try pb.writeString(23, "track event");
    const annotation = try pb.beginNested(4);
    try pb.writeString(10, "phase");
    try pb.writeString(6, "run");
    try pb.endNested(annotation);
    try pb.endNested(event);
}

fn appendCount(encode: EncodeFn) !usize {
    var storage: [256]u8 = undefined;
    var pb = proto.PbWriter.init(&storage);
    try encode(&pb);
    return pb.appendAttemptCount();
}

fn runFailureMatrix(encode: EncodeFn) !void {
    const count = try appendCount(encode);
    var known_good_storage: [256]u8 = undefined;
    var known_good = proto.PbWriter.init(&known_good_storage);
    try known_good.writeVarint(7);
    try encode(&known_good);
    const expected = known_good.written();

    var append_point: usize = 1;
    while (append_point <= count) : (append_point += 1) {
        var storage: [256]u8 = undefined;
        var pb = proto.PbWriter.init(&storage);
        try pb.writeVarint(7); // committed prefix must survive rollback.
        const checkpoint = pb.checkpoint();
        const initial_depth = pb.nestingDepth();
        const prefix = pb.written();

        pb.setAppendFailurePoint(append_point);
        try std.testing.expectError(error.InjectedFailure, encode(&pb));
        try pb.rollback(checkpoint);
        try std.testing.expectEqual(checkpoint, pb.written().len);
        try std.testing.expectEqual(initial_depth, pb.nestingDepth());
        try std.testing.expectEqualSlices(u8, prefix, pb.written());

        try encode(&pb);
        try std.testing.expectEqual(initial_depth, pb.nestingDepth());
        try std.testing.expectEqualSlices(u8, expected, pb.written());
    }
}

test "append failure matrix restores encoder transactions" {
    try runFailureMatrix(simpleField);
    try runFailureMatrix(rawTagAndVarint);
    try runFailureMatrix(signedAndFixedFields);
    try runFailureMatrix(stringField);
    try runFailureMatrix(nestedDescriptor);
    try runFailureMatrix(trackEvent);
}
