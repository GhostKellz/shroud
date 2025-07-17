const std = @import("std");

test "basic qid test" {
    const qid = @import("qid.zig");
    const test_pubkey = [_]u8{1} ** 32;
    const test_qid = qid.QID.fromPublicKey(&test_pubkey);
    
    try std.testing.expect(test_qid.isValid());
}
