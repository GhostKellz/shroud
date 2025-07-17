const std = @import("std");

test "ed25519 api test" {
    // Test different Ed25519 API methods
    const seed = [_]u8{0} ** 32;

    // Try generateDeterministic (this should work)
    const kp1 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    _ = kp1;

    // Try random generation
    const kp2 = std.crypto.sign.Ed25519.KeyPair.generate(null);
    _ = kp2;
}
