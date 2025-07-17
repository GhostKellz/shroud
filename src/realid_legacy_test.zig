//! Test for RealID legacy features implementation

const std = @import("std");
const shroud = @import("root.zig");

test "passphrase identity generation" {
    const passphrase = "my-secure-passphrase-123";

    // Generate identity from passphrase
    const keypair = try shroud.generateIdentityFromPassphrase(passphrase);

    // Should be deterministic - same passphrase = same identity
    const keypair2 = try shroud.generateIdentityFromPassphrase(passphrase);
    try std.testing.expect(std.mem.eql(u8, &keypair.public_key, &keypair2.public_key));
    try std.testing.expect(std.mem.eql(u8, &keypair.private_key, &keypair2.private_key));
    try std.testing.expect(keypair.qid.eql(keypair2.qid));

    // QID should be valid SHROUD QID
    try std.testing.expect(keypair.qid.isValid());
}

test "QID generation and validation" {
    const test_pubkey = [_]u8{0x42} ** 32;
    const qid = shroud.QID.fromPublicKey(&test_pubkey);

    // Should be valid SHROUD QID
    try std.testing.expect(qid.isValid());

    // Should convert to string and back
    var buffer: [40]u8 = undefined;
    const qid_str = try qid.toString(&buffer);
    try std.testing.expect(std.mem.startsWith(u8, qid_str, "fd00"));

    const parsed_qid = try shroud.QID.fromString(qid_str);
    try std.testing.expect(qid.eql(parsed_qid));
}

test "device fingerprinting" {
    const device1 = try shroud.generateDeviceFingerprint(std.testing.allocator);
    const device2 = try shroud.generateDeviceFingerprint(std.testing.allocator);

    // Should be deterministic for same system
    try std.testing.expect(device1.eql(device2));

    // Should convert to hex and back
    var buffer: [64]u8 = undefined;
    const hex_str = try device1.toHexString(&buffer);
    try std.testing.expect(hex_str.len == 64);

    const parsed_device = try shroud.DeviceFingerprint.fromHexString(hex_str);
    try std.testing.expect(device1.eql(parsed_device));
}

test "device policy management" {
    var policy = shroud.DevicePolicy.init(std.testing.allocator);
    defer policy.deinit();

    const device1 = try shroud.generateDeviceFingerprint(std.testing.allocator);
    const device2 = shroud.DeviceFingerprint{ .bytes = [_]u8{0xFF} ** 32 };

    // Add trusted device
    try policy.addDevice(device1);

    // Current device should be allowed
    try std.testing.expect(policy.isDeviceAllowed(device1));

    // Unknown device should be allowed if allow_new_devices is true
    try std.testing.expect(policy.isDeviceAllowed(device2));

    // Require device binding and disallow new devices
    policy.require_device_binding = true;
    policy.allow_new_devices = false;

    // Now only known device should be allowed
    try std.testing.expect(policy.isDeviceAllowed(device1));
    try std.testing.expect(!policy.isDeviceAllowed(device2));
}

test "full identity generation with options" {
    // Test passphrase-based generation
    const passphrase_options = shroud.IdentityGenerationOptions{
        .passphrase = "test-passphrase",
        .device_binding = false,
    };

    var identity = try shroud.generateIdentity(std.testing.allocator, passphrase_options);
    defer {
        std.testing.allocator.free(identity.id);
        identity.deinit();
    }

    // Should have metadata about generation method
    try std.testing.expect(std.mem.eql(u8, identity.getMetadata("generation_method").?, "passphrase"));
    try std.testing.expect(identity.getMetadata("qid") != null);

    // QID should be in metadata
    const qid_from_identity = identity.generateQID();
    try std.testing.expect(qid_from_identity.isValid());
}

test "device-aware access control" {
    var policy = shroud.DevicePolicy.init(std.testing.allocator);
    defer policy.deinit();

    const device = try shroud.generateDeviceFingerprint(std.testing.allocator);
    try policy.addDevice(device);
    policy.require_device_binding = true;
    policy.allow_new_devices = false;

    // Create device-aware access context
    var context = shroud.DeviceAccessContext.init(std.testing.allocator, "test-user", "/test/resource", .read);
    defer context.deinit();

    try context.addRole("viewer");
    context.setDeviceFingerprint(device);
    context.setDevicePolicy(&policy);

    // Device should be allowed
    try std.testing.expect(context.isDeviceAllowed());

    // Wrong device should not be allowed
    const wrong_device = shroud.DeviceFingerprint{ .bytes = [_]u8{0xFF} ** 32 };
    context.setDeviceFingerprint(wrong_device);
    try std.testing.expect(!context.isDeviceAllowed());
}
