//! Sigil: Zero-Trust Identity Framework (formerly RealID)
//! Migrated to Shroud v1.0 modular architecture
const std = @import("std");
const testing = std.testing;

// Export all Sigil modules
pub const types = @import("types.zig");
pub const core = @import("core.zig");
pub const sign = @import("sign.zig");
pub const qid = @import("qid.zig");
pub const fingerprint = @import("fingerprint.zig");
pub const ffi = @import("ffi.zig");

// Re-export main types for convenience (legacy compatibility)
pub const RealIDKeyPair = types.RealIDKeyPair;
pub const RealIDPrivateKey = types.RealIDPrivateKey;
pub const RealIDPublicKey = types.RealIDPublicKey;
pub const RealIDSignature = types.RealIDSignature;
pub const QID = types.QID;
pub const DeviceFingerprint = types.DeviceFingerprint;
pub const RealIDError = types.RealIDError;

pub const SigilError = error{
    InvalidIdentity,
    ResolutionFailed,
    AuthenticationFailed,
};

// Re-export main functions for convenience
pub const realid_generate_from_passphrase = core.realid_generate_from_passphrase;
pub const realid_generate_from_passphrase_with_device = core.realid_generate_from_passphrase_with_device;
pub const realid_sign = sign.realid_sign;
pub const realid_verify = sign.realid_verify;
pub const realid_qid_from_pubkey = qid.realid_qid_from_pubkey;
pub const generate_device_fingerprint = fingerprint.generate_device_fingerprint;

test "basic keypair generation" {
    const keypair = try realid_generate_from_passphrase("test_passphrase_123");
    
    // Verify that keys are generated (Ed25519 private key is 64 bytes, public key is 32 bytes)
    try testing.expect(keypair.private_key.bytes.len == 64);
    try testing.expect(keypair.public_key.bytes.len == 32);
}

test "signing and verification" {
    const keypair = try realid_generate_from_passphrase("test_passphrase_123");
    const test_data = "Hello, RealID!";

    // Sign the data
    const signature = try realid_sign(test_data, keypair.private_key);

    // Verify the signature
    const is_valid = realid_verify(signature, test_data, keypair.public_key);
    try testing.expect(is_valid);

    // Test with invalid data
    const is_invalid = realid_verify(signature, "Different data", keypair.public_key);
    try testing.expect(!is_invalid);
}

test "QID generation" {
    const keypair = try realid_generate_from_passphrase("test_passphrase_123");
    const qid_result = realid_qid_from_pubkey(keypair.public_key);

    // QID should be 16 bytes (IPv6 address)
    try testing.expect(qid_result.bytes.len == 16);

    // Should have the correct RealID prefix (fd00)
    try testing.expect(qid_result.bytes[0] == 0xfd);
    try testing.expect(qid_result.bytes[1] == 0x00);
}

test "device fingerprint generation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const fingerprint1 = try generate_device_fingerprint(allocator);
    const fingerprint2 = try generate_device_fingerprint(allocator);

    // Fingerprints should be deterministic on the same system
    try testing.expect(std.mem.eql(u8, &fingerprint1.bytes, &fingerprint2.bytes));
}
