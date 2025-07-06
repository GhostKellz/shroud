//! Ed25519 signature verification with support for detached and inline signatures
//! Provides fast verification for audit trails and batch operations

const std = @import("std");
const crypto = std.crypto;
const key = @import("key.zig");
const sign = @import("sign.zig");
const backend = @import("backend.zig");

/// Verify a detached signature against a message and public key
pub fn verify(message: []const u8, signature: []const u8, public_key: []const u8) bool {
    if (signature.len != sign.SIGNATURE_SIZE) return false;
    if (public_key.len != key.PUBLIC_KEY_SIZE) return false;

    const pub_key_bytes: [key.PUBLIC_KEY_SIZE]u8 = public_key[0..key.PUBLIC_KEY_SIZE].*;
    const sig_bytes: [sign.SIGNATURE_SIZE]u8 = signature[0..sign.SIGNATURE_SIZE].*;

    // Default to Ed25519 for backwards compatibility
    return backend.verify(message, sig_bytes, pub_key_bytes, .ed25519);
}

/// Verify using Signature and Keypair structs
pub fn verifySignature(message: []const u8, signature: sign.Signature, public_key: [key.PUBLIC_KEY_SIZE]u8) bool {
    // Default to Ed25519 for backwards compatibility
    return backend.verify(message, signature.bytes, public_key, .ed25519);
}

/// Verify using a keypair (uses public key part and algorithm)
pub fn verifyWithKeypair(message: []const u8, signature: sign.Signature, keypair: key.Keypair) bool {
    // Use the algorithm from the keypair
    return backend.verifyWithKeypairAlgorithm(message, signature.bytes, keypair);
}

/// Verify an inline signature (message + signature concatenated)
pub fn verifyInline(signed_message: []const u8, public_key: []const u8) bool {
    if (signed_message.len < sign.SIGNATURE_SIZE) return false;

    const message_len = signed_message.len - sign.SIGNATURE_SIZE;
    const message = signed_message[0..message_len];
    const signature = signed_message[message_len..];

    return verify(message, signature, public_key);
}

/// Extract message from inline signature without verification
pub fn extractMessage(signed_message: []const u8) []const u8 {
    if (signed_message.len < sign.SIGNATURE_SIZE) return signed_message;
    return signed_message[0 .. signed_message.len - sign.SIGNATURE_SIZE];
}

/// Extract signature from inline signature
pub fn extractSignature(signed_message: []const u8) ?[]const u8 {
    if (signed_message.len < sign.SIGNATURE_SIZE) return null;
    const message_len = signed_message.len - sign.SIGNATURE_SIZE;
    return signed_message[message_len..];
}

/// Verify with additional context (domain separation) - must match signing context
pub fn verifyWithContext(message: []const u8, context: []const u8, signature: []const u8, public_key: []const u8) bool {
    // Recreate the domain-separated hash
    var hasher = crypto.hash.blake2.Blake2b256.init(.{});
    hasher.update(context);
    hasher.update(message);

    var domain_separated_hash: [32]u8 = undefined;
    hasher.final(&domain_separated_hash);

    return verify(&domain_separated_hash, signature, public_key);
}

/// Batch verification for multiple signatures (more efficient than individual verification)
pub fn verifyBatch(messages: []const []const u8, signatures: []const sign.Signature, public_keys: []const [key.PUBLIC_KEY_SIZE]u8) bool {
    if (messages.len != signatures.len or messages.len != public_keys.len) {
        return false;
    }

    // Verify each signature individually
    // Note: Ed25519 batch verification is complex to implement correctly,
    // so we use individual verification for now
    for (messages, signatures, public_keys) |message, signature, public_key| {
        if (!verify(message, &signature.bytes, &public_key)) {
            return false;
        }
    }

    return true;
}

/// Verify signatures with same public key (common case for transaction batches)
pub fn verifyBatchSameKey(messages: []const []const u8, signatures: []const sign.Signature, public_key: [key.PUBLIC_KEY_SIZE]u8) bool {
    for (messages, signatures) |message, signature| {
        if (!verify(message, &signature.bytes, &public_key)) {
            return false;
        }
    }
    return true;
}

/// Verify HMAC-style challenge signature
pub fn verifyChallenge(challenge: []const u8, signature: []const u8, public_key: []const u8) bool {
    const context = "zsig-challenge-v1";
    return verifyWithContext(challenge, context, signature, public_key);
}

/// Verify from hex-encoded signature and public key
pub fn verifyFromHex(message: []const u8, signature_hex: []const u8, public_key_hex: []const u8) !bool {
    const signature = try sign.Signature.fromHex(signature_hex);
    const public_key = try key.Keypair.publicKeyFromHex(public_key_hex);

    return verify(message, &signature.bytes, &public_key);
}

/// Verify from base64-encoded signature
pub fn verifyFromBase64(message: []const u8, signature_b64: []const u8, public_key_hex: []const u8) !bool {
    const signature = try sign.Signature.fromBase64(signature_b64);
    const public_key = try key.Keypair.publicKeyFromHex(public_key_hex);

    return verify(message, &signature.bytes, &public_key);
}

/// Comprehensive verification result with detailed information
pub const VerificationResult = struct {
    valid: bool,
    error_type: ?VerificationError = null,
    message: ?[]const u8 = null,

    pub const VerificationError = enum {
        invalid_signature_length,
        invalid_public_key_length,
        signature_verification_failed,
        malformed_inline_signature,
        context_mismatch,
    };
};

/// Comprehensive verification with detailed error reporting
pub fn verifyDetailed(message: []const u8, signature: []const u8, public_key: []const u8) VerificationResult {
    if (signature.len != sign.SIGNATURE_SIZE) {
        return VerificationResult{
            .valid = false,
            .error_type = .invalid_signature_length,
            .message = "Signature must be exactly 64 bytes",
        };
    }

    if (public_key.len != key.PUBLIC_KEY_SIZE) {
        return VerificationResult{
            .valid = false,
            .error_type = .invalid_public_key_length,
            .message = "Public key must be exactly 32 bytes",
        };
    }

    const is_valid = verify(message, signature, public_key);
    if (!is_valid) {
        return VerificationResult{
            .valid = false,
            .error_type = .signature_verification_failed,
            .message = "Cryptographic signature verification failed",
        };
    }

    return VerificationResult{ .valid = true };
}

test "basic verification" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "Hello, Zsig verification!";

    const signature = try sign.sign(message, keypair);

    // Should verify successfully
    try std.testing.expect(verify(message, &signature.bytes, &keypair.publicKey()));

    // Should fail with wrong message
    try std.testing.expect(!verify("Wrong message", &signature.bytes, &keypair.publicKey()));

    // Should fail with wrong public key
    const wrong_keypair = try key.Keypair.generate(allocator);
    try std.testing.expect(!verify(message, &signature.bytes, &wrong_keypair.publicKey()));
}

test "inline signature verification" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "inline verification test";

    const inline_sig = try sign.signInline(allocator, message, keypair);
    defer allocator.free(inline_sig);

    // Should verify successfully
    try std.testing.expect(verifyInline(inline_sig, &keypair.publicKey()));

    // Extract message should work
    const extracted = extractMessage(inline_sig);
    try std.testing.expectEqualSlices(u8, message, extracted);
}

test "context verification" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "context verification test";
    const context = "test-context-v1";

    const signature = try sign.signWithContext(message, context, keypair);

    // Should verify with correct context
    try std.testing.expect(verifyWithContext(message, context, &signature.bytes, &keypair.publicKey()));

    // Should fail with wrong context
    try std.testing.expect(!verifyWithContext(message, "wrong-context", &signature.bytes, &keypair.publicKey()));

    // Should fail with no context
    try std.testing.expect(!verify(message, &signature.bytes, &keypair.publicKey()));
}

test "batch verification" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const messages = [_][]const u8{ "msg1", "msg2", "msg3" };

    const signatures = try sign.signBatch(allocator, &messages, keypair);
    defer allocator.free(signatures);

    // Create public key array
    const public_keys = [_][key.PUBLIC_KEY_SIZE]u8{ keypair.publicKey(), keypair.publicKey(), keypair.publicKey() };

    // Should verify all signatures
    try std.testing.expect(verifyBatch(&messages, signatures, &public_keys));
    try std.testing.expect(verifyBatchSameKey(&messages, signatures, keypair.publicKey()));

    // Should fail if one signature is wrong
    var bad_signatures = try allocator.dupe(sign.Signature, signatures);
    defer allocator.free(bad_signatures);
    bad_signatures[1].bytes[0] ^= 1; // Corrupt one signature

    try std.testing.expect(!verifyBatch(&messages, bad_signatures, &public_keys));
    try std.testing.expect(!verifyBatchSameKey(&messages, bad_signatures, keypair.publicKey()));
}

test "challenge verification" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const challenge = "authentication-challenge-123";

    const signature = try sign.signChallenge(challenge, keypair);

    // Should verify with challenge verification function
    try std.testing.expect(verifyChallenge(challenge, &signature.bytes, &keypair.publicKey()));

    // Should fail with regular verification (different context)
    try std.testing.expect(!verify(challenge, &signature.bytes, &keypair.publicKey()));
}

test "format verification" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "format test";

    const signature = try sign.sign(message, keypair);

    // Test hex format verification
    const sig_hex = try signature.toHex(allocator);
    defer allocator.free(sig_hex);

    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);

    try std.testing.expect(try verifyFromHex(message, sig_hex, pub_hex));

    // Test base64 format verification
    const sig_b64 = try signature.toBase64(allocator);
    defer allocator.free(sig_b64);

    try std.testing.expect(try verifyFromBase64(message, sig_b64, pub_hex));
}

test "detailed verification" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "detailed verification test";

    const signature = try sign.sign(message, keypair);

    // Valid signature
    const result1 = verifyDetailed(message, &signature.bytes, &keypair.publicKey());
    try std.testing.expect(result1.valid);
    try std.testing.expect(result1.error_type == null);

    // Invalid signature length
    const result2 = verifyDetailed(message, signature.bytes[0..32], &keypair.publicKey());
    try std.testing.expect(!result2.valid);
    try std.testing.expect(result2.error_type == .invalid_signature_length);

    // Invalid public key length
    const result3 = verifyDetailed(message, &signature.bytes, keypair.publicKey()[0..16]);
    try std.testing.expect(!result3.valid);
    try std.testing.expect(result3.error_type == .invalid_public_key_length);
}
