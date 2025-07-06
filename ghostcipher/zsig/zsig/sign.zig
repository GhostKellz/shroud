//! Ed25519 signature generation with support for detached and inline signatures
//! Provides deterministic signing for audit trails and WASM compatibility

const std = @import("std");
const crypto = std.crypto;
const key = @import("key.zig");

/// Ed25519 signature size in bytes
pub const SIGNATURE_SIZE = 64;

/// Signature structure containing the 64-byte Ed25519 signature
pub const Signature = struct {
    bytes: [SIGNATURE_SIZE]u8,

    const Self = @This();

    /// Convert signature to hex string
    pub fn toHex(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
    }

    /// Parse signature from hex string
    pub fn fromHex(hex_string: []const u8) !Self {
        if (hex_string.len != SIGNATURE_SIZE * 2) {
            return error.InvalidSignatureLength;
        }

        var signature = Self{ .bytes = undefined };
        _ = try std.fmt.hexToBytes(&signature.bytes, hex_string);
        return signature;
    }

    /// Convert to base64 for text formats
    pub fn toBase64(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const encoder = std.base64.standard.Encoder;
        const encoded_len = encoder.calcSize(SIGNATURE_SIZE);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, &self.bytes);
        return result;
    }

    /// Parse signature from base64
    pub fn fromBase64(b64_string: []const u8) !Self {
        const decoder = std.base64.standard.Decoder;
        var signature = Self{ .bytes = undefined };
        try decoder.decode(&signature.bytes, b64_string);
        return signature;
    }
};

/// Sign a message using Ed25519 (detached signature)
pub fn sign(message: []const u8, keypair: key.Keypair) !Signature {
    const signature_bytes = try keypair.sign(message);
    return Signature{ .bytes = signature_bytes };
}

/// Sign a message and return raw bytes
pub fn signBytes(message: []const u8, keypair: key.Keypair) ![SIGNATURE_SIZE]u8 {
    return try keypair.sign(message);
}

/// Create an inline signature (message + signature concatenated)
pub fn signInline(allocator: std.mem.Allocator, message: []const u8, keypair: key.Keypair) ![]u8 {
    const signature = try sign(message, keypair);

    const result = try allocator.alloc(u8, message.len + SIGNATURE_SIZE);
    @memcpy(result[0..message.len], message);
    @memcpy(result[message.len..], &signature.bytes);

    return result;
}

/// Sign with additional context (domain separation)
pub fn signWithContext(message: []const u8, context: []const u8, keypair: key.Keypair) !Signature {
    const signature_bytes = try keypair.signWithContext(message, context);
    return Signature{ .bytes = signature_bytes };
}

/// Batch signing for multiple messages (useful for transaction batches)
pub fn signBatch(allocator: std.mem.Allocator, messages: []const []const u8, keypair: key.Keypair) ![]Signature {
    var signatures = try allocator.alloc(Signature, messages.len);

    for (messages, 0..) |message, i| {
        signatures[i] = try sign(message, keypair);
    }

    return signatures;
}

/// Deterministic nonce generation for reproducible signatures (useful for testing)
pub fn signDeterministic(message: []const u8, keypair: key.Keypair, nonce_context: []const u8) !Signature {
    // Ed25519 is already deterministic, but we can add additional context
    return signWithContext(message, nonce_context, keypair);
}

/// HMAC-style challenge signing for CLI workflows
pub fn signChallenge(challenge: []const u8, keypair: key.Keypair) !Signature {
    const context = "zsig-challenge-v1";
    return signWithContext(challenge, context, keypair);
}

test "basic signing" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "Hello, Zsig!";

    const signature = try sign(message, keypair);
    try std.testing.expect(signature.bytes.len == SIGNATURE_SIZE);
}

test "deterministic signing" {
    const seed = [_]u8{42} ** 32;
    const keypair = key.Keypair.fromSeed(seed);
    const message = "deterministic test";

    const sig1 = try sign(message, keypair);
    const sig2 = try sign(message, keypair);

    // Ed25519 signatures should be deterministic
    try std.testing.expectEqualSlices(u8, &sig1.bytes, &sig2.bytes);
}

test "signature formats" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "format test";

    const signature = try sign(message, keypair);

    // Test hex conversion
    const hex = try signature.toHex(allocator);
    defer allocator.free(hex);

    const from_hex = try Signature.fromHex(hex);
    try std.testing.expectEqualSlices(u8, &signature.bytes, &from_hex.bytes);

    // Test base64 conversion
    const b64 = try signature.toBase64(allocator);
    defer allocator.free(b64);

    const from_b64 = try Signature.fromBase64(b64);
    try std.testing.expectEqualSlices(u8, &signature.bytes, &from_b64.bytes);
}

test "inline signature" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "inline test";

    const inline_sig = try signInline(allocator, message, keypair);
    defer allocator.free(inline_sig);

    // Should contain message + signature
    try std.testing.expect(inline_sig.len == message.len + SIGNATURE_SIZE);
    try std.testing.expectEqualSlices(u8, message, inline_sig[0..message.len]);
}

test "context signing" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const message = "context test";
    const context1 = "context1";
    const context2 = "context2";

    const sig1 = try signWithContext(message, context1, keypair);
    const sig2 = try signWithContext(message, context2, keypair);

    // Different contexts should produce different signatures
    try std.testing.expect(!std.mem.eql(u8, &sig1.bytes, &sig2.bytes));
}

test "batch signing" {
    const allocator = std.testing.allocator;

    const keypair = try key.Keypair.generate(allocator);
    const messages = [_][]const u8{ "msg1", "msg2", "msg3" };

    const signatures = try signBatch(allocator, &messages, keypair);
    defer allocator.free(signatures);

    try std.testing.expect(signatures.len == messages.len);

    // Each signature should be valid (we'll verify in verify.zig tests)
    for (signatures) |signature| {
        try std.testing.expect(signature.bytes.len == SIGNATURE_SIZE);
    }
}
