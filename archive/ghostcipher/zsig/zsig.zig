//! Zsig: Cryptographic Signing Engine for Zig
//!
//! A lightweight and modular cryptographic signing library designed for fast, secure,
//! and minimalistic digital signature operations using Ed25519 signatures.
//!
//! ## Features
//! - Ed25519 signing and verification
//! - Public/private keypair generation
//! - Detached and inline signatures
//! - Deterministic signing for audit trails
//! - WASM and embedded-friendly
//! - No external C dependencies
//!
//! ## Basic Usage
//! ```zig
//! const zsig = @import("zsig");
//!
//! // Generate a keypair
//! const keypair = try zsig.Keypair.generate(allocator);
//!
//! // Sign a message
//! const message = "Hello, World!";
//! const signature = try zsig.sign(message, keypair);
//!
//! // Verify the signature
//! const is_valid = zsig.verify(message, &signature.bytes, &keypair.publicKey());
//! ```

const std = @import("std");

// Version and project metadata
pub const version = "0.4.0";
pub const info = struct {
    pub const name = "zsig";
    pub const description = "Cryptographic Signing Engine for Zig - GhostChain Foundation";
    pub const author = "GhostKellz";
    pub const license = "MIT";
    pub const repository = "https://github.com/ghostkellz/zsig";
};

// Re-export backend system
pub const backend = @import("zsig/backend.zig");

// Re-export core modules
pub const key = @import("zsig/key.zig");
pub const sign = @import("zsig/sign.zig");
pub const verify = @import("zsig/verify.zig");

// Re-export main types for convenience
pub const Keypair = key.Keypair;
pub const Signature = sign.Signature;
pub const VerificationResult = verify.VerificationResult;

// Re-export key constants
pub const PUBLIC_KEY_SIZE = key.PUBLIC_KEY_SIZE;
pub const PRIVATE_KEY_SIZE = key.PRIVATE_KEY_SIZE;
pub const SIGNATURE_SIZE = sign.SIGNATURE_SIZE;
pub const SEED_SIZE = key.SEED_SIZE;

// Re-export main functions for convenience
pub const generateKeypair = key.Keypair.generate;
pub const keypairFromSeed = key.Keypair.fromSeed;
pub const keypairFromPassphrase = key.Keypair.fromPassphrase;

/// Sign a message (convenience function)
pub const signMessage = sign.sign;
pub const signBytes = sign.signBytes;
pub const signInline = sign.signInline;
pub const signWithContext = sign.signWithContext;
pub const signBatch = sign.signBatch;
pub const signChallenge = sign.signChallenge;

/// Verify a signature (convenience function)
pub const verifySignature = verify.verify;
pub const verifyInline = verify.verifyInline;
pub const verifyWithContext = verify.verifyWithContext;
pub const verifyBatch = verify.verifyBatch;
pub const verifyChallenge = verify.verifyChallenge;
pub const verifyDetailed = verify.verifyDetailed;

/// Utility functions
pub const KeyDerivation = key.KeyDerivation;

test "zsig integration test" {
    const allocator = std.testing.allocator;

    // Test full signing and verification workflow
    const keypair = try generateKeypair(allocator);
    const message = "Integration test message";

    // Test basic signing
    const signature = try signMessage(message, keypair);
    try std.testing.expect(verifySignature(message, &signature.bytes, &keypair.publicKey()));

    // Test context signing
    const context = "test-context";
    const ctx_signature = try signWithContext(message, context, keypair);
    try std.testing.expect(verifyWithContext(message, context, &ctx_signature.bytes, &keypair.publicKey()));

    // Test inline signing
    const inline_sig = try signInline(allocator, message, keypair);
    defer allocator.free(inline_sig);
    try std.testing.expect(verifyInline(inline_sig, &keypair.publicKey()));

    // Test batch operations
    const messages = [_][]const u8{ "msg1", "msg2", "msg3" };
    const signatures = try signBatch(allocator, &messages, keypair);
    defer allocator.free(signatures);

    try std.testing.expect(verify.verifyBatchSameKey(&messages, signatures, keypair.publicKey()));
}

test "deterministic operations" {
    const allocator = std.testing.allocator;

    const seed = [_]u8{123} ** SEED_SIZE;
    const passphrase = "test passphrase for deterministic generation";

    // Test deterministic key generation
    const kp1 = keypairFromSeed(seed);
    const kp2 = keypairFromSeed(seed);
    try std.testing.expectEqualSlices(u8, &kp1.publicKey(), &kp2.publicKey());
    try std.testing.expectEqualSlices(u8, &kp1.secretKey(), &kp2.secretKey());

    // Test deterministic passphrase generation
    const kp3 = try keypairFromPassphrase(allocator, passphrase, "salt");
    const kp4 = try keypairFromPassphrase(allocator, passphrase, "salt");
    try std.testing.expectEqualSlices(u8, &kp3.publicKey(), &kp4.publicKey());
    try std.testing.expectEqualSlices(u8, &kp3.secretKey(), &kp4.secretKey());

    // Test deterministic signing
    const message = "deterministic signing test";
    const sig1 = try signMessage(message, kp1);
    const sig2 = try signMessage(message, kp2);
    try std.testing.expectEqualSlices(u8, &sig1.bytes, &sig2.bytes);
}

test "cross-module compatibility" {
    const allocator = std.testing.allocator;

    // Test that all modules work together correctly
    const keypair = try key.Keypair.generate(allocator);
    const message = "cross-module test";

    // Sign with sign module
    const signature = try sign.sign(message, keypair);

    // Verify with verify module
    try std.testing.expect(verify.verify(message, &signature.bytes, &keypair.publicKey()));

    // Test format conversions
    const sig_hex = try signature.toHex(allocator);
    defer allocator.free(sig_hex);

    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);

    try std.testing.expect(try verify.verifyFromHex(message, sig_hex, pub_hex));
}

/// Advanced printing function (keeping for compatibility)
pub fn advancedPrint() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Zsig v{s} - Cryptographic Signing Engine for Zig\n", .{version});
    try stdout.print("Features: Ed25519 signing, verification, key generation\n", .{});
    try stdout.print("Run `zig build test` to run the test suite.\n", .{});

    try bw.flush();
}
