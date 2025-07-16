//! Key generation and management for Ed25519 cryptographic operations
//! Supports deterministic key derivation, secure memory handling, and multiple output formats
//! Uses pluggable crypto backends for enhanced flexibility

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;
const base64 = std.base64;
const backend = @import("backend.zig");

/// Ed25519 public key size in bytes
pub const PUBLIC_KEY_SIZE = 32;

/// Ed25519 private key size in bytes (includes public key)
pub const PRIVATE_KEY_SIZE = 64;

/// Ed25519 seed size for key generation
pub const SEED_SIZE = 32;

/// Keypair structure containing both public and private keys
pub const Keypair = struct {
    /// Backend keypair implementation
    inner: backend.Keypair,

    const Self = @This();

/// Generate a new random keypair using the system's CSPRNG
    pub fn generate(allocator: std.mem.Allocator) !Self {
        const inner = try backend.generateKeypairDefault(allocator);
        return Self{ .inner = inner };
    }

    /// Generate a keypair with specific algorithm
    pub fn generateWithAlgorithm(allocator: std.mem.Allocator, algo: backend.Algorithm) !Self {
        const inner = try backend.generateKeypair(allocator, algo);
        return Self{ .inner = inner };
    }

    /// Generate a keypair from a 32-byte seed (deterministic)
    pub fn fromSeed(seed: [SEED_SIZE]u8) Self {
        const inner = backend.keypairFromSeedDefault(seed);
        return Self{ .inner = inner };
    }

    /// Generate a keypair from seed with specific algorithm
    pub fn fromSeedWithAlgorithm(seed: [SEED_SIZE]u8, algo: backend.Algorithm) Self {
        const inner = backend.keypairFromSeed(seed, algo);
        return Self{ .inner = inner };
    }

    /// Generate a keypair from a passphrase using PBKDF2 (brain wallet style)
    pub fn fromPassphrase(allocator: std.mem.Allocator, passphrase: []const u8, salt: ?[]const u8) !Self {
        _ = allocator;
        const actual_salt = salt orelse "zsig-default-salt";

        var seed: [SEED_SIZE]u8 = undefined;
        try crypto.pwhash.pbkdf2(&seed, passphrase, actual_salt, 100000, crypto.auth.hmac.sha2.HmacSha256);

        return fromSeed(seed);
    }

    /// Generate a keypair from passphrase with specific algorithm
    pub fn fromPassphraseWithAlgorithm(allocator: std.mem.Allocator, passphrase: []const u8, salt: ?[]const u8, algo: backend.Algorithm) !Self {
        _ = allocator;
        const actual_salt = salt orelse "zsig-default-salt";

        var seed: [SEED_SIZE]u8 = undefined;
        try crypto.pwhash.pbkdf2(&seed, passphrase, actual_salt, 100000, crypto.auth.hmac.sha2.HmacSha256);

        return fromSeedWithAlgorithm(seed, algo);
    }

    /// Get the algorithm used by this keypair
    pub fn algorithm(self: Self) backend.Algorithm {
        return self.inner.algorithm;
    }

    /// Get public key bytes
    pub fn publicKey(self: *const Self) [PUBLIC_KEY_SIZE]u8 {
        return self.inner.public_key;
    }

    /// Get secret key bytes
    pub fn secretKey(self: *const Self) [PRIVATE_KEY_SIZE]u8 {
        return self.inner.private_key;
    }

    /// Export public key as hex string
    pub fn publicKeyHex(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return try fmt.allocPrint(allocator, "{}", .{fmt.fmtSliceHexLower(&self.inner.public_key)});
    }

    /// Export private key as base64 (includes both private and public key)
    pub fn privateKeyBase64(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const encoder = base64.standard.Encoder;
        const encoded_len = encoder.calcSize(PRIVATE_KEY_SIZE);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, &self.inner.private_key);
        return result;
    }

    /// Export keypair as a bundle (for .key files)
    pub fn exportBundle(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const private_b64 = try self.privateKeyBase64(allocator);
        defer allocator.free(private_b64);

        const public_hex = try self.publicKeyHex(allocator);
        defer allocator.free(public_hex);

        return try fmt.allocPrint(allocator, "-----BEGIN ZSIG KEYPAIR-----\n" ++
            "Private: {s}\n" ++
            "Public: {s}\n" ++
            "-----END ZSIG KEYPAIR-----\n", .{ private_b64, public_hex });
    }

    /// Import keypair from base64 private key
    pub fn fromPrivateKeyBase64(private_key_b64: []const u8) !Self {
        const decoder = base64.standard.Decoder;
        var secret_key: [PRIVATE_KEY_SIZE]u8 = undefined;

        try decoder.decode(&secret_key, private_key_b64);

        return Self{
            .inner = backend.Keypair{
                .public_key = secret_key[32..64].*,
                .private_key = secret_key,
                .algorithm = .ed25519, // Default to Ed25519 for backwards compatibility
            },
        };
    }

    /// Import public key from hex string
    pub fn publicKeyFromHex(hex_string: []const u8) ![PUBLIC_KEY_SIZE]u8 {
        var public_key: [PUBLIC_KEY_SIZE]u8 = undefined;
        _ = try fmt.hexToBytes(&public_key, hex_string);
        return public_key;
    }

    /// Securely zero out private key material
    pub fn zeroize(self: *Self) void {
        crypto.utils.secureZero(u8, &self.inner.private_key);
    }

    /// Sign a message using this keypair
    pub fn sign(self: *const Self, message: []const u8) ![64]u8 {
        return self.inner.sign(message);
    }

    /// Sign a message with additional context
    pub fn signWithContext(self: *const Self, message: []const u8, context: []const u8) ![64]u8 {
        return self.inner.signWithContext(message, context);
    }
};

/// Key derivation utilities for HD wallet support
pub const KeyDerivation = struct {
    /// Derive child key from parent using a simple path (non-BIP32 for now)
    pub fn deriveChild(parent: Keypair, index: u32) Keypair {
        var hasher = crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&parent.inner.private_key);
        hasher.update(mem.asBytes(&index));

        var child_seed: [SEED_SIZE]u8 = undefined;
        hasher.final(&child_seed);

        return Keypair.fromSeed(child_seed);
    }
};

test "keypair generation" {
    const allocator = std.testing.allocator;

    // Test random generation
    const kp1 = try Keypair.generate(allocator);
    const kp2 = try Keypair.generate(allocator);

    // Keys should be different
    try std.testing.expect(!mem.eql(u8, &kp1.publicKey(), &kp2.publicKey()));
    try std.testing.expect(!mem.eql(u8, &kp1.secretKey(), &kp2.secretKey()));
}

test "deterministic generation from seed" {
    const seed = [_]u8{1} ** 32;

    const kp1 = Keypair.fromSeed(seed);
    const kp2 = Keypair.fromSeed(seed);

    // Should be identical
    try std.testing.expectEqualSlices(u8, &kp1.publicKey(), &kp2.publicKey());
    try std.testing.expectEqualSlices(u8, &kp1.secretKey(), &kp2.secretKey());
}

test "passphrase generation" {
    const allocator = std.testing.allocator;

    const kp1 = try Keypair.fromPassphrase(allocator, "test passphrase", "salt123");
    const kp2 = try Keypair.fromPassphrase(allocator, "test passphrase", "salt123");

    // Should be deterministic
    try std.testing.expectEqualSlices(u8, &kp1.publicKey(), &kp2.publicKey());
    try std.testing.expectEqualSlices(u8, &kp1.secretKey(), &kp2.secretKey());
}

test "export and import" {
    const allocator = std.testing.allocator;

    const original = try Keypair.generate(allocator);

    // Test base64 export/import
    const private_b64 = try original.privateKeyBase64(allocator);
    defer allocator.free(private_b64);

    const imported = try Keypair.fromPrivateKeyBase64(private_b64);

    try std.testing.expectEqualSlices(u8, &original.publicKey(), &imported.publicKey());
    try std.testing.expectEqualSlices(u8, &original.secretKey(), &imported.secretKey());

    // Test hex public key
    const public_hex = try original.publicKeyHex(allocator);
    defer allocator.free(public_hex);

    const public_from_hex = try Keypair.publicKeyFromHex(public_hex);
    try std.testing.expectEqualSlices(u8, &original.publicKey(), &public_from_hex);
}
