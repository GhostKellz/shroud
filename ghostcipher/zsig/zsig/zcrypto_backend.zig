//! ZCrypto backend implementation for zsig
//! Provides Ed25519, secp256k1, and secp256r1 signature algorithms with HMAC authentication

const std = @import("std");
const zcrypto = @import("zcrypto");
const backend = @import("backend.zig");

/// Signature algorithm types supported by zcrypto backend
pub const SignatureAlgorithm = enum {
    ed25519,
    secp256k1,
    secp256r1,
};

/// Extended keypair supporting multiple signature algorithms
pub const ZCryptoKeypair = struct {
    algorithm: SignatureAlgorithm,
    ed25519_keypair: ?zcrypto.asym.Ed25519KeyPair = null,
    secp256k1_keypair: ?zcrypto.asym.Secp256k1KeyPair = null,
    secp256r1_keypair: ?zcrypto.asym.Secp256r1KeyPair = null,

    const Self = @This();

    /// Generate a new keypair for the specified algorithm
    pub fn generate(algorithm: SignatureAlgorithm) !Self {
        return switch (algorithm) {
            .ed25519 => Self{
                .algorithm = .ed25519,
                .ed25519_keypair = zcrypto.asym.ed25519.generate(),
            },
            .secp256k1 => Self{
                .algorithm = .secp256k1,
                .secp256k1_keypair = zcrypto.asym.secp256k1.generate(),
            },
            .secp256r1 => Self{
                .algorithm = .secp256r1,
                .secp256r1_keypair = zcrypto.asym.secp256r1.generate(),
            },
        };
    }

    /// Generate keypair from seed
    pub fn fromSeed(algorithm: SignatureAlgorithm, seed: [32]u8) !Self {
        return switch (algorithm) {
            .ed25519 => {
                // Create Ed25519 keypair from 32-byte seed
                const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidSeed;
                
                const ed25519_kp = zcrypto.asym.Ed25519KeyPair{
                    .public_key = key_pair.public_key.toBytes(),
                    .private_key = key_pair.secret_key.toBytes(),
                };
                
                return Self{
                    .algorithm = .ed25519,
                    .ed25519_keypair = ed25519_kp,
                };
            },
            .secp256k1 => {
                // For secp256k1, use the seed directly as private key
                const secret_key = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(seed) catch return error.InvalidSeed;
                const key_pair = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InvalidSeed;
                
                return Self{
                    .algorithm = .secp256k1,
                    .secp256k1_keypair = zcrypto.asym.Secp256k1KeyPair{
                        .public_key = key_pair.public_key.toCompressedSec1(),
                        .private_key = seed,
                    },
                };
            },
            .secp256r1 => {
                // For secp256r1, use the seed directly as private key
                const secret_key = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(seed) catch return error.InvalidSeed;
                const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InvalidSeed;
                
                return Self{
                    .algorithm = .secp256r1,
                    .secp256r1_keypair = zcrypto.asym.Secp256r1KeyPair{
                        .public_key = key_pair.public_key.toCompressedSec1(),
                        .private_key = seed,
                    },
                };
            },
        };
    }

    /// Get public key bytes (32 bytes for all algorithms)
    pub fn publicKey(self: *const Self) [32]u8 {
        return switch (self.algorithm) {
            .ed25519 => self.ed25519_keypair.?.public_key,
            .secp256k1 => self.secp256k1_keypair.?.public_key[0..32].*,  // secp256k1 compressed is 33 bytes, take first 32
            .secp256r1 => self.secp256r1_keypair.?.public_key[0..32].*,  // secp256r1 compressed is 33 bytes, take first 32
        };
    }

    /// Sign a message
    pub fn sign(self: *const Self, message: []const u8) [64]u8 {
        return switch (self.algorithm) {
            .ed25519 => self.ed25519_keypair.?.sign(message),
            .secp256k1 => {
                const hash = zcrypto.hash.sha256(message);
                return self.secp256k1_keypair.?.sign(hash);
            },
            .secp256r1 => {
                const hash = zcrypto.hash.sha256(message);
                return self.secp256r1_keypair.?.sign(hash);
            },
        };
    }

    /// Sign with HMAC authentication
    pub fn signWithHmac(self: *const Self, message: []const u8, hmac_key: []const u8) struct { signature: [64]u8, hmac_tag: [32]u8 } {
        const signature = self.sign(message);
        const hmac_tag = zcrypto.auth.hmac.sha256(message, hmac_key);
        return .{ .signature = signature, .hmac_tag = hmac_tag };
    }

    /// Verify signature
    pub fn verify(message: []const u8, signature: [64]u8, public_key: [32]u8, algorithm: SignatureAlgorithm) bool {
        return switch (algorithm) {
            .ed25519 => zcrypto.asym.ed25519.verify(message, signature, public_key),
            .secp256k1 => {
                const hash = zcrypto.hash.sha256(message);
                return zcrypto.asym.secp256k1.verify(hash, signature, public_key);
            },
            .secp256r1 => {
                const hash = zcrypto.hash.sha256(message);
                return zcrypto.asym.secp256r1.verify(hash, signature, public_key);
            },
        };
    }

    /// Verify signature with HMAC authentication
    pub fn verifyWithHmac(message: []const u8, signature: [64]u8, hmac_tag: [32]u8, public_key: [32]u8, hmac_key: []const u8, algorithm: SignatureAlgorithm) bool {
        // First verify HMAC
        const expected_tag = zcrypto.auth.hmac.sha256(message, hmac_key);
        if (!zcrypto.util.constantTimeCompare(&hmac_tag, &expected_tag)) {
            return false;
        }
        
        // Then verify signature
        return verify(message, signature, public_key, algorithm);
    }
};

/// ZCrypto implementation of CryptoInterface for Ed25519 (backward compatibility)
pub const ZCryptoInterface = struct {
    pub fn getInterface() backend.CryptoInterface {
        return backend.CryptoInterface{
            .generateKeypairFn = generateZCrypto,
            .keypairFromSeedFn = fromSeedZCrypto,
            .signFn = signZCrypto,
            .verifyFn = verifyZCrypto,
            .hashFn = hashZCrypto,
        };
    }

    fn generateZCrypto() backend.KeypairResult {
        const keypair = zcrypto.asym.ed25519.generate();
        return backend.KeypairResult{
            .public_key = keypair.public_key,
            .secret_key = keypair.private_key,
        };
    }

    fn fromSeedZCrypto(seed: [32]u8) backend.KeypairResult {
        // Create Ed25519 keypair from seed using Zig std crypto
        const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
            // Fallback to random generation if seed derivation fails
            return generateZCrypto();
        };
        
        return backend.KeypairResult{
            .public_key = key_pair.public_key.toBytes(),
            .secret_key = key_pair.secret_key.toBytes(),
        };
    }

    fn signZCrypto(message: []const u8, secret_key: [64]u8) [64]u8 {
        const ed25519_secret = std.crypto.sign.Ed25519.SecretKey.fromBytes(secret_key) catch unreachable;
        const ed25519_keypair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(ed25519_secret) catch unreachable;
        const signature = ed25519_keypair.sign(message, null) catch unreachable;
        return signature.toBytes();
    }

    fn verifyZCrypto(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        return zcrypto.asym.ed25519.verify(message, signature, public_key);
    }

    fn hashZCrypto(data: []const u8) [32]u8 {
        return zcrypto.hash.sha256(data);
    }
};

/// Multi-algorithm crypto interface for advanced usage
pub const MultiAlgorithmInterface = struct {
    default_algorithm: SignatureAlgorithm,

    pub fn init(default_algorithm: SignatureAlgorithm) MultiAlgorithmInterface {
        return MultiAlgorithmInterface{ .default_algorithm = default_algorithm };
    }

    pub fn generateKeypair(self: *const MultiAlgorithmInterface) !ZCryptoKeypair {
        return try ZCryptoKeypair.generate(self.default_algorithm);
    }

    pub fn generateKeypairWithAlgorithm(algorithm: SignatureAlgorithm) !ZCryptoKeypair {
        return try ZCryptoKeypair.generate(algorithm);
    }

    pub fn keypairFromSeed(self: *const MultiAlgorithmInterface, seed: [32]u8) !ZCryptoKeypair {
        return try ZCryptoKeypair.fromSeed(self.default_algorithm, seed);
    }

    pub fn keypairFromSeedWithAlgorithm(algorithm: SignatureAlgorithm, seed: [32]u8) !ZCryptoKeypair {
        return try ZCryptoKeypair.fromSeed(algorithm, seed);
    }
};

/// HMAC authentication utilities
pub const HmacAuth = struct {
    /// Generate HMAC authentication tag
    pub fn generateTag(message: []const u8, key: []const u8) [32]u8 {
        return zcrypto.auth.hmac.sha256(message, key);
    }

    /// Verify HMAC authentication tag
    pub fn verifyTag(message: []const u8, tag: [32]u8, key: []const u8) bool {
        const expected = zcrypto.auth.hmac.sha256(message, key);
        return zcrypto.util.constantTimeCompare(&tag, &expected);
    }

    /// Generate authentication key from passphrase
    pub fn keyFromPassphrase(allocator: std.mem.Allocator, passphrase: []const u8, salt: []const u8) ![32]u8 {
        return try zcrypto.kdf.hkdfSha256(allocator, passphrase, salt, "zsig-hmac-key", 32);
    }
};

/// Secure utilities using zcrypto
pub const SecureUtils = struct {
    /// Generate cryptographically secure random bytes
    pub fn generateSalt(size: usize) []u8 {
        return zcrypto.rand.generateSalt(size);
    }

    /// Generate cryptographically secure key
    pub fn generateKey(size: usize) []u8 {
        return zcrypto.rand.generateKey(size);
    }

    /// Secure memory clearing
    pub fn secureZero(data: []u8) void {
        zcrypto.util.secureZero(data);
    }

    /// Constant-time comparison
    pub fn constantTimeCompare(a: []const u8, b: []const u8) bool {
        return zcrypto.util.constantTimeCompare(a, b);
    }
};

test "zcrypto backend ed25519" {
    
    // Test Ed25519 keypair generation
    const keypair = try ZCryptoKeypair.generate(.ed25519);
    const message = "test message for ed25519";
    
    // Test signing and verification
    const signature = keypair.sign(message);
    const public_key = keypair.publicKey();
    
    try std.testing.expect(ZCryptoKeypair.verify(message, signature, public_key, .ed25519));
    
    // Test with different message (should fail)
    try std.testing.expect(!ZCryptoKeypair.verify("different message", signature, public_key, .ed25519));
}

test "zcrypto backend secp256k1" {
    
    // Test secp256k1 keypair generation
    const keypair = try ZCryptoKeypair.generate(.secp256k1);
    const message = "test message for secp256k1";
    
    // Test signing and verification
    const signature = keypair.sign(message);
    const public_key = keypair.publicKey();
    
    try std.testing.expect(ZCryptoKeypair.verify(message, signature, public_key, .secp256k1));
    
    // Test with different message (should fail)
    try std.testing.expect(!ZCryptoKeypair.verify("different message", signature, public_key, .secp256k1));
}

test "zcrypto backend secp256r1" {
    
    // Test secp256r1 keypair generation
    const keypair = try ZCryptoKeypair.generate(.secp256r1);
    const message = "test message for secp256r1";
    
    // Test signing and verification
    const signature = keypair.sign(message);
    const public_key = keypair.publicKey();
    
    try std.testing.expect(ZCryptoKeypair.verify(message, signature, public_key, .secp256r1));
    
    // Test with different message (should fail)
    try std.testing.expect(!ZCryptoKeypair.verify("different message", signature, public_key, .secp256r1));
}

test "hmac authentication" {
    
    const keypair = try ZCryptoKeypair.generate(.ed25519);
    const message = "authenticated message";
    const hmac_key = "secret-authentication-key";
    
    // Test signing with HMAC
    const auth_result = keypair.signWithHmac(message, hmac_key);
    const public_key = keypair.publicKey();
    
    // Verify with HMAC
    try std.testing.expect(ZCryptoKeypair.verifyWithHmac(
        message,
        auth_result.signature,
        auth_result.hmac_tag,
        public_key,
        hmac_key,
        .ed25519
    ));
    
    // Test with wrong HMAC key (should fail)
    try std.testing.expect(!ZCryptoKeypair.verifyWithHmac(
        message,
        auth_result.signature,
        auth_result.hmac_tag,
        public_key,
        "wrong-key",
        .ed25519
    ));
}

test "backward compatibility interface" {
    // Test that zcrypto interface works with existing backend system
    backend.setCryptoInterface(ZCryptoInterface.getInterface());
    
    const kp1 = try backend.Keypair.generate(std.testing.allocator);
    const message = "backward compatibility test";
    
    const signature = kp1.sign(message);
    try std.testing.expect(backend.Verifier.verify(message, signature, kp1.public_key));
}