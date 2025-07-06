//! Extended backend system for zsig with proper post-quantum support
//! Handles variable-sized keys correctly for zcrypto v0.5.0+ integration

const std = @import("std");
const zcrypto = @import("zcrypto");

/// Extended Keypair structure that handles variable-sized keys
pub const ExtendedKeypair = struct {
    algorithm: Algorithm,
    
    // Separate storage for different algorithms
    ed25519_keys: ?Ed25519Keys = null,
    ml_dsa_keys: ?MlDsaKeys = null,
    hybrid_keys: ?HybridKeys = null,
    
    const Ed25519Keys = struct {
        public_key: [32]u8,
        private_key: [32]u8,
    };
    
    const MlDsaKeys = struct {
        public_key: [1952]u8,  // ML_DSA_65.PUBLIC_KEY_SIZE
        private_key: [4016]u8, // ML_DSA_65.PRIVATE_KEY_SIZE
    };
    
    const HybridKeys = struct {
        classical_public: [32]u8,
        classical_private: [32]u8,
        pq_public: [1184]u8,   // ML_KEM_768.PUBLIC_KEY_SIZE
        pq_private: [2400]u8,  // ML_KEM_768.PRIVATE_KEY_SIZE
    };
    
    pub fn generate(allocator: std.mem.Allocator, algorithm: Algorithm) !ExtendedKeypair {
        return switch (algorithm) {
            .ed25519 => {
                const keypair = zcrypto.asym.ed25519.generate();
                return ExtendedKeypair{
                    .algorithm = .ed25519,
                    .ed25519_keys = Ed25519Keys{
                        .public_key = keypair.public_key,
                        .private_key = keypair.private_key,
                    },
                };
            },
            .ml_dsa_65 => {
                const pq_keypair = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator);
                return ExtendedKeypair{
                    .algorithm = .ml_dsa_65,
                    .ml_dsa_keys = MlDsaKeys{
                        .public_key = pq_keypair.public_key,
                        .private_key = pq_keypair.private_key,
                    },
                };
            },
            .hybrid_x25519_ml_kem => {
                const hybrid_keypair = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();
                return ExtendedKeypair{
                    .algorithm = .hybrid_x25519_ml_kem,
                    .hybrid_keys = HybridKeys{
                        .classical_public = hybrid_keypair.classical_public,
                        .classical_private = hybrid_keypair.classical_private,
                        .pq_public = hybrid_keypair.pq_public,
                        .pq_private = hybrid_keypair.pq_private,
                    },
                };
            },
        };
    }
    
    pub fn fromSeed(seed: [32]u8, algorithm: Algorithm) !ExtendedKeypair {
        return switch (algorithm) {
            .ed25519 => {
                const keypair = zcrypto.asym.ed25519.generateFromSeed(seed) catch {
                    // If generateFromSeed is not available, use regular generation
                    return error.SeedGenerationNotSupported;
                };
                return ExtendedKeypair{
                    .algorithm = .ed25519,
                    .ed25519_keys = Ed25519Keys{
                        .public_key = keypair.public_key,
                        .private_key = keypair.private_key,
                    },
                };
            },
            .ml_dsa_65 => {
                const pq_keypair = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generate(seed);
                return ExtendedKeypair{
                    .algorithm = .ml_dsa_65,
                    .ml_dsa_keys = MlDsaKeys{
                        .public_key = pq_keypair.public_key,
                        .private_key = pq_keypair.private_key,
                    },
                };
            },
            .hybrid_x25519_ml_kem => {
                // Hybrid algorithms don't support seed-based generation currently
                return error.SeedGenerationNotSupported;
            },
        };
    }
    
    pub fn sign(self: *const ExtendedKeypair, message: []const u8) !ExtendedSignature {
        return switch (self.algorithm) {
            .ed25519 => {
                const keys = self.ed25519_keys.?;
                const zcrypto_keypair = zcrypto.asym.ed25519.KeyPair{
                    .public_key = keys.public_key,
                    .private_key = keys.private_key,
                };
                const sig_bytes = try zcrypto_keypair.sign(message);
                return ExtendedSignature{
                    .algorithm = .ed25519,
                    .ed25519_sig = sig_bytes,
                };
            },
            .ml_dsa_65 => {
                const keys = self.ml_dsa_keys.?;
                const zcrypto_keypair = zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair{
                    .public_key = keys.public_key,
                    .private_key = keys.private_key,
                };
                
                var randomness: [32]u8 = undefined;
                std.crypto.random.bytes(&randomness);
                
                const sig_bytes = try zcrypto_keypair.sign(message, randomness);
                return ExtendedSignature{
                    .algorithm = .ml_dsa_65,
                    .ml_dsa_sig = sig_bytes,
                };
            },
            .hybrid_x25519_ml_kem => {
                // For hybrid, we could sign with the classical key
                // This is a simplified approach - full hybrid would combine both
                const keys = self.hybrid_keys.?;
                const classical_keypair = zcrypto.asym.ed25519.KeyPair{
                    .public_key = keys.classical_public,
                    .private_key = keys.classical_private,
                };
                const sig_bytes = try classical_keypair.sign(message);
                return ExtendedSignature{
                    .algorithm = .hybrid_x25519_ml_kem,
                    .ed25519_sig = sig_bytes, // Store as classical signature for now
                };
            },
        };
    }
    
    pub fn verify(self: *const ExtendedKeypair, message: []const u8, signature: ExtendedSignature) bool {
        if (self.algorithm != signature.algorithm) return false;
        
        return switch (self.algorithm) {
            .ed25519 => {
                const keys = self.ed25519_keys.?;
                const zcrypto_keypair = zcrypto.asym.ed25519.KeyPair{
                    .public_key = keys.public_key,
                    .private_key = undefined, // Not needed for verification
                };
                return zcrypto_keypair.verify(message, signature.ed25519_sig.?);
            },
            .ml_dsa_65 => {
                const keys = self.ml_dsa_keys.?;
                const is_valid = zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
                    keys.public_key, message, signature.ml_dsa_sig.?
                ) catch return false;
                return is_valid;
            },
            .hybrid_x25519_ml_kem => {
                // Simplified hybrid verification using classical component
                const keys = self.hybrid_keys.?;
                const classical_keypair = zcrypto.asym.ed25519.KeyPair{
                    .public_key = keys.classical_public,
                    .private_key = undefined,
                };
                return classical_keypair.verify(message, signature.ed25519_sig.?);
            },
        };
    }
    
    /// Get the public key in a standardized format for external storage/transmission
    pub fn getPublicKeyBytes(self: *const ExtendedKeypair, allocator: std.mem.Allocator) ![]u8 {
        return switch (self.algorithm) {
            .ed25519 => {
                const keys = self.ed25519_keys.?;
                return try allocator.dupe(u8, &keys.public_key);
            },
            .ml_dsa_65 => {
                const keys = self.ml_dsa_keys.?;
                return try allocator.dupe(u8, &keys.public_key);
            },
            .hybrid_x25519_ml_kem => {
                // For hybrid, concatenate classical + PQ public keys
                const keys = self.hybrid_keys.?;
                var combined = try allocator.alloc(u8, 32 + 1184);
                @memcpy(combined[0..32], &keys.classical_public);
                @memcpy(combined[32..], &keys.pq_public);
                return combined;
            },
        };
    }
};

/// Extended signature structure that handles variable-sized signatures
pub const ExtendedSignature = struct {
    algorithm: Algorithm,
    
    // Separate storage for different signature types
    ed25519_sig: ?[64]u8 = null,
    ml_dsa_sig: ?[3309]u8 = null, // ML_DSA_65.SIGNATURE_SIZE
    
    pub fn toHex(self: ExtendedSignature, allocator: std.mem.Allocator) ![]u8 {
        const sig_bytes = switch (self.algorithm) {
            .ed25519, .hybrid_x25519_ml_kem => &self.ed25519_sig.?,
            .ml_dsa_65 => &self.ml_dsa_sig.?,
        };
        return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(sig_bytes)});
    }
    
    pub fn toBase64(self: ExtendedSignature, allocator: std.mem.Allocator) ![]u8 {
        const sig_bytes = switch (self.algorithm) {
            .ed25519, .hybrid_x25519_ml_kem => &self.ed25519_sig.?,
            .ml_dsa_65 => &self.ml_dsa_sig.?,
        };
        
        const encoder = std.base64.standard.Encoder;
        const encoded_len = encoder.calcSize(sig_bytes.len);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, sig_bytes);
        return result;
    }
};

/// Algorithm enum (reuse from backend.zig)
pub const Algorithm = enum {
    ed25519,
    ml_dsa_65,
    hybrid_x25519_ml_kem,
    
    pub const default = Algorithm.ed25519;
};

/// Static verification function for external public keys
pub fn verifyWithPublicKey(
    message: []const u8,
    signature: ExtendedSignature,
    public_key_bytes: []const u8,
    algorithm: Algorithm
) bool {
    return switch (algorithm) {
        .ed25519 => {
            if (public_key_bytes.len != 32) return false;
            if (signature.ed25519_sig == null) return false;
            
            var public_key: [32]u8 = undefined;
            @memcpy(&public_key, public_key_bytes);
            
            const zcrypto_keypair = zcrypto.asym.ed25519.KeyPair{
                .public_key = public_key,
                .private_key = undefined,
            };
            return zcrypto_keypair.verify(message, signature.ed25519_sig.?);
        },
        .ml_dsa_65 => {
            if (public_key_bytes.len != 1952) return false;
            if (signature.ml_dsa_sig == null) return false;
            
            var public_key: [1952]u8 = undefined;
            @memcpy(&public_key, public_key_bytes);
            
            const is_valid = zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
                public_key, message, signature.ml_dsa_sig.?
            ) catch return false;
            return is_valid;
        },
        .hybrid_x25519_ml_kem => {
            // For hybrid, extract classical component and verify
            if (public_key_bytes.len < 32) return false;
            if (signature.ed25519_sig == null) return false;
            
            var classical_public: [32]u8 = undefined;
            @memcpy(&classical_public, public_key_bytes[0..32]);
            
            const zcrypto_keypair = zcrypto.asym.ed25519.KeyPair{
                .public_key = classical_public,
                .private_key = undefined,
            };
            return zcrypto_keypair.verify(message, signature.ed25519_sig.?);
        },
    };
}

test "extended backend Ed25519" {
    const allocator = std.testing.allocator;
    
    const keypair = try ExtendedKeypair.generate(allocator, .ed25519);
    const message = "test message for extended backend";
    
    const signature = try keypair.sign(message);
    try std.testing.expect(keypair.verify(message, signature));
    
    // Test public key extraction
    const pub_key_bytes = try keypair.getPublicKeyBytes(allocator);
    defer allocator.free(pub_key_bytes);
    
    try std.testing.expect(verifyWithPublicKey(message, signature, pub_key_bytes, .ed25519));
}

test "extended backend post-quantum" {
    const allocator = std.testing.allocator;
    
    // Test ML-DSA-65 if available
    const pq_keypair = ExtendedKeypair.generate(allocator, .ml_dsa_65) catch |err| switch (err) {
        error.UnsupportedAlgorithm => return, // Skip if not available
        else => return err,
    };
    
    const message = "post-quantum test message";
    const pq_signature = try pq_keypair.sign(message);
    try std.testing.expect(pq_keypair.verify(message, pq_signature));
    
    // Test public key extraction
    const pq_pub_key_bytes = try pq_keypair.getPublicKeyBytes(allocator);
    defer allocator.free(pq_pub_key_bytes);
    
    try std.testing.expect(verifyWithPublicKey(message, pq_signature, pq_pub_key_bytes, .ml_dsa_65));
}

test "extended backend hybrid" {
    const allocator = std.testing.allocator;
    
    // Test hybrid X25519+ML-KEM if available
    const hybrid_keypair = ExtendedKeypair.generate(allocator, .hybrid_x25519_ml_kem) catch |err| switch (err) {
        error.UnsupportedAlgorithm => return, // Skip if not available
        else => return err,
    };
    
    const message = "hybrid cryptography test";
    const hybrid_signature = try hybrid_keypair.sign(message);
    try std.testing.expect(hybrid_keypair.verify(message, hybrid_signature));
    
    // Test public key extraction
    const hybrid_pub_key_bytes = try hybrid_keypair.getPublicKeyBytes(allocator);
    defer allocator.free(hybrid_pub_key_bytes);
    
    try std.testing.expect(verifyWithPublicKey(message, hybrid_signature, hybrid_pub_key_bytes, .hybrid_x25519_ml_kem));
}
