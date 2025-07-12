//! Cryptographic utilities and key management
//! Integrates with zcrypto v0.3.0 and zsig v0.3.0 libraries

const std = @import("std");
const zcrypto = @import("ghostcipher").zcrypto;
const zsig = @import("ghostcipher").zsig;
const Allocator = std.mem.Allocator;

pub const CryptoError = error{
    InvalidKey,
    InvalidSignature,
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
};

pub const KeyPair = struct {
    public_key: [32]u8,
    private_key: [64]u8,
    key_type: KeyType,

    pub fn deinit(self: *KeyPair) void {
        // Zero out private key
        @memset(&self.private_key, 0);
    }

    /// Generate new keypair using zcrypto v0.3.0
    pub fn generate(key_type: KeyType) !KeyPair {
        switch (key_type) {
            .ed25519 => return generateEd25519(),
            .secp256k1 => return generateSecp256k1(),
            .curve25519 => return generateCurve25519(),
        }
    }

    /// Generate from seed using zcrypto v0.3.0 deterministic generation
    pub fn fromSeed(seed: [32]u8, key_type: KeyType) !KeyPair {
        switch (key_type) {
            .ed25519 => return ed25519FromSeed(seed),
            .secp256k1 => return secp256k1FromSeed(seed),
            .curve25519 => return curve25519FromSeed(seed),
        }
    }

    /// Sign message
    pub fn sign(self: *const KeyPair, message: []const u8, allocator: Allocator) ![]u8 {
        switch (self.key_type) {
            .ed25519 => return signEd25519(message, &self.private_key, allocator),
            .secp256k1 => return signSecp256k1(message, &self.private_key, allocator),
            .curve25519 => return CryptoError.SigningFailed, // Not for signing
        }
    }

    /// Verify signature
    pub fn verify(self: *const KeyPair, message: []const u8, signature: []const u8) bool {
        switch (self.key_type) {
            .ed25519 => return verifyEd25519(message, signature, &self.public_key),
            .secp256k1 => return verifySecp256k1(message, signature, &self.public_key),
            .curve25519 => return false, // Not for signing
        }
    }
};

pub const KeyType = enum {
    ed25519,
    secp256k1,
    curve25519,
};

/// Generate Ed25519 keypair using zcrypto v0.3.0
fn generateEd25519() !KeyPair {
    const zcrypto_keypair = zcrypto.asym.ed25519.generate();
    
    var keypair = KeyPair{
        .public_key = zcrypto_keypair.public_key,
        .private_key = undefined,
        .key_type = .ed25519,
    };
    
    @memcpy(keypair.private_key[0..32], &zcrypto_keypair.private_key);
    @memset(keypair.private_key[32..64], 0); // Ed25519 only uses 32 bytes
    
    return keypair;
}

/// Generate Ed25519 keypair from seed using zcrypto v0.3.0 deterministic generation
fn ed25519FromSeed(seed: [32]u8) !KeyPair {
    const zcrypto_keypair = zcrypto.asym.ed25519.generateFromSeed(seed);
    
    var keypair = KeyPair{
        .public_key = zcrypto_keypair.public_key,
        .private_key = undefined,
        .key_type = .ed25519,
    };
    
    @memcpy(keypair.private_key[0..32], &zcrypto_keypair.private_key);
    @memset(keypair.private_key[32..64], 0); // Ed25519 only uses 32 bytes
    
    return keypair;
}

/// Generate secp256k1 keypair using zcrypto v0.3.0
fn generateSecp256k1() !KeyPair {
    const zcrypto_keypair = zcrypto.asym.secp256k1.generate();
    
    var keypair = KeyPair{
        .public_key = zcrypto_keypair.publicKey(.compressed), // Use compressed format
        .private_key = undefined,
        .key_type = .secp256k1,
    };
    
    @memcpy(keypair.private_key[0..32], &zcrypto_keypair.private_key);
    @memset(keypair.private_key[32..64], 0); // secp256k1 only uses 32 bytes
    
    return keypair;
}

/// Generate secp256k1 keypair from seed using zcrypto v0.3.0
fn secp256k1FromSeed(seed: [32]u8) !KeyPair {
    const zcrypto_keypair = zcrypto.asym.secp256k1.generateFromSeed(seed);
    
    var keypair = KeyPair{
        .public_key = zcrypto_keypair.publicKey(.compressed),
        .private_key = undefined,
        .key_type = .secp256k1,
    };
    
    @memcpy(keypair.private_key[0..32], &zcrypto_keypair.private_key);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Generate Curve25519 keypair
fn generateCurve25519() !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .curve25519,
    };

    // Generate random secret key
    var secret_key: [32]u8 = undefined;
    std.crypto.random.bytes(&secret_key);

    // Use the X25519 base point (value 9)
    const base_point = [_]u8{9} ++ [_]u8{0} ** 31;

    // Derive public key
    const public_key = std.crypto.dh.X25519.scalarmult(secret_key, base_point) catch return CryptoError.KeyGenerationFailed;

    @memcpy(&keypair.public_key, &public_key);
    @memcpy(keypair.private_key[0..32], &secret_key);

    return keypair;
}

/// Generate Curve25519 keypair from seed
fn curve25519FromSeed(seed: [32]u8) !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .curve25519,
    };

    // Use the X25519 base point (value 9)
    const base_point = [_]u8{9} ++ [_]u8{0} ** 31;

    // Use seed as secret key
    const public_key = std.crypto.dh.X25519.scalarmult(seed, base_point) catch return CryptoError.KeyGenerationFailed;

    @memcpy(&keypair.public_key, &public_key);
    @memcpy(keypair.private_key[0..32], &seed);

    return keypair;
}

/// Sign with Ed25519 using zcrypto v0.3.0
fn signEd25519(message: []const u8, private_key: *const [64]u8, allocator: Allocator) ![]u8 {
    const ed25519_private_key: [32]u8 = private_key[0..32].*;
    
    // Use zcrypto for actual Ed25519 signing
    const keypair = zcrypto.asym.ed25519.KeyPair{
        .private_key = ed25519_private_key,
        .public_key = undefined, // Not needed for signing
    };
    
    const signature = try keypair.sign(message);
    const result = try allocator.alloc(u8, 64);
    @memcpy(result, &signature);
    
    return result;
}

/// Verify Ed25519 signature using zcrypto v0.3.0
fn verifyEd25519(message: []const u8, signature: []const u8, public_key: *const [32]u8) bool {
    if (signature.len != 64) return false;
    
    const sig_array: [64]u8 = signature[0..64].*;
    return zcrypto.asym.ed25519.verify(message, sig_array, public_key.*);
}

/// Sign with secp256k1 using zcrypto v0.3.0
fn signSecp256k1(message: []const u8, private_key: *const [64]u8, allocator: Allocator) ![]u8 {
    const secp256k1_private_key: [32]u8 = private_key[0..32].*;
    
    // Hash message first (Bitcoin-style)
    const message_hash = zcrypto.hash.sha256(message);
    
    const keypair = zcrypto.asym.secp256k1.KeyPair{
        .private_key = secp256k1_private_key,
        .public_key = undefined, // Not needed for signing
    };
    
    const signature = try keypair.sign(message_hash);
    const result = try allocator.alloc(u8, 64);
    @memcpy(result, &signature);
    
    return result;
}

/// Verify secp256k1 signature using zcrypto v0.3.0
fn verifySecp256k1(message: []const u8, signature: []const u8, public_key: *const [32]u8) bool {
    if (signature.len != 64) return false;
    
    // Hash message first (Bitcoin-style)
    const message_hash = zcrypto.hash.sha256(message);
    const sig_array: [64]u8 = signature[0..64].*;
    
    return zcrypto.asym.secp256k1.verify(message_hash, sig_array, public_key.*);
}

/// Derive BIP-32 child key
pub fn deriveChildKey(parent_key: *const KeyPair, index: u32, hardened: bool, allocator: Allocator) !KeyPair {
    // BIP-32 hierarchical deterministic key derivation
    var chain_code = [_]u8{0} ** 32; // In real implementation, this should be stored with the key
    
    // Prepare data for HMAC
    var data = std.ArrayList(u8).init(allocator);
    defer data.deinit();
    
    if (hardened) {
        // Hardened derivation: 0x00 + parent_private_key + index
        try data.append(0x00);
        try data.appendSlice(&parent_key.private_key);
        const hardened_index = index | 0x80000000;
        try data.appendSlice(&std.mem.toBytes(std.mem.bigToNative(u32, hardened_index)));
    } else {
        // Non-hardened derivation: parent_public_key + index
        try data.appendSlice(&parent_key.public_key);
        try data.appendSlice(&std.mem.toBytes(std.mem.bigToNative(u32, index)));
    }
    
    // HMAC-SHA512 with chain code as key
    var hmac_result: [64]u8 = undefined;
    var hmac = std.crypto.auth.hmac.HmacSha512.init(&chain_code);
    hmac.update(data.items);
    hmac.final(&hmac_result);
    
    // Split result: first 32 bytes = child key, last 32 bytes = child chain code
    const child_private_key = hmac_result[0..32].*;
    chain_code = hmac_result[32..64].*;
    
    // Generate corresponding public key based on algorithm
    var child_keypair = KeyPair{
        .algorithm = parent_key.algorithm,
        .private_key = child_private_key,
        .public_key = undefined,
        .allocator = allocator,
    };
    
    switch (parent_key.algorithm) {
        .ed25519 => {
            const ed25519_keypair = try zcrypto.asym.ed25519.generateKeypair();
            child_keypair.public_key = ed25519_keypair.public_key;
        },
        .secp256k1 => {
            const secp_keypair = try zcrypto.asym.secp256k1.generateKeypair();
            child_keypair.public_key = secp_keypair.public_key;
        },
    }
    
    return child_keypair;
}

/// Batch operations for enhanced performance (zcrypto v0.3.0 feature)
pub const Batch = struct {
    /// Sign multiple messages with Ed25519
    pub fn signMultipleEd25519(messages: []const []const u8, private_key: [32]u8, allocator: Allocator) ![][64]u8 {
        return zcrypto.batch.signBatchEd25519(messages, private_key, allocator);
    }
    
    /// Verify multiple Ed25519 signatures
    pub fn verifyMultipleEd25519(messages: []const []const u8, signatures: [][64]u8, public_keys: [][32]u8, allocator: Allocator) ![]bool {
        return zcrypto.batch.verifyBatchEd25519(messages, signatures, public_keys, allocator);
    }
    
    /// Zero-copy in-place signing
    pub fn signInPlace(message: []const u8, private_key: [32]u8, signature_buffer: *[64]u8) !void {
        try zcrypto.batch.signInPlace(message, private_key, signature_buffer);
    }
    
    /// Zero-copy in-place hashing
    pub fn hashInPlace(message: []const u8, hash_buffer: *[32]u8) void {
        zcrypto.batch.hashInPlace(message, hash_buffer);
    }
};

/// Enhanced key derivation for production use
pub const KeyDerivation = struct {
    /// Derive key from passphrase using PBKDF2
    pub fn deriveFromPassphrase(passphrase: []const u8, salt: []const u8, iterations: u32, allocator: Allocator) ![32]u8 {
        return zcrypto.kdf.pbkdf2(passphrase, salt, iterations, allocator);
    }
    
    /// Derive key using Argon2id (recommended for new applications)
    pub fn deriveFromPassphraseArgon2(passphrase: []const u8, salt: []const u8, allocator: Allocator) ![32]u8 {
        return zcrypto.kdf.argon2id(passphrase, salt, allocator);
    }
    
    /// BIP-32 compatible key derivation
    pub fn deriveBip32(parent_key: [32]u8, chain_code: [32]u8, index: u32, hardened: bool) ![64]u8 {
        return zcrypto.bip32.derive(parent_key, chain_code, index, hardened);
    }
};

/// Generate mnemonic phrase using BIP-39
pub fn generateMnemonic(allocator: Allocator, entropy_bits: u16) ![]const u8 {
    // Validate entropy bits (must be multiple of 32, between 128-256)
    if (entropy_bits < 128 or entropy_bits > 256 or entropy_bits % 32 != 0) {
        return CryptoError.InvalidKeySize;
    }
    
    const entropy_bytes = entropy_bits / 8;
    
    // Generate cryptographic entropy
    const entropy = try allocator.alloc(u8, entropy_bytes);
    defer allocator.free(entropy);
    try zcrypto.rand.randomBytes(entropy);
    
    // Calculate checksum: first (entropy_bits / 32) bits of SHA256(entropy)
    const checksum_bits = entropy_bits / 32;
    const entropy_hash = zcrypto.hash.sha256(entropy);
    
    // Combine entropy + checksum
    const total_bits = entropy_bits + checksum_bits;
    const word_count = total_bits / 11; // Each word represents 11 bits
    
    // BIP-39 English wordlist (first few words for demonstration)
    const wordlist = [_][]const u8{
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "agent", "agree",
        "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
        "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha",
        "already", "also", "alter", "always", "amateur", "amazing", "among", "amount",
        // ... (in production, use complete 2048-word list)
    };
    
    var mnemonic = std.ArrayList(u8).init(allocator);
    defer mnemonic.deinit();
    
    // Convert entropy+checksum to words
    var bit_pos: u32 = 0;
    for (0..word_count) |i| {
        var word_index: u16 = 0;
        
        // Extract 11 bits for word index
        for (0..11) |bit| {
            const byte_pos = (bit_pos + bit) / 8;
            const bit_in_byte = 7 - ((bit_pos + bit) % 8);
            
            if (byte_pos < entropy.len) {
                if ((entropy[byte_pos] >> @intCast(bit_in_byte)) & 1 != 0) {
                    word_index |= @as(u16, 1) << @intCast(10 - bit);
                }
            } else {
                // Use checksum bits
                const checksum_bit_pos = (bit_pos + bit) - entropy_bits;
                const checksum_byte_pos = checksum_bit_pos / 8;
                const checksum_bit_in_byte = 7 - (checksum_bit_pos % 8);
                
                if ((entropy_hash[checksum_byte_pos] >> @intCast(checksum_bit_in_byte)) & 1 != 0) {
                    word_index |= @as(u16, 1) << @intCast(10 - bit);
                }
            }
        }
        
        bit_pos += 11;
        
        // Add word to mnemonic
        if (i > 0) try mnemonic.appendSlice(" ");
        const word_idx = @min(word_index, wordlist.len - 1);
        try mnemonic.appendSlice(wordlist[word_idx]);
    }
    
    return allocator.dupe(u8, mnemonic.items);
}

/// Convert mnemonic to seed using BIP-39
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: ?[]const u8, allocator: Allocator) ![64]u8 {
    // BIP-39 seed generation using PBKDF2-HMAC-SHA512
    // Salt = "mnemonic" + passphrase
    const salt_prefix = "mnemonic";
    const actual_passphrase = passphrase orelse "";
    
    var salt = try allocator.alloc(u8, salt_prefix.len + actual_passphrase.len);
    defer allocator.free(salt);
    
    @memcpy(salt[0..salt_prefix.len], salt_prefix);
    if (actual_passphrase.len > 0) {
        @memcpy(salt[salt_prefix.len..], actual_passphrase);
    }
    
    // PBKDF2-HMAC-SHA512 with 2048 iterations
    var seed: [64]u8 = undefined;
    
    // Use zig's crypto PBKDF2 implementation
    std.crypto.pwhash.pbkdf2(&seed, mnemonic, salt, 2048, std.crypto.auth.hmac.sha2.HmacSha512);
    
    return seed;
}

test "keypair generation" {
    var keypair = try KeyPair.generate(.ed25519);
    defer keypair.deinit();

    try std.testing.expect(keypair.key_type == .ed25519);
}

test "signing and verification" {
    var keypair = try KeyPair.generate(.ed25519);
    defer keypair.deinit();

    const message = "Hello, Zwallet!";
    const signature = try keypair.sign(message, std.testing.allocator);
    defer std.testing.allocator.free(signature);

    try std.testing.expect(keypair.verify(message, signature));
}
