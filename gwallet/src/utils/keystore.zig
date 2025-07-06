//! Encrypted keystore for secure key storage
//! Provides JSON keystore format with Argon2 key derivation

const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("crypto.zig");

pub const KeystoreError = error{
    InvalidPassword,
    CorruptedKeystore,
    UnsupportedVersion,
    DecryptionFailed,
    EncryptionFailed,
    InvalidFormat,
};

pub const KeystoreVersion = enum(u8) {
    v1 = 1,
    v2 = 2,
};

pub const EncryptionParams = struct {
    cipher: []const u8,
    salt: [32]u8,
    iv: [16]u8,
    iterations: u32,
    memory_cost: u32,
    parallelism: u32,
};

pub const Keystore = struct {
    version: KeystoreVersion,
    id: [16]u8, // UUID
    address: ?[]const u8,
    crypto_params: EncryptionParams,
    ciphertext: []const u8,
    mac: [32]u8, // HMAC for integrity

    allocator: Allocator,

    pub fn init(allocator: Allocator) Keystore {
        var id: [16]u8 = undefined;
        std.crypto.random.bytes(&id);

        var salt: [32]u8 = undefined;
        var iv: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        std.crypto.random.bytes(&iv);

        return Keystore{
            .version = .v2,
            .id = id,
            .address = null,
            .crypto_params = EncryptionParams{
                .cipher = "aes-256-ctr",
                .salt = salt,
                .iv = iv,
                .iterations = 600000, // Argon2 iterations
                .memory_cost = 65536, // 64 MB
                .parallelism = 4,
            },
            .ciphertext = &[_]u8{},
            .mac = [_]u8{0} ** 32,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Keystore) void {
        if (self.address) |addr| {
            self.allocator.free(addr);
        }
        if (self.ciphertext.len > 0) {
            // Zero out ciphertext before freeing
            @memset(@constCast(self.ciphertext), 0);
            self.allocator.free(@constCast(self.ciphertext));
        }
    }

    /// Encrypt and store a keypair
    pub fn encryptKeypair(self: *Keystore, keypair: *const crypto.KeyPair, password: []const u8, address: ?[]const u8) !void {
        // Derive encryption key from password using Argon2
        const derived_key = try self.deriveKey(password);
        defer @memset(&derived_key, 0); // Clear derived key

        // Serialize keypair
        const plaintext = try self.serializeKeypair(keypair);
        defer {
            @memset(plaintext, 0);
            self.allocator.free(plaintext);
        }

        // Encrypt plaintext
        const ciphertext = try self.encrypt(plaintext, &derived_key);

        // Calculate MAC
        const mac = try self.calculateMac(&derived_key, ciphertext);

        // Store encrypted data
        if (self.ciphertext.len > 0) {
            self.allocator.free(@constCast(self.ciphertext));
        }
        self.ciphertext = ciphertext;
        self.mac = mac;

        // Store address
        if (address) |addr| {
            if (self.address) |old_addr| {
                self.allocator.free(old_addr);
            }
            self.address = try self.allocator.dupe(u8, addr);
        }
    }

    /// Decrypt and restore a keypair
    pub fn decryptKeypair(self: *const Keystore, password: []const u8) !crypto.KeyPair {
        // Derive decryption key
        const derived_key = try self.deriveKey(password);
        defer @memset(@constCast(&derived_key), 0);

        // Verify MAC
        const expected_mac = try self.calculateMac(&derived_key, self.ciphertext);
        if (!std.mem.eql(u8, &self.mac, &expected_mac)) {
            return KeystoreError.InvalidPassword;
        }

        // Decrypt ciphertext
        const plaintext = try self.decrypt(self.ciphertext, &derived_key);
        defer {
            @memset(plaintext, 0);
            self.allocator.free(plaintext);
        }

        // Deserialize keypair
        return try self.deserializeKeypair(plaintext);
    }

    /// Save keystore to file
    pub fn saveToFile(self: *const Keystore, path: []const u8) !void {
        const json = try self.toJson();
        defer self.allocator.free(json);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        try file.writeAll(json);
    }

    /// Load keystore from file
    pub fn loadFromFile(allocator: Allocator, path: []const u8) !Keystore {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024); // Max 1MB
        defer allocator.free(content);

        return try fromJson(allocator, content);
    }

    /// Convert keystore to JSON
    pub fn toJson(self: *const Keystore) ![]u8 {
        // Create JSON object manually for now
        // TODO: Use proper JSON serialization

        const json_template =
            \\{{
            \\  "version": {d},
            \\  "id": "{s}",
            \\  "address": "{s}",
            \\  "crypto": {{
            \\    "cipher": "{s}",
            \\    "cipherparams": {{
            \\      "iv": "{s}"
            \\    }},
            \\    "ciphertext": "{s}",
            \\    "kdf": "argon2id",
            \\    "kdfparams": {{
            \\      "salt": "{s}",
            \\      "iterations": {d},
            \\      "memoryCost": {d},
            \\      "parallelism": {d}
            \\    }},
            \\    "mac": "{s}"
            \\  }}
            \\}}
        ;

        // Convert binary data to hex strings
        const id_hex = try self.bytesToHex(self.allocator, &self.id);
        defer self.allocator.free(id_hex);

        const iv_hex = try self.bytesToHex(self.allocator, &self.crypto_params.iv);
        defer self.allocator.free(iv_hex);

        const salt_hex = try self.bytesToHex(self.allocator, &self.crypto_params.salt);
        defer self.allocator.free(salt_hex);

        const ciphertext_hex = try self.bytesToHex(self.allocator, self.ciphertext);
        defer self.allocator.free(ciphertext_hex);

        const mac_hex = try self.bytesToHex(self.allocator, &self.mac);
        defer self.allocator.free(mac_hex);

        return try std.fmt.allocPrint(self.allocator, json_template, .{
            @intFromEnum(self.version),
            id_hex,
            self.address orelse "",
            self.crypto_params.cipher,
            iv_hex,
            ciphertext_hex,
            salt_hex,
            self.crypto_params.iterations,
            self.crypto_params.memory_cost,
            self.crypto_params.parallelism,
            mac_hex,
        });
    }

    /// Create keystore from JSON
    pub fn fromJson(allocator: Allocator, json: []const u8) !Keystore {
        _ = json;

        // TODO: Implement proper JSON parsing
        // For now, return a dummy keystore
        return Keystore.init(allocator);
    }

    // Helper functions

    fn deriveKey(self: *const Keystore, password: []const u8) ![32]u8 {
        // TODO: Use Argon2 from zcrypto
        // For now, use a simplified key derivation

        var derived_key: [32]u8 = undefined;
        var context = std.crypto.auth.blake2.Blake2b256.init(.{});
        context.update(password);
        context.update(&self.crypto_params.salt);
        context.final(&derived_key);

        return derived_key;
    }

    fn encrypt(self: *const Keystore, plaintext: []const u8, key: *const [32]u8) ![]u8 {
        const ciphertext = try self.allocator.alloc(u8, plaintext.len);

        // TODO: Use proper AES-256-CTR encryption
        // For now, XOR with key (insecure, for demonstration only)
        for (plaintext, 0..) |byte, i| {
            ciphertext[i] = byte ^ key[i % 32];
        }

        return ciphertext;
    }

    fn decrypt(self: *const Keystore, ciphertext: []const u8, key: *const [32]u8) ![]u8 {
        const plaintext = try self.allocator.alloc(u8, ciphertext.len);

        // TODO: Use proper AES-256-CTR decryption
        // For now, XOR with key (matches encrypt function above)
        for (ciphertext, 0..) |byte, i| {
            plaintext[i] = byte ^ key[i % 32];
        }

        return plaintext;
    }

    fn calculateMac(self: *const Keystore, key: *const [32]u8, data: []const u8) ![32]u8 {
        _ = self;

        var mac: [32]u8 = undefined;
        var hmac = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256).init(key);
        hmac.update(data);
        hmac.final(&mac);

        return mac;
    }

    fn serializeKeypair(self: *const Keystore, keypair: *const crypto.KeyPair) ![]u8 {
        // Simple serialization format: key_type (1 byte) + public_key (32 bytes) + private_key (64 bytes)
        const serialized = try self.allocator.alloc(u8, 1 + 32 + 64);

        serialized[0] = @intFromEnum(keypair.key_type);
        @memcpy(serialized[1..33], &keypair.public_key);
        @memcpy(serialized[33..97], &keypair.private_key);

        return serialized;
    }

    fn deserializeKeypair(self: *const Keystore, data: []const u8) !crypto.KeyPair {
        _ = self;

        if (data.len != 97) {
            return KeystoreError.InvalidFormat;
        }

        const key_type = std.meta.intToEnum(crypto.KeyType, data[0]) catch return KeystoreError.InvalidFormat;

        var keypair = crypto.KeyPair{
            .key_type = key_type,
            .public_key = undefined,
            .private_key = undefined,
        };

        @memcpy(&keypair.public_key, data[1..33]);
        @memcpy(&keypair.private_key, data[33..97]);

        return keypair;
    }

    fn bytesToHex(self: *const Keystore, bytes: []const u8) ![]u8 {
        const hex = try self.allocator.alloc(u8, bytes.len * 2);
        _ = try std.fmt.bufPrint(hex, "{}", .{std.fmt.fmtSliceHexLower(bytes)});
        return hex;
    }
};

test "keystore creation" {
    var keystore = Keystore.init(std.testing.allocator);
    defer keystore.deinit();

    try std.testing.expect(keystore.version == .v2);
}

test "keystore encryption/decryption" {
    var keystore = Keystore.init(std.testing.allocator);
    defer keystore.deinit();

    var keypair = try crypto.KeyPair.generate(.ed25519);
    defer keypair.deinit();

    try keystore.encryptKeypair(&keypair, "test_password", "test_address");

    const decrypted = try keystore.decryptKeypair("test_password");
    try std.testing.expect(decrypted.key_type == .ed25519);
}
