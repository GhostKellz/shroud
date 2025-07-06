const std = @import("std");
const zcrypto = @import("zcrypto");

pub const EncryptedStorage = struct {
    allocator: std.mem.Allocator,
    encryption_key: [32]u8,

    pub fn init(allocator: std.mem.Allocator) EncryptedStorage {
        return EncryptedStorage{
            .allocator = allocator,
            .encryption_key = zcrypto.rand.generateKey(32),
        };
    }

    pub fn initWithKey(allocator: std.mem.Allocator, key: [32]u8) EncryptedStorage {
        return EncryptedStorage{
            .allocator = allocator,
            .encryption_key = key,
        };
    }

    pub fn deriveKeyFromPassword(allocator: std.mem.Allocator, password: []const u8, salt: [16]u8) ![32]u8 {
        return try zcrypto.kdf.argon2id(allocator, password, &salt, 32);
    }

    pub fn encryptData(self: *EncryptedStorage, plaintext: []const u8) !EncryptedData {
        const ciphertext = try zcrypto.sym.encryptAesGcm(self.allocator, plaintext, &self.encryption_key);
        return EncryptedData{
            .ciphertext = ciphertext,
            .allocator = self.allocator,
        };
    }

    pub fn decryptData(self: *EncryptedStorage, encrypted_data: EncryptedData) ![]u8 {
        return try zcrypto.sym.decryptAesGcm(self.allocator, encrypted_data.ciphertext, &self.encryption_key);
    }

    pub fn secureWipe(self: *EncryptedStorage) void {
        zcrypto.util.secureZero(&self.encryption_key);
    }
};

pub const EncryptedData = struct {
    ciphertext: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *EncryptedData) void {
        zcrypto.util.secureZero(self.ciphertext);
        self.allocator.free(self.ciphertext);
    }

    pub fn toBase64(self: EncryptedData, allocator: std.mem.Allocator) ![]u8 {
        return try zcrypto.util.base64Encode(allocator, self.ciphertext);
    }

    pub fn fromBase64(allocator: std.mem.Allocator, base64_data: []const u8) !EncryptedData {
        const ciphertext = try zcrypto.util.base64Decode(allocator, base64_data);
        return EncryptedData{
            .ciphertext = ciphertext,
            .allocator = allocator,
        };
    }
};

pub const SecureFile = struct {
    storage: EncryptedStorage,
    file_path: []const u8,

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8, password: []const u8) !SecureFile {
        var salt: [16]u8 = undefined;
        zcrypto.rand.fillBytes(&salt);
        
        const key = try EncryptedStorage.deriveKeyFromPassword(allocator, password, salt);
        
        return SecureFile{
            .storage = EncryptedStorage.initWithKey(allocator, key),
            .file_path = file_path,
        };
    }

    pub fn save(self: *SecureFile, data: []const u8) !void {
        var encrypted_data = try self.storage.encryptData(data);
        defer encrypted_data.deinit();

        const base64_data = try encrypted_data.toBase64(self.storage.allocator);
        defer self.storage.allocator.free(base64_data);

        const file = try std.fs.cwd().createFile(self.file_path, .{});
        defer file.close();

        try file.writeAll(base64_data);
    }

    pub fn load(self: *SecureFile) ![]u8 {
        const file = try std.fs.cwd().openFile(self.file_path, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const base64_data = try self.storage.allocator.alloc(u8, file_size);
        defer self.storage.allocator.free(base64_data);

        _ = try file.readAll(base64_data);

        var encrypted_data = try EncryptedData.fromBase64(self.storage.allocator, base64_data);
        defer encrypted_data.deinit();

        return try self.storage.decryptData(encrypted_data);
    }

    pub fn deinit(self: *SecureFile) void {
        self.storage.secureWipe();
    }
};

test "encrypted storage basic operations" {
    const allocator = std.testing.allocator;
    
    var storage = EncryptedStorage.init(allocator);
    defer storage.secureWipe();

    const plaintext = "This is sensitive ledger data that must be encrypted";
    
    var encrypted = try storage.encryptData(plaintext);
    defer encrypted.deinit();

    const decrypted = try storage.decryptData(encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "password-based key derivation" {
    const allocator = std.testing.allocator;
    
    const password = "super_secure_password";
    var salt: [16]u8 = undefined;
    zcrypto.rand.fillBytes(&salt);

    const key1 = try EncryptedStorage.deriveKeyFromPassword(allocator, password, salt);
    const key2 = try EncryptedStorage.deriveKeyFromPassword(allocator, password, salt);

    try std.testing.expectEqualSlices(u8, &key1, &key2);
}

test "secure file operations" {
    const allocator = std.testing.allocator;
    
    const test_file = "test_secure_ledger.dat";
    const password = "test_password";
    const test_data = "Confidential ledger transaction data";

    var secure_file = try SecureFile.init(allocator, test_file, password);
    defer secure_file.deinit();

    try secure_file.save(test_data);
    
    const loaded_data = try secure_file.load();
    defer allocator.free(loaded_data);

    try std.testing.expectEqualStrings(test_data, loaded_data);

    // Clean up
    std.fs.cwd().deleteFile(test_file) catch {};
}