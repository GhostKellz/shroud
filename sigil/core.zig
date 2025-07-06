const std = @import("std");
const zcrypto = @import("zcrypto");
const types = @import("types.zig");

const RealIDKeyPair = types.RealIDKeyPair;
const RealIDPrivateKey = types.RealIDPrivateKey;
const RealIDPublicKey = types.RealIDPublicKey;
const DeviceFingerprint = types.DeviceFingerprint;
const RealIDError = types.RealIDError;

// Constants for key derivation
const PBKDF2_ITERATIONS = 100000;
const SALT_PREFIX = "RealID-v1";

/// Generate a RealID keypair from a passphrase
pub fn realid_generate_from_passphrase(passphrase: []const u8) RealIDError!RealIDKeyPair {
    if (passphrase.len == 0) {
        return RealIDError.InvalidPassphrase;
    }

    // Create salt from passphrase and prefix using SHA-256
    var salt_data = std.ArrayList(u8).init(std.heap.page_allocator);
    defer salt_data.deinit();
    salt_data.appendSlice(SALT_PREFIX) catch return RealIDError.OutOfMemory;
    salt_data.appendSlice(passphrase) catch return RealIDError.OutOfMemory;
    const salt = zcrypto.hash.sha256(salt_data.items);

    // Derive key material using PBKDF2-SHA256
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    const key_material = zcrypto.kdf.pbkdf2Sha256(allocator, passphrase, &salt, PBKDF2_ITERATIONS, 64) catch {
        return RealIDError.CryptoError;
    };
    defer allocator.free(key_material);

    // Create Ed25519 keypair from seed using proper seed derivation
    // Ed25519 uses the first 32 bytes as seed and derives the actual secret key
    const seed = key_material[0..32].*;
    const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
        return RealIDError.CryptoError;
    };

    return RealIDKeyPair{
        .private_key = RealIDPrivateKey{ .bytes = keypair.secret_key.bytes },
        .public_key = RealIDPublicKey{ .bytes = keypair.public_key.bytes },
    };
}

/// Generate a RealID keypair from passphrase with device fingerprint
pub fn realid_generate_from_passphrase_with_device(
    passphrase: []const u8,
    device_fingerprint: DeviceFingerprint,
) RealIDError!RealIDKeyPair {
    if (passphrase.len == 0) {
        return RealIDError.InvalidPassphrase;
    }

    // Create salt from passphrase, prefix, and device fingerprint using SHA-256
    var salt_data = std.ArrayList(u8).init(std.heap.page_allocator);
    defer salt_data.deinit();
    salt_data.appendSlice(SALT_PREFIX) catch return RealIDError.OutOfMemory;
    salt_data.appendSlice(&device_fingerprint.bytes) catch return RealIDError.OutOfMemory;
    salt_data.appendSlice(passphrase) catch return RealIDError.OutOfMemory;
    const salt = zcrypto.hash.sha256(salt_data.items);

    // Derive key material using PBKDF2-SHA256
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    const key_material = zcrypto.kdf.pbkdf2Sha256(allocator, passphrase, &salt, PBKDF2_ITERATIONS, 64) catch {
        return RealIDError.CryptoError;
    };
    defer allocator.free(key_material);

    // Create Ed25519 keypair from seed
    const seed = key_material[0..32].*;
    const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
        return RealIDError.CryptoError;
    };

    return RealIDKeyPair{
        .private_key = RealIDPrivateKey{ .bytes = keypair.secret_key.bytes },
        .public_key = RealIDPublicKey{ .bytes = keypair.public_key.bytes },
    };
}

/// Generate a device fingerprint based on system characteristics
pub fn generate_device_fingerprint(allocator: std.mem.Allocator) RealIDError!DeviceFingerprint {
    // Simple device fingerprinting based on available system info
    // We'll collect system info and hash it with SHA-256
    var fingerprint_data = std.ArrayList(u8).init(allocator);
    defer fingerprint_data.deinit();

    try fingerprint_data.appendSlice("RealID-Device-v1");

    // Add hostname if available
    if (std.process.getEnvVarOwned(allocator, "HOSTNAME")) |hostname| {
        defer allocator.free(hostname);
        try fingerprint_data.appendSlice(hostname);
    } else |_| {
        // If no hostname, use a default marker
        try fingerprint_data.appendSlice("unknown-host");
    }

    // Add user info if available
    if (std.process.getEnvVarOwned(allocator, "USER")) |user| {
        defer allocator.free(user);
        try fingerprint_data.appendSlice(user);
    } else |_| {
        try fingerprint_data.appendSlice("unknown-user");
    }

    // Add current working directory
    var cwd_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    if (std.process.getCwd(&cwd_buf)) |cwd| {
        try fingerprint_data.appendSlice(cwd);
    } else |_| {
        try fingerprint_data.appendSlice("unknown-cwd");
    }

    // Hash all the collected data using SHA-256
    const fingerprint_hash = zcrypto.hash.sha256(fingerprint_data.items);
    
    return DeviceFingerprint{ .bytes = fingerprint_hash };
}
