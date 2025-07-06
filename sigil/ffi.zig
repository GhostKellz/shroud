const std = @import("std");
const core = @import("core.zig");
const sign = @import("sign.zig");
const qid = @import("qid.zig");
const fingerprint = @import("fingerprint.zig");
const types = @import("types.zig");

const RealIDKeyPair = types.RealIDKeyPair;
const RealIDPrivateKey = types.RealIDPrivateKey;
const RealIDPublicKey = types.RealIDPublicKey;
const RealIDSignature = types.RealIDSignature;
const QID = types.QID;
const DeviceFingerprint = types.DeviceFingerprint;

// C-compatible result codes
const REALID_SUCCESS: c_int = 0;
const REALID_ERROR_INVALID_PASSPHRASE: c_int = -1;
const REALID_ERROR_INVALID_SIGNATURE: c_int = -2;
const REALID_ERROR_INVALID_KEY: c_int = -3;
const REALID_ERROR_CRYPTO: c_int = -4;
const REALID_ERROR_MEMORY: c_int = -5;
const REALID_ERROR_BUFFER_TOO_SMALL: c_int = -6;

// Global allocator for FFI functions (in real implementation, this should be configurable)
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

/// Generate keypair from passphrase (C ABI)
export fn realid_generate_from_passphrase_c(
    passphrase: [*c]const u8,
    passphrase_len: usize,
    keypair_out: *RealIDKeyPair,
) c_int {
    const pass_slice = passphrase[0..passphrase_len];

    const result = core.realid_generate_from_passphrase(pass_slice) catch |err| {
        return switch (err) {
            types.RealIDError.InvalidPassphrase => REALID_ERROR_INVALID_PASSPHRASE,
            types.RealIDError.CryptoError => REALID_ERROR_CRYPTO,
            types.RealIDError.OutOfMemory => REALID_ERROR_MEMORY,
            else => REALID_ERROR_CRYPTO,
        };
    };

    keypair_out.* = result;
    return REALID_SUCCESS;
}

/// Generate keypair from passphrase with device fingerprint (C ABI)
export fn realid_generate_from_passphrase_with_device_c(
    passphrase: [*c]const u8,
    passphrase_len: usize,
    device_fingerprint: *const DeviceFingerprint,
    keypair_out: *RealIDKeyPair,
) c_int {
    const pass_slice = passphrase[0..passphrase_len];

    const result = core.realid_generate_from_passphrase_with_device(pass_slice, device_fingerprint.*) catch |err| {
        return switch (err) {
            types.RealIDError.InvalidPassphrase => REALID_ERROR_INVALID_PASSPHRASE,
            types.RealIDError.CryptoError => REALID_ERROR_CRYPTO,
            types.RealIDError.OutOfMemory => REALID_ERROR_MEMORY,
            else => REALID_ERROR_CRYPTO,
        };
    };

    keypair_out.* = result;
    return REALID_SUCCESS;
}

/// Sign data (C ABI)
export fn realid_sign_c(
    data: [*c]const u8,
    data_len: usize,
    private_key: *const RealIDPrivateKey,
    signature_out: *RealIDSignature,
) c_int {
    const data_slice = data[0..data_len];

    const result = sign.realid_sign(data_slice, private_key.*) catch |err| {
        return switch (err) {
            types.RealIDError.InvalidPrivateKey => REALID_ERROR_INVALID_KEY,
            types.RealIDError.CryptoError => REALID_ERROR_CRYPTO,
            else => REALID_ERROR_CRYPTO,
        };
    };

    signature_out.* = result;
    return REALID_SUCCESS;
}

/// Verify signature (C ABI)
export fn realid_verify_c(
    signature: *const RealIDSignature,
    data: [*c]const u8,
    data_len: usize,
    public_key: *const RealIDPublicKey,
) c_int {
    const data_slice = data[0..data_len];

    const is_valid = sign.realid_verify(signature.*, data_slice, public_key.*);
    return if (is_valid) REALID_SUCCESS else REALID_ERROR_INVALID_SIGNATURE;
}

/// Generate QID from public key (C ABI)
export fn realid_qid_from_pubkey_c(
    public_key: *const RealIDPublicKey,
    qid_out: *QID,
) c_int {
    qid_out.* = qid.realid_qid_from_pubkey(public_key.*);
    return REALID_SUCCESS;
}

/// Generate device fingerprint (C ABI)
export fn realid_generate_device_fingerprint_c(
    fingerprint_out: *DeviceFingerprint,
) c_int {
    const result = fingerprint.generate_device_fingerprint(allocator) catch |err| {
        return switch (err) {
            types.RealIDError.OutOfMemory => REALID_ERROR_MEMORY,
            else => REALID_ERROR_CRYPTO,
        };
    };

    fingerprint_out.* = result;
    return REALID_SUCCESS;
}

/// Get public key from private key (C ABI)
export fn realid_get_public_key_c(
    private_key: *const RealIDPrivateKey,
    public_key_out: *RealIDPublicKey,
) c_int {
    const result = sign.realid_get_public_key(private_key.*) catch |err| {
        return switch (err) {
            types.RealIDError.InvalidPrivateKey => REALID_ERROR_INVALID_KEY,
            else => REALID_ERROR_CRYPTO,
        };
    };

    public_key_out.* = result;
    return REALID_SUCCESS;
}

/// Convert QID to string (C ABI)
export fn realid_qid_to_string_c(
    qid_input: *const QID,
    buffer: [*c]u8,
    buffer_len: usize,
    written_len: *usize,
) c_int {
    const buffer_slice = buffer[0..buffer_len];

    const result = qid.qid_to_string(qid_input.*, buffer_slice) catch |err| {
        return switch (err) {
            error.BufferTooSmall => REALID_ERROR_BUFFER_TOO_SMALL,
            else => REALID_ERROR_CRYPTO,
        };
    };

    written_len.* = result.len;
    return REALID_SUCCESS;
}
