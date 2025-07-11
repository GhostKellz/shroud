const std = @import("std");

export fn zcrypto_ed25519_keypair(public_key: [*c]u8, private_key: [*c]u8) c_int {
    _ = public_key;
    _ = private_key;
    return 0;
}

export fn zcrypto_ed25519_sign(private_key: [*c]const u8, message: [*c]const u8, message_len: usize, signature: [*c]u8) c_int {
    _ = private_key;
    _ = message;
    _ = message_len;
    _ = signature;
    return 0;
}

export fn zcrypto_ed25519_verify(public_key: [*c]const u8, message: [*c]const u8, message_len: usize, signature: [*c]const u8) c_int {
    _ = public_key;
    _ = message;
    _ = message_len;
    _ = signature;
    return 0;
}

export fn zcrypto_blake3_hash(input: [*c]const u8, input_len: usize, output: [*c]u8) c_int {
    _ = input;
    _ = input_len;
    _ = output;
    return 0;
}

export fn zcrypto_secp256k1_keypair(public_key: [*c]u8, private_key: [*c]u8) c_int {
    _ = public_key;
    _ = private_key;
    return 0;
}

export fn zcrypto_secp256k1_sign(private_key: [*c]const u8, message_hash: [*c]const u8, signature: [*c]u8) c_int {
    _ = private_key;
    _ = message_hash;
    _ = signature;
    return 0;
}

export fn zcrypto_secp256k1_verify(public_key: [*c]const u8, message_hash: [*c]const u8, signature: [*c]const u8) c_int {
    _ = public_key;
    _ = message_hash;
    _ = signature;
    return 0;
}

pub const ZCRYPTO_SUCCESS: c_int = 0;
pub const ZCRYPTO_ERROR_INVALID_INPUT: c_int = -1;
pub const ZCRYPTO_ERROR_INVALID_KEY: c_int = -2;
pub const ZCRYPTO_ERROR_INVALID_SIGNATURE: c_int = -3;