const std = @import("std");

pub const zcrypto = @import("zcrypto/root.zig");
pub const zsig = @import("zsig/root.zig");

pub const CryptoError = error{
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed,
    SignatureFailed,
    VerificationFailed,
};

test "ghostcipher tests" {
    std.testing.refAllDecls(@This());
}