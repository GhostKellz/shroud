const std = @import("std");

pub const zcrypto = @import("zcrypto/root.zig");
pub const zsig = @import("zsig/root.zig");

// Export compatibility aliases for FFI
pub const signatures = zcrypto.asym;
pub const hash = zcrypto.hash;
pub const random = zcrypto.rand;
pub const utils = zcrypto.util;

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