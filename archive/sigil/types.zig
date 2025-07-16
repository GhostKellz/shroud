const std = @import("std");

// Core RealID types
pub const RealIDPrivateKey = struct {
    bytes: [64]u8, // Ed25519 private key is 64 bytes
};

pub const RealIDPublicKey = struct {
    bytes: [32]u8,
};

pub const RealIDKeyPair = struct {
    private_key: RealIDPrivateKey,
    public_key: RealIDPublicKey,
};

pub const RealIDSignature = struct {
    bytes: [64]u8,
};

pub const QID = struct {
    bytes: [16]u8, // IPv6 address
};

pub const DeviceFingerprint = struct {
    bytes: [32]u8,
};

// Error types
pub const RealIDError = error{
    InvalidPassphrase,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    CryptoError,
    OutOfMemory,
};
