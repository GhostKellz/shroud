// Wrapper for realid to resolve dependency conflicts
// This re-exports realid functionality using our zcrypto version

const std = @import("std");
const zcrypto = @import("ghostcipher").zcrypto;

// Re-export realid types and functions
// Since realid doesn't export a module properly, we'll need to implement
// the necessary functionality or wait for the library to be fixed

pub const RealID = struct {
    // Placeholder implementation
    // The actual realid library needs to be properly integrated
};

// Export the expected API
pub const generateKeyPair = zcrypto.Ed25519.generateKeyPair;
pub const sign = zcrypto.Ed25519.sign;
pub const verify = zcrypto.Ed25519.verify;