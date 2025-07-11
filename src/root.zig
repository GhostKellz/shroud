//! Shroud v1.0: Unified Cryptographic Framework
//! Modular architecture integrating all Ghostchain crypto components
const std = @import("std");

// Core modules
pub const ghostcipher = @import("ghostcipher");
pub const sigil = @import("sigil");
pub const zns = @import("zns");
pub const ghostwire = @import("ghostwire");
pub const keystone = @import("keystone");

// Advanced modules
pub const guardian = @import("guardian");
pub const covenant = @import("covenant");
pub const shadowcraft = @import("shadowcraft");
pub const gwallet = @import("gwallet");

// Clean v0.5.0 API - no legacy compatibility
// Use: shroud.ghostcipher.zcrypto, shroud.ghostcipher.zsig, shroud.sigil

pub const ShroudError = error{
    ModuleInitFailed,
    CryptoError,
    NetworkError,
    IdentityError,
    LedgerError,
};

pub fn version() []const u8 {
    return "0.5.0";
}

test "shroud module imports" {
    std.testing.refAllDecls(@This());
}
