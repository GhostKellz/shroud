//! By convention, root.zig is the root source file when making a library.
//! This file exports the zsig module for use as a library dependency.

const zsig = @import("zsig.zig");

// Re-export everything from zsig module
pub const ZsigSigner = zsig.ZsigSigner;
pub const ZsigVerifier = zsig.ZsigVerifier;
pub const ZsigKeyPair = zsig.ZsigKeyPair;
pub const ZsigSignature = zsig.ZsigSignature;
pub const ZsigError = zsig.ZsigError;

// Include tests from zsig module
test {
    @import("std").testing.refAllDecls(@This());
}
