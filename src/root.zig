//! Shroud v0.1.0 - Identity & Privacy Framework
//! A focused zero-trust identity and privacy library for Zig
const std = @import("std");

// Export core modules
pub const guardian = @import("guardian.zig");
pub const access_token = @import("access_token.zig");
pub const identity = @import("identity.zig");
pub const qid = @import("qid.zig");
pub const device = @import("device.zig");

// Export new advanced modules
pub const zk_proof = @import("zk_proof.zig");
pub const wasm_guardian = @import("wasm_guardian.zig");
pub const cross_chain = @import("cross_chain.zig");
pub const hierarchical_trust = @import("hierarchical_trust.zig");

// Re-export commonly used types
pub const Permission = guardian.Permission;
pub const Role = guardian.Role;
pub const Guardian = guardian.Guardian;
pub const AccessToken = access_token.AccessToken;
pub const KeyPair = access_token.KeyPair;
pub const Identity = identity.Identity;
pub const IdentityManager = identity.IdentityManager;
pub const Delegation = identity.Delegation;
pub const QID = qid.QID;
pub const IdentityKeyPair = identity.IdentityKeyPair;
pub const IdentityGenerationOptions = identity.IdentityGenerationOptions;
pub const DeviceFingerprint = device.DeviceFingerprint;
pub const DevicePolicy = device.DevicePolicy;
pub const BoundIdentity = device.BoundIdentity;
pub const DeviceAccessContext = guardian.DeviceAccessContext;

// Re-export new advanced types
pub const ZkProof = zk_proof.ZkProof;
pub const ZkAttestation = zk_proof.ZkAttestation;
pub const ZkProofSystem = zk_proof.ZkProofSystem;
pub const EphemeralIdentity = zk_proof.EphemeralIdentity;
pub const PrivacyLevel = zk_proof.PrivacyLevel;
pub const WasmGuardian = wasm_guardian.WasmGuardian;
pub const WasmPolicyEngine = wasm_guardian.WasmPolicyEngine;
pub const CrossChainIdentity = cross_chain.CrossChainIdentity;
pub const CrossChainResolver = cross_chain.CrossChainResolver;
pub const DID = cross_chain.DID;
pub const ChainType = cross_chain.ChainType;
pub const HierarchicalDelegation = hierarchical_trust.HierarchicalDelegation;
pub const HierarchicalTrustManager = hierarchical_trust.HierarchicalTrustManager;
pub const TrustLevel = hierarchical_trust.TrustLevel;
pub const TrustMetrics = hierarchical_trust.TrustMetrics;

// Re-export commonly used functions
pub const generateKeyPair = access_token.generateKeyPair;
pub const generateEphemeralKeyPair = access_token.generateEphemeralKeyPair;
pub const signData = access_token.signData;
pub const verifyData = access_token.verifyData;
pub const createBasicRoles = guardian.createBasicRoles;

// Convenience functions for RealID legacy features
pub const generateIdentityFromPassphrase = identity.generateIdentityFromPassphrase;
pub const generateIdentity = identity.generateIdentity;
pub const generateDeviceFingerprint = device.generateDeviceFingerprint;
pub const checkDevicePermission = guardian.checkDevicePermission;

pub fn version() []const u8 {
    return "0.1.0";
}

pub fn bufferedPrint() !void {
    const stdout_file = std.fs.File.stdout().deprecatedWriter();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Shroud v{s} - Identity & Privacy Framework\n", .{version()});
    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush();
}

test "shroud version" {
    try std.testing.expect(std.mem.eql(u8, version(), "0.1.0"));
}
