//! Shroud v0.1.0 - Identity & Privacy Framework
//! A focused zero-trust identity and privacy library for Zig
const std = @import("std");

// Export core modules
pub const guardian = @import("guardian.zig");
pub const access_token = @import("access_token.zig");
pub const identity = @import("identity.zig");

// Re-export commonly used types
pub const Permission = guardian.Permission;
pub const Role = guardian.Role;
pub const Guardian = guardian.Guardian;
pub const AccessToken = access_token.AccessToken;
pub const KeyPair = access_token.KeyPair;
pub const Identity = identity.Identity;
pub const IdentityManager = identity.IdentityManager;
pub const Delegation = identity.Delegation;

// Re-export commonly used functions
pub const generateKeyPair = access_token.generateKeyPair;
pub const generateEphemeralKeyPair = access_token.generateEphemeralKeyPair;
pub const signData = access_token.signData;
pub const verifyData = access_token.verifyData;
pub const createBasicRoles = guardian.createBasicRoles;

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
