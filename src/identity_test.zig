const std = @import("std");
const testing = std.testing;
const identity = @import("identity.zig");
const access_token = @import("access_token.zig");
const guardian = @import("guardian.zig");

test "identity creation and management" {
    const keypair = try access_token.generateKeyPair("test_passphrase");
    
    var manager = identity.IdentityManager.init(testing.allocator);
    defer manager.deinit();
    
    try manager.createIdentity("user123", keypair.public_key);
    
    const id = manager.getIdentity("user123").?;
    try id.addRole("user");
    try id.setMetadata("email", "user@example.com");
    
    try testing.expect(id.hasRole("user"));
    try testing.expect(std.mem.eql(u8, id.getMetadata("email").?, "user@example.com"));
}

test "identity authentication with token" {
    const keypair = try access_token.generateKeyPair("test_passphrase");
    
    var manager = identity.IdentityManager.init(testing.allocator);
    defer manager.deinit();
    
    try manager.createIdentity("user123", keypair.public_key);
    
    const id = manager.getIdentity("user123").?;
    var token = try id.createAccessToken(3600, keypair.private_key);
    defer token.deinit();
    
    const authenticated_id = try manager.authenticate(&token, keypair.public_key);
    try testing.expect(std.mem.eql(u8, authenticated_id.id, "user123"));
}

test "identity authorization" {
    const keypair = try access_token.generateKeyPair("test_passphrase");
    
    var manager = identity.IdentityManager.init(testing.allocator);
    defer manager.deinit();
    
    try guardian.createBasicRoles(&manager.guardian);
    try manager.createIdentity("user123", keypair.public_key);
    
    const id = manager.getIdentity("user123").?;
    try id.addRole("user");
    
    const authorized = try manager.authorize(id, "/api/data", .read);
    try testing.expect(authorized);
    
    const not_authorized = try manager.authorize(id, "/admin/config", .admin);
    try testing.expect(!not_authorized);
}

test "delegation creation and verification" {
    const keypair1 = try access_token.generateKeyPair("delegator_passphrase");
    const keypair2 = try access_token.generateKeyPair("delegate_passphrase");
    
    var manager = identity.IdentityManager.init(testing.allocator);
    defer manager.deinit();
    
    try guardian.createBasicRoles(&manager.guardian);
    try manager.createIdentity("delegator", keypair1.public_key);
    try manager.createIdentity("delegate", keypair2.public_key);
    
    const delegator = manager.getIdentity("delegator").?;
    const delegate = manager.getIdentity("delegate").?;
    
    try delegator.addRole("admin");
    try delegate.addRole("user");
    
    // Create delegation
    try manager.createDelegation(
        "delegator",
        "delegate", 
        "/api/special/*",
        &[_]guardian.Permission{.admin},
        3600,
        keypair1.private_key
    );
    
    // Delegate should now have admin access to /api/special/*
    const authorized = try manager.authorize(delegate, "/api/special/endpoint", .admin);
    try testing.expect(authorized);
}

test "delegation expiration" {
    const keypair1 = try access_token.generateKeyPair("delegator_passphrase");
    _ = try access_token.generateKeyPair("delegate_passphrase");
    
    var delegation = identity.Delegation.init(testing.allocator, "delegator", "delegate", "/api/*", 0); // Expires immediately
    defer delegation.deinit();
    
    // Set delegation to be expired
    delegation.expires_at = @as(u64, @intCast(std.time.timestamp())) - 10;
    
    try delegation.addPermission(.admin);
    try delegation.sign(keypair1.private_key);
    
    try testing.expect(delegation.isExpired());
    try testing.expect(delegation.verify(keypair1.public_key));
}

test "delegation signature verification" {
    const keypair1 = try access_token.generateKeyPair("delegator_passphrase");
    const keypair2 = try access_token.generateKeyPair("other_passphrase");
    
    var delegation = identity.Delegation.init(testing.allocator, "delegator", "delegate", "/api/*", 3600);
    defer delegation.deinit();
    
    try delegation.addPermission(.admin);
    try delegation.sign(keypair1.private_key);
    
    try testing.expect(delegation.verify(keypair1.public_key));
    try testing.expect(!delegation.verify(keypair2.public_key)); // Wrong key
}