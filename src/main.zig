const std = @import("std");
const shroud = @import("shroud");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Shroud v{s} Demo ===\n", .{shroud.version()});
    
    // Generate a keypair
    const keypair = shroud.generateKeyPair("demo_passphrase") catch |err| {
        std.debug.print("Error generating keypair: {}\n", .{err});
        return;
    };
    std.debug.print("✓ Generated keypair\n", .{});
    
    // Create identity manager
    var manager = shroud.IdentityManager.init(allocator);
    defer manager.deinit();
    
    // Set up basic roles
    shroud.createBasicRoles(&manager.guardian) catch |err| {
        std.debug.print("Error creating basic roles: {}\n", .{err});
        return;
    };
    std.debug.print("✓ Created basic roles (admin, user, viewer)\n", .{});
    
    // Create an identity
    manager.createIdentity("demo_user", keypair.public_key) catch |err| {
        std.debug.print("Error creating identity: {}\n", .{err});
        return;
    };
    
    const identity = manager.getIdentity("demo_user").?;
    identity.addRole("user") catch |err| {
        std.debug.print("Error adding role: {}\n", .{err});
        return;
    };
    identity.setMetadata("email", "demo@example.com") catch |err| {
        std.debug.print("Error setting metadata: {}\n", .{err});
        return;
    };
    std.debug.print("✓ Created identity 'demo_user' with 'user' role\n", .{});
    
    // Create access token
    var token = identity.createAccessToken(3600, keypair.private_key) catch |err| {
        std.debug.print("Error creating access token: {}\n", .{err});
        return;
    };
    defer token.deinit();
    std.debug.print("✓ Created signed access token (expires in 1 hour)\n", .{});
    
    // Authenticate with token
    const authenticated = manager.authenticate(&token, keypair.public_key) catch |err| {
        std.debug.print("Error authenticating: {}\n", .{err});
        return;
    };
    std.debug.print("✓ Authenticated identity: {s}\n", .{authenticated.id});
    
    // Test authorization
    const can_read = manager.authorize(identity, "/api/data", .read) catch false;
    const can_admin = manager.authorize(identity, "/admin/config", .admin) catch false;
    
    std.debug.print("✓ Authorization check: read=/api/data -> {}\n", .{can_read});
    std.debug.print("✓ Authorization check: admin=/admin/config -> {}\n", .{can_admin});
    
    std.debug.print("\n=== Demo Complete ===\n", .{});
    try shroud.bufferedPrint();
}
