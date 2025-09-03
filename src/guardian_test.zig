const std = @import("std");
const testing = std.testing;
const guardian = @import("guardian.zig");

test "guardian role permissions" {
    var g = guardian.Guardian.init(testing.allocator);
    defer g.deinit();
    
    try g.addRole("test_role", &[_]guardian.Permission{ .read, .write });
    
    const role = g.roles.get("test_role").?;
    try testing.expect(role.hasPermission(.read));
    try testing.expect(role.hasPermission(.write));
    try testing.expect(!role.hasPermission(.admin));
}

test "guardian access control" {
    var g = guardian.Guardian.init(testing.allocator);
    defer g.deinit();
    
    try guardian.createBasicRoles(&g);
    
    var context = guardian.AccessContext.init("user123", "/api/data", .read);
    defer context.deinit(testing.allocator);
    
    try context.addRole(testing.allocator, "user");
    
    const allowed = try g.canAccess(&context);
    try testing.expect(allowed);
}

test "guardian admin permissions" {
    var g = guardian.Guardian.init(testing.allocator);
    defer g.deinit();
    
    try guardian.createBasicRoles(&g);
    
    var context = guardian.AccessContext.init("admin123", "/admin/config", .admin);
    defer context.deinit(testing.allocator);
    
    try context.addRole(testing.allocator, "admin");
    
    const allowed = try g.canAccess(&context);
    try testing.expect(allowed);
}

test "guardian access denied" {
    var g = guardian.Guardian.init(testing.allocator);
    defer g.deinit();
    
    try guardian.createBasicRoles(&g);
    
    var context = guardian.AccessContext.init("user123", "/admin/config", .admin);
    defer context.deinit(testing.allocator);
    
    try context.addRole(testing.allocator, "user");
    
    const allowed = try g.canAccess(&context);
    try testing.expect(!allowed);
}

test "guardian role validation" {
    var g = guardian.Guardian.init(testing.allocator);
    defer g.deinit();
    
    try guardian.createBasicRoles(&g);
    
    try testing.expect(g.validateRole("admin"));
    try testing.expect(g.validateRole("user"));
    try testing.expect(!g.validateRole("nonexistent"));
}