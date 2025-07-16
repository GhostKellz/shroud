const std = @import("std");
const testing = std.testing;
const wasm_guardian = @import("wasm_guardian.zig");
const guardian = @import("guardian.zig");

test "WasmPolicyEngine basic functionality" {
    const allocator = testing.allocator;
    
    var engine = wasm_guardian.WasmPolicyEngine.init(allocator);
    defer engine.deinit();
    
    // Create a simple WASM policy
    const default_policy = try wasm_guardian.createDefaultWasmPolicy(allocator);
    defer allocator.free(default_policy);
    
    // Load the policy
    try engine.loadPolicy("default", default_policy);
    
    // Create access context
    var context = guardian.AccessContext.init(allocator, "admin", "test_resource", .read);
    defer context.deinit();
    try context.addRole("admin");
    
    // Evaluate policy
    const result = try engine.evaluatePolicy("default", &context);
    try testing.expect(result); // Should allow admin access
}

test "WasmGuardian with fallback" {
    const allocator = testing.allocator;
    
    var wasm_guardian_instance = wasm_guardian.WasmGuardian.init(allocator);
    defer wasm_guardian_instance.deinit();
    
    // Add basic roles to fallback guardian
    try wasm_guardian_instance.addRole("user", &[_]guardian.Permission{.read});
    try wasm_guardian_instance.addRole("admin", &[_]guardian.Permission{ .read, .write, .admin });
    
    // Test fallback guardian functionality
    var context = guardian.AccessContext.init(allocator, "alice", "document1", .read);
    defer context.deinit();
    try context.addRole("user");
    
    // Should use fallback since no WASM policy specified
    const result = try wasm_guardian_instance.canAccess(&context, null);
    try testing.expect(result);
}

test "WasmPolicy creation and evaluation" {
    const allocator = testing.allocator;
    
    // Create minimal WASM module
    const wasm_bytes = [_]u8{
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // WASM magic + version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x01, 0x7F,       // Type section
        0x03, 0x02, 0x01, 0x00,                         // Function section
        0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x01, 0x0B, // Code section (returns 1)
    };
    
    var policy = try wasm_guardian.WasmPolicy.init(allocator, "test_policy", &wasm_bytes);
    defer policy.deinit();
    
    // Create context for evaluation
    var context = guardian.AccessContext.init(allocator, "testuser", "resource", .read);
    defer context.deinit();
    
    // Policy evaluation should work
    const result = try policy.evaluate(&context);
    // Result depends on the policy logic - for our test user, it should be false
    try testing.expect(!result);
}

test "WasmRuntime module loading" {
    const allocator = testing.allocator;
    
    var runtime = wasm_guardian.WasmRuntime.init(allocator);
    defer runtime.deinit();
    
    // Valid WASM module
    const valid_wasm = [_]u8{
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // WASM magic + version
    };
    
    try runtime.loadModule(&valid_wasm);
    try testing.expect(runtime.module_loaded);
    
    // Invalid WASM module should fail
    var runtime2 = wasm_guardian.WasmRuntime.init(allocator);
    defer runtime2.deinit();
    
    const invalid_wasm = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    const load_result = runtime2.loadModule(&invalid_wasm);
    try testing.expectError(wasm_guardian.WasmError.InvalidWasmModule, load_result);
}

test "WasmCompiler policy compilation" {
    const allocator = testing.allocator;
    
    // Simple policy source
    const policy_source = 
        \\allow if user.role == "admin"
        \\deny
    ;
    
    // Compile to WASM
    const wasm_bytes = try wasm_guardian.WasmCompiler.compilePolicy(allocator, policy_source, .simple);
    defer allocator.free(wasm_bytes);
    
    try testing.expect(wasm_bytes.len > 8); // Should have WASM header + content
    try testing.expect(std.mem.eql(u8, wasm_bytes[0..4], "\x00asm")); // WASM magic
}

test "WasmPolicy parameter validation" {
    const allocator = testing.allocator;
    
    // Test policy with admin user
    var runtime = wasm_guardian.WasmRuntime.init(allocator);
    defer runtime.deinit();
    
    const wasm_module = [_]u8{
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // WASM magic + version
    };
    try runtime.loadModule(&wasm_module);
    
    // Create serialized parameters for admin user
    var params = std.ArrayList(u8).init(allocator);
    defer params.deinit();
    
    const admin_id = "admin";
    try params.append(@intCast(admin_id.len));
    try params.appendSlice(admin_id);
    try params.append(0); // roles count
    
    // Add timestamp, resource, operation
    var timestamp_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &timestamp_bytes, @intCast(std.time.timestamp()), .little);
    try params.appendSlice(&timestamp_bytes);
    
    const resource = "test";
    try params.append(@intCast(resource.len));
    try params.appendSlice(resource);
    try params.append(@intFromEnum(guardian.Permission.read));
    
    // Should return 1 for admin user
    const result = try runtime.callFunction("evaluate", params.items);
    try testing.expect(result == 1);
}

test "WasmGuardian role validation" {
    const allocator = testing.allocator;
    
    var wasm_guardian_instance = wasm_guardian.WasmGuardian.init(allocator);
    defer wasm_guardian_instance.deinit();
    
    // Add role
    try wasm_guardian_instance.addRole("moderator", &[_]guardian.Permission{ .read, .write });
    
    // Validate role exists
    try testing.expect(wasm_guardian_instance.validateRole("moderator"));
    try testing.expect(!wasm_guardian_instance.validateRole("nonexistent"));
}

test "WasmPolicy permission validation function" {
    const allocator = testing.allocator;
    
    var runtime = wasm_guardian.WasmRuntime.init(allocator);
    defer runtime.deinit();
    
    const wasm_module = [_]u8{
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // WASM magic + version
    };
    try runtime.loadModule(&wasm_module);
    
    // Create parameters for permission check
    var params = std.ArrayList(u8).init(allocator);
    defer params.deinit();
    
    // Identity: "admin"
    const identity = "admin";
    try params.append(@intCast(identity.len));
    try params.appendSlice(identity);
    
    // Resource: "admin_panel"
    const resource = "admin_panel";
    try params.append(@intCast(resource.len));
    try params.appendSlice(resource);
    
    // Permission: write
    try params.append(@intFromEnum(guardian.Permission.write));
    
    // Should return 1 for admin user with write permission
    const result = try runtime.callFunction("validate_permission", params.items);
    try testing.expect(result == 1);
}