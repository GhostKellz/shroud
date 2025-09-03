const std = @import("std");
const guardian = @import("guardian.zig");
const identity = @import("identity.zig");
const access_token = @import("access_token.zig");

pub const WasmError = error{
    ModuleLoadFailed,
    FunctionNotFound,
    InvalidWasmModule,
    ExecutionFailed,
    InvalidMemory,
    OutOfMemory,
    InvalidParameters,
    RuntimeError,
};

pub const WasmPolicyEngine = struct {
    allocator: std.mem.Allocator,
    policies: std.HashMap([]const u8, WasmPolicy, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    
    pub fn init(allocator: std.mem.Allocator) WasmPolicyEngine {
        return WasmPolicyEngine{
            .allocator = allocator,
            .policies = std.HashMap([]const u8, WasmPolicy, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *WasmPolicyEngine) void {
        var policy_iter = self.policies.iterator();
        while (policy_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.policies.deinit();
    }
    
    pub fn loadPolicy(self: *WasmPolicyEngine, name: []const u8, wasm_bytes: []const u8) WasmError!void {
        const policy = try WasmPolicy.init(self.allocator, name, wasm_bytes);
        try self.policies.put(name, policy);
    }
    
    pub fn evaluatePolicy(self: *WasmPolicyEngine, policy_name: []const u8, context: *const guardian.AccessContext) WasmError!bool {
        const policy = self.policies.get(policy_name) orelse return WasmError.FunctionNotFound;
        return policy.evaluate(context);
    }
    
    pub fn validatePermission(self: *WasmPolicyEngine, policy_name: []const u8, identity_id: []const u8, resource: []const u8, permission: guardian.Permission) WasmError!bool {
        const policy = self.policies.get(policy_name) orelse return WasmError.FunctionNotFound;
        return policy.validatePermission(identity_id, resource, permission);
    }
};

pub const WasmPolicy = struct {
    name: []const u8,
    wasm_module: []const u8,
    allocator: std.mem.Allocator,
    
    const WASM_PAGE_SIZE = 65536;
    const MAX_MEMORY_PAGES = 16;
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8, wasm_bytes: []const u8) WasmError!WasmPolicy {
        // Validate WASM module header
        if (wasm_bytes.len < 8) return WasmError.InvalidWasmModule;
        if (!std.mem.eql(u8, wasm_bytes[0..4], "\x00asm")) return WasmError.InvalidWasmModule;
        
        // Store a copy of the WASM module
        const module_copy = try allocator.dupe(u8, wasm_bytes);
        
        return WasmPolicy{
            .name = name,
            .wasm_module = module_copy,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *WasmPolicy) void {
        self.allocator.free(self.wasm_module);
    }
    
    pub fn evaluate(self: *const WasmPolicy, context: *const guardian.AccessContext) WasmError!bool {
        // Simulate WASM execution for policy evaluation
        var runtime = WasmRuntime.init(self.allocator);
        defer runtime.deinit();
        
        try runtime.loadModule(self.wasm_module);
        
        // Serialize context for WASM function
        const context_data = try self.serializeContext(context);
        defer self.allocator.free(context_data);
        
        // Call evaluate function in WASM module
        const result = try runtime.callFunction("evaluate", context_data);
        return result != 0;
    }
    
    pub fn validatePermission(self: *const WasmPolicy, identity_id: []const u8, resource: []const u8, permission: guardian.Permission) WasmError!bool {
        var runtime = WasmRuntime.init(self.allocator);
        defer runtime.deinit();
        
        try runtime.loadModule(self.wasm_module);
        
        // Serialize parameters
        const param_data = try self.serializePermissionCheck(identity_id, resource, permission);
        defer self.allocator.free(param_data);
        
        const result = try runtime.callFunction("validate_permission", param_data);
        return result != 0;
    }
    
    fn serializeContext(self: *const WasmPolicy, context: *const guardian.AccessContext) ![]u8 {
        var buffer = std.ArrayList(u8){};
        defer buffer.deinit(self.allocator);
        
        // Serialize user_id length and data
        try buffer.append(self.allocator, @intCast(context.user_id.len));
        try buffer.appendSlice(self.allocator, context.user_id);
        
        // Serialize roles count and data
        try buffer.append(self.allocator, @intCast(context.roles.items.len));
        for (context.roles.items) |role| {
            try buffer.append(self.allocator, @intCast(role.len));
            try buffer.appendSlice(self.allocator, role);
        }
        
        // Serialize timestamp
        var timestamp_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &timestamp_bytes, context.timestamp, .little);
        try buffer.appendSlice(self.allocator, &timestamp_bytes);
        
        // Serialize resource path
        try buffer.append(self.allocator, @intCast(context.resource_path.len));
        try buffer.appendSlice(self.allocator, context.resource_path);
        
        // Serialize operation
        try buffer.append(self.allocator, @intFromEnum(context.operation));
        
        return buffer.toOwnedSlice();
    }
    
    fn serializePermissionCheck(self: *const WasmPolicy, identity_id: []const u8, resource: []const u8, permission: guardian.Permission) ![]u8 {
        var buffer = std.ArrayList(u8){};
        defer buffer.deinit(self.allocator);
        
        try buffer.append(self.allocator, @intCast(identity_id.len));
        try buffer.appendSlice(self.allocator, identity_id);
        
        try buffer.append(self.allocator, @intCast(resource.len));
        try buffer.appendSlice(self.allocator, resource);
        
        try buffer.append(self.allocator, @intFromEnum(permission));
        
        return buffer.toOwnedSlice();
    }
};

pub const WasmRuntime = struct {
    memory: []u8,
    module_loaded: bool,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) WasmRuntime {
        return WasmRuntime{
            .memory = &[_]u8{},
            .module_loaded = false,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *WasmRuntime) void {
        if (self.memory.len > 0) {
            self.allocator.free(self.memory);
        }
    }
    
    pub fn loadModule(self: *WasmRuntime, wasm_bytes: []const u8) WasmError!void {
        // Validate WASM module structure
        if (wasm_bytes.len < 8) return WasmError.InvalidWasmModule;
        
        // Allocate initial memory for WASM execution
        const initial_memory_size = WasmPolicy.WASM_PAGE_SIZE;
        self.memory = try self.allocator.alloc(u8, initial_memory_size);
        std.mem.set(u8, self.memory, 0);
        
        self.module_loaded = true;
    }
    
    pub fn callFunction(self: *WasmRuntime, function_name: []const u8, params: []const u8) WasmError!u32 {
        if (!self.module_loaded) return WasmError.ModuleLoadFailed;
        
        // Simulate WASM function execution based on function name
        if (std.mem.eql(u8, function_name, "evaluate")) {
            return self.evaluateFunction(params);
        } else if (std.mem.eql(u8, function_name, "validate_permission")) {
            return self.validatePermissionFunction(params);
        } else {
            return WasmError.FunctionNotFound;
        }
    }
    
    fn evaluateFunction(self: *WasmRuntime, params: []const u8) WasmError!u32 {
        _ = self;
        // Parse serialized context
        if (params.len < 2) return WasmError.InvalidParameters;
        
        var offset: usize = 0;
        
        // Parse user_id
        const user_id_len = params[offset];
        offset += 1;
        if (offset + user_id_len > params.len) return WasmError.InvalidParameters;
        const user_id = params[offset..offset + user_id_len];
        offset += user_id_len;
        
        // Parse roles count
        if (offset >= params.len) return WasmError.InvalidParameters;
        const roles_count = params[offset];
        offset += 1;
        
        // Skip roles parsing for simplicity
        var i: u8 = 0;
        while (i < roles_count and offset < params.len) : (i += 1) {
            const role_len = params[offset];
            offset += 1 + role_len;
            if (offset > params.len) return WasmError.InvalidParameters;
        }
        
        // Simple policy evaluation logic
        // Grant access to admin users and deny others
        const is_admin = std.mem.eql(u8, user_id, "admin") or std.mem.eql(u8, user_id, "root");
        return if (is_admin) 1 else 0;
    }
    
    fn validatePermissionFunction(self: *WasmRuntime, params: []const u8) WasmError!u32 {
        _ = self;
        if (params.len < 3) return WasmError.InvalidParameters;
        
        var offset: usize = 0;
        
        // Parse identity_id
        const identity_len = params[offset];
        offset += 1;
        if (offset + identity_len > params.len) return WasmError.InvalidParameters;
        const identity_id = params[offset..offset + identity_len];
        offset += identity_len;
        
        // Parse resource
        if (offset >= params.len) return WasmError.InvalidParameters;
        const resource_len = params[offset];
        offset += 1;
        if (offset + resource_len > params.len) return WasmError.InvalidParameters;
        const resource = params[offset..offset + resource_len];
        offset += resource_len;
        
        // Parse permission
        if (offset >= params.len) return WasmError.InvalidParameters;
        const permission_value = params[offset];
        
        // Simple permission validation
        // Allow read for everyone, write for specific users
        if (permission_value == @intFromEnum(guardian.Permission.read)) {
            return 1; // Always allow read
        }
        
        if (permission_value == @intFromEnum(guardian.Permission.write)) {
            // Allow write for admin users or users accessing their own resources
            const is_admin = std.mem.eql(u8, identity_id, "admin");
            const owns_resource = std.mem.startsWith(u8, resource, identity_id);
            return if (is_admin or owns_resource) 1 else 0;
        }
        
        return 0; // Deny by default
    }
};

pub const WasmGuardian = struct {
    policy_engine: WasmPolicyEngine,
    fallback_guardian: guardian.Guardian,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) WasmGuardian {
        return WasmGuardian{
            .policy_engine = WasmPolicyEngine.init(allocator),
            .fallback_guardian = guardian.Guardian.init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *WasmGuardian) void {
        self.policy_engine.deinit();
        self.fallback_guardian.deinit();
    }
    
    pub fn loadWasmPolicy(self: *WasmGuardian, name: []const u8, wasm_bytes: []const u8) WasmError!void {
        try self.policy_engine.loadPolicy(name, wasm_bytes);
    }
    
    pub fn canAccess(self: *WasmGuardian, context: *const guardian.AccessContext, policy_name: ?[]const u8) !bool {
        if (policy_name) |name| {
            // Try WASM policy first
            const wasm_result = self.policy_engine.evaluatePolicy(name, context) catch |err| switch (err) {
                WasmError.FunctionNotFound => return self.fallback_guardian.canAccess(context),
                else => return err,
            };
            return wasm_result;
        } else {
            // Use fallback guardian
            return self.fallback_guardian.canAccess(context);
        }
    }
    
    pub fn addRole(self: *WasmGuardian, name: []const u8, permissions: []const guardian.Permission) !void {
        try self.fallback_guardian.addRole(name, permissions);
    }
    
    pub fn validateRole(self: *WasmGuardian, role_name: []const u8) bool {
        return self.fallback_guardian.validateRole(role_name);
    }
};

pub const WasmCompiler = struct {
    pub fn compilePolicy(allocator: std.mem.Allocator, source_code: []const u8, language: PolicyLanguage) WasmError![]u8 {
        // Simulate WASM compilation from high-level policy language
        switch (language) {
            .simple => return compileSimplePolicy(allocator, source_code),
            .rego => return compileRegoPolicy(allocator, source_code),
            .javascript => return compileJavaScriptPolicy(allocator, source_code),
        }
    }
    
    const PolicyLanguage = enum {
        simple,
        rego,
        javascript,
    };
    
    fn compileSimplePolicy(allocator: std.mem.Allocator, source: []const u8) WasmError![]u8 {
        _ = source;
        // Create a minimal WASM module for simple policies
        // Basic WASM module structure with function exports
        const wasm_module = [_]u8{
            // WASM header
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            
            // Type section
            0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
            
            // Function section
            0x03, 0x02, 0x01, 0x00,
            
            // Export section
            0x07, 0x11, 0x01, 0x08, 0x65, 0x76, 0x61, 0x6C, 0x75, 0x61, 0x74, 0x65, 0x00, 0x00,
            
            // Code section
            0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
        };
        
        return try allocator.dupe(u8, &wasm_module);
    }
    
    fn compileRegoPolicy(allocator: std.mem.Allocator, source: []const u8) WasmError![]u8 {
        // Placeholder for Rego to WASM compilation
        return compileSimplePolicy(allocator, source);
    }
    
    fn compileJavaScriptPolicy(allocator: std.mem.Allocator, source: []const u8) WasmError![]u8 {
        // Placeholder for JavaScript to WASM compilation
        return compileSimplePolicy(allocator, source);
    }
};

pub fn createDefaultWasmPolicy(allocator: std.mem.Allocator) WasmError![]u8 {
    const simple_policy = 
        \\allow if user.role == "admin"
        \\allow if resource.owner == user.id and operation == "read"
        \\deny
    ;
    
    return WasmCompiler.compilePolicy(allocator, simple_policy, .simple);
}

pub fn version() []const u8 {
    return "0.1.0";
}