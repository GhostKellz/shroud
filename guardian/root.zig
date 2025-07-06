const std = @import("std");

pub const GuardianError = error{
    RuleValidationFailed,
    PolicyViolation,
    AccessDenied,
    InvalidPermission,
    RoleNotFound,
    PolicyNotFound,
    InsufficientPrivileges,
    OperationBlocked,
    QuotaExceeded,
    TimeWindowViolation,
};

pub const Permission = enum {
    read,
    write,
    execute,
    admin,
    transfer,
    deploy,
    upgrade,
    delegate,
    
    pub fn toString(self: Permission) []const u8 {
        return switch (self) {
            .read => "read",
            .write => "write", 
            .execute => "execute",
            .admin => "admin",
            .transfer => "transfer",
            .deploy => "deploy",
            .upgrade => "upgrade",
            .delegate => "delegate",
        };
    }
};

pub const Role = struct {
    name: []const u8,
    permissions: std.ArrayList(Permission),
    inherits_from: ?[]const u8,
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8) Role {
        return Role{
            .name = name,
            .permissions = std.ArrayList(Permission).init(allocator),
            .inherits_from = null,
        };
    }
    
    pub fn deinit(self: *Role) void {
        self.permissions.deinit();
    }
    
    pub fn addPermission(self: *Role, permission: Permission) !void {
        try self.permissions.append(permission);
    }
    
    pub fn hasPermission(self: *const Role, permission: Permission) bool {
        for (self.permissions.items) |perm| {
            if (perm == permission) return true;
        }
        return false;
    }
};

pub const AccessRule = struct {
    resource: []const u8,
    required_permission: Permission,
    conditions: std.ArrayList(Condition),
    priority: u8,
    
    pub fn init(allocator: std.mem.Allocator, resource: []const u8, permission: Permission) AccessRule {
        return AccessRule{
            .resource = resource,
            .required_permission = permission,
            .conditions = std.ArrayList(Condition).init(allocator),
            .priority = 50, // Default priority
        };
    }
    
    pub fn deinit(self: *AccessRule) void {
        self.conditions.deinit();
    }
    
    pub fn addCondition(self: *AccessRule, condition: Condition) !void {
        try self.conditions.append(condition);
    }
};

pub const ConditionType = enum {
    time_window,
    ip_allowlist,
    rate_limit,
    balance_minimum,
    stake_requirement,
    multi_sig_required,
};

pub const Condition = struct {
    type: ConditionType,
    params: std.HashMap([]const u8, []const u8, std.hash_map.HashMap([]const u8, []const u8).Context, std.hash_map.default_max_load_percentage),
    
    pub fn init(allocator: std.mem.Allocator, condition_type: ConditionType) Condition {
        return Condition{
            .type = condition_type,
            .params = std.HashMap([]const u8, []const u8, std.hash_map.HashMap([]const u8, []const u8).Context, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *Condition) void {
        self.params.deinit();
    }
    
    pub fn setParam(self: *Condition, key: []const u8, value: []const u8) !void {
        try self.params.put(key, value);
    }
};

pub const AccessContext = struct {
    user_id: []const u8,
    roles: std.ArrayList([]const u8),
    timestamp: u64,
    ip_address: ?[]const u8,
    user_agent: ?[]const u8,
    resource_path: []const u8,
    operation: Permission,
    metadata: std.HashMap([]const u8, []const u8, std.hash_map.HashMap([]const u8, []const u8).Context, std.hash_map.default_max_load_percentage),
    
    pub fn init(allocator: std.mem.Allocator, user_id: []const u8, resource: []const u8, operation: Permission) AccessContext {
        return AccessContext{
            .user_id = user_id,
            .roles = std.ArrayList([]const u8).init(allocator),
            .timestamp = @intCast(std.time.timestamp()),
            .ip_address = null,
            .user_agent = null,
            .resource_path = resource,
            .operation = operation,
            .metadata = std.HashMap([]const u8, []const u8, std.hash_map.HashMap([]const u8, []const u8).Context, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *AccessContext) void {
        self.roles.deinit();
        self.metadata.deinit();
    }
    
    pub fn addRole(self: *AccessContext, role: []const u8) !void {
        try self.roles.append(role);
    }
    
    pub fn hasRole(self: *const AccessContext, role: []const u8) bool {
        for (self.roles.items) |r| {
            if (std.mem.eql(u8, r, role)) return true;
        }
        return false;
    }
};

pub const PolicyEngine = struct {
    roles: std.HashMap([]const u8, Role, std.hash_map.HashMap([]const u8, Role).Context, std.hash_map.default_max_load_percentage),
    rules: std.ArrayList(AccessRule),
    rate_limits: std.HashMap([]const u8, RateLimit, std.hash_map.HashMap([]const u8, RateLimit).Context, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) PolicyEngine {
        return PolicyEngine{
            .roles = std.HashMap([]const u8, Role, std.hash_map.HashMap([]const u8, Role).Context, std.hash_map.default_max_load_percentage).init(allocator),
            .rules = std.ArrayList(AccessRule).init(allocator),
            .rate_limits = std.HashMap([]const u8, RateLimit, std.hash_map.HashMap([]const u8, RateLimit).Context, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *PolicyEngine) void {
        var role_iter = self.roles.iterator();
        while (role_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.roles.deinit();
        
        for (self.rules.items) |*rule| {
            rule.deinit();
        }
        self.rules.deinit();
        
        self.rate_limits.deinit();
    }
    
    pub fn addRole(self: *PolicyEngine, name: []const u8, permissions: []const Permission) !void {
        var role = Role.init(self.allocator, name);
        for (permissions) |permission| {
            try role.addPermission(permission);
        }
        try self.roles.put(name, role);
    }
    
    pub fn addRule(self: *PolicyEngine, resource: []const u8, permission: Permission) !void {
        const rule = AccessRule.init(self.allocator, resource, permission);
        try self.rules.append(rule);
    }
    
    pub fn checkAccess(self: *PolicyEngine, context: *const AccessContext) GuardianError!bool {
        // Check rate limits first
        if (try self.checkRateLimit(context.user_id)) {
            return GuardianError.QuotaExceeded;
        }
        
        // Find applicable rules
        for (self.rules.items) |rule| {
            if (self.resourceMatches(rule.resource, context.resource_path)) {
                if (rule.required_permission == context.operation) {
                    return try self.evaluateRule(&rule, context);
                }
            }
        }
        
        // Default deny
        return false;
    }
    
    fn evaluateRule(self: *PolicyEngine, rule: *const AccessRule, context: *const AccessContext) GuardianError!bool {
        // Check if user has required permission through roles
        for (context.roles.items) |role_name| {
            if (self.roles.get(role_name)) |role| {
                if (role.hasPermission(rule.required_permission)) {
                    // Check conditions
                    for (rule.conditions.items) |condition| {
                        if (!try self.evaluateCondition(&condition, context)) {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }
        
        return false;
    }
    
    fn evaluateCondition(self: *PolicyEngine, condition: *const Condition, context: *const AccessContext) GuardianError!bool {
        return switch (condition.type) {
            .time_window => self.checkTimeWindow(condition, context),
            .ip_allowlist => self.checkIPAllowlist(condition, context),
            .rate_limit => true, // Already checked at start
            .balance_minimum => self.checkBalanceMinimum(condition, context),
            .stake_requirement => self.checkStakeRequirement(condition, context),
            .multi_sig_required => self.checkMultiSigRequired(condition, context),
        };
    }
    
    fn checkTimeWindow(self: *PolicyEngine, condition: *const Condition, context: *const AccessContext) bool {
        _ = self;
        _ = condition;
        _ = context;
        // Implement time window checking
        return true;
    }
    
    fn checkIPAllowlist(self: *PolicyEngine, condition: *const Condition, context: *const AccessContext) bool {
        _ = self;
        _ = condition;
        _ = context;
        // Implement IP allowlist checking
        return true;
    }
    
    fn checkBalanceMinimum(self: *PolicyEngine, condition: *const Condition, context: *const AccessContext) bool {
        _ = self;
        _ = condition;
        _ = context;
        // Implement balance checking
        return true;
    }
    
    fn checkStakeRequirement(self: *PolicyEngine, condition: *const Condition, context: *const AccessContext) bool {
        _ = self;
        _ = condition;
        _ = context;
        // Implement stake checking
        return true;
    }
    
    fn checkMultiSigRequired(self: *PolicyEngine, condition: *const Condition, context: *const AccessContext) bool {
        _ = self;
        _ = condition;
        _ = context;
        // Implement multi-sig checking
        return true;
    }
    
    fn resourceMatches(self: *PolicyEngine, pattern: []const u8, resource: []const u8) bool {
        _ = self;
        // Simple pattern matching - could be expanded to support wildcards
        return std.mem.eql(u8, pattern, resource) or std.mem.eql(u8, pattern, "*");
    }
    
    fn checkRateLimit(self: *PolicyEngine, user_id: []const u8) !bool {
        if (self.rate_limits.getPtr(user_id)) |limit| {
            const now = @as(u64, @intCast(std.time.timestamp()));
            if (now - limit.window_start > limit.window_seconds) {
                // Reset window
                limit.window_start = now;
                limit.requests_in_window = 0;
            }
            
            if (limit.requests_in_window >= limit.max_requests) {
                return true; // Rate limited
            }
            
            limit.requests_in_window += 1;
        }
        
        return false; // Not rate limited
    }
};

pub const RateLimit = struct {
    max_requests: u32,
    window_seconds: u64,
    window_start: u64,
    requests_in_window: u32,
    
    pub fn init(max_requests: u32, window_seconds: u64) RateLimit {
        return RateLimit{
            .max_requests = max_requests,
            .window_seconds = window_seconds,
            .window_start = @intCast(std.time.timestamp()),
            .requests_in_window = 0,
        };
    }
};

pub fn version() []const u8 {
    return "0.3.0";
}

pub fn createPolicyEngine(allocator: std.mem.Allocator) PolicyEngine {
    return PolicyEngine.init(allocator);
}

pub fn createBasicRoles(engine: *PolicyEngine) !void {
    try engine.addRole("admin", &[_]Permission{ .read, .write, .execute, .admin, .deploy, .upgrade });
    try engine.addRole("user", &[_]Permission{ .read, .write });
    try engine.addRole("viewer", &[_]Permission{.read});
    try engine.addRole("operator", &[_]Permission{ .read, .write, .execute });
}

test "guardian policy engine" {
    var engine = createPolicyEngine(std.testing.allocator);
    defer engine.deinit();
    
    try createBasicRoles(&engine);
    try engine.addRule("*", .read);
    
    var context = AccessContext.init(std.testing.allocator, "user123", "/api/data", .read);
    defer context.deinit();
    
    try context.addRole("user");
    
    const allowed = try engine.checkAccess(&context);
    try std.testing.expect(allowed);
}

test "guardian role permissions" {
    var engine = createPolicyEngine(std.testing.allocator);
    defer engine.deinit();
    
    try engine.addRole("test_role", &[_]Permission{ .read, .write });
    
    const role = engine.roles.get("test_role").?;
    try std.testing.expect(role.hasPermission(.read));
    try std.testing.expect(role.hasPermission(.write));
    try std.testing.expect(!role.hasPermission(.admin));
}