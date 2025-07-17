//! Policy Engine with Templates and Dynamic Evaluation
//! Advanced policy management for complex authorization scenarios

const std = @import("std");
const guardian = @import("guardian.zig");
const advanced_tokens = @import("advanced_tokens.zig");

/// Policy template for common use cases
pub const PolicyTemplate = struct {
    name: []const u8,
    description: []const u8,
    permissions: std.ArrayList(TemplatePermission),
    conditions: std.ArrayList(TemplateCondition),
    parameters: std.HashMap([]const u8, ParameterDefinition, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    version: []const u8,
    allocator: std.mem.Allocator,

    pub const TemplatePermission = struct {
        permission_pattern: []const u8,
        required: bool,
        description: []const u8,
    };

    pub const TemplateCondition = struct {
        condition_type: ConditionType,
        parameters: []const []const u8,
        description: []const u8,

        pub const ConditionType = enum {
            time_restriction,
            amount_limit,
            location_check,
            device_verification,
            multi_party_approval,
        };
    };

    pub const ParameterDefinition = struct {
        name: []const u8,
        type: ParameterType,
        required: bool,
        default_value: ?[]const u8,
        description: []const u8,

        pub const ParameterType = enum {
            string,
            number,
            boolean,
            array,
        };
    };

    pub fn init(allocator: std.mem.Allocator, name: []const u8, description: []const u8, version: []const u8) PolicyTemplate {
        return PolicyTemplate{
            .name = name,
            .description = description,
            .permissions = std.ArrayList(TemplatePermission).init(allocator),
            .conditions = std.ArrayList(TemplateCondition).init(allocator),
            .parameters = std.HashMap([]const u8, ParameterDefinition, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .version = version,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PolicyTemplate) void {
        self.permissions.deinit();
        self.conditions.deinit();
        self.parameters.deinit();
    }

    pub fn addPermission(self: *PolicyTemplate, permission: TemplatePermission) !void {
        try self.permissions.append(permission);
    }

    pub fn addCondition(self: *PolicyTemplate, condition: TemplateCondition) !void {
        try self.conditions.append(condition);
    }

    pub fn addParameter(self: *PolicyTemplate, name: []const u8, param: ParameterDefinition) !void {
        try self.parameters.put(name, param);
    }

    /// Instantiate policy from template with given parameters
    pub fn instantiate(self: *const PolicyTemplate, params: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage)) !Policy {
        var policy = Policy.init(self.allocator, self.name, self.description);

        // Process template permissions
        for (self.permissions.items) |template_perm| {
            const resolved_pattern = try self.resolveParameters(template_perm.permission_pattern, params);
            defer self.allocator.free(resolved_pattern);

            const policy_perm = Policy.PolicyPermission{
                .permission = try advanced_tokens.HierarchicalPermission.init(self.allocator, resolved_pattern),
                .required = template_perm.required,
            };
            try policy.addPermission(policy_perm);
        }

        // Process template conditions
        for (self.conditions.items) |template_cond| {
            const policy_cond = try self.instantiateCondition(template_cond, params);
            try policy.addCondition(policy_cond);
        }

        return policy;
    }

    fn resolveParameters(self: *const PolicyTemplate, pattern: []const u8, params: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage)) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        var i: usize = 0;
        while (i < pattern.len) {
            if (pattern[i] == '{' and i + 1 < pattern.len) {
                // Find parameter end
                var param_end = i + 1;
                while (param_end < pattern.len and pattern[param_end] != '}') {
                    param_end += 1;
                }

                if (param_end < pattern.len) {
                    const param_name = pattern[i + 1..param_end];
                    if (params.get(param_name)) |value| {
                        try result.appendSlice(value);
                    } else {
                        // Check for default value
                        if (self.parameters.get(param_name)) |param_def| {
                            if (param_def.default_value) |default| {
                                try result.appendSlice(default);
                            } else {
                                return error.MissingRequiredParameter;
                            }
                        } else {
                            return error.UnknownParameter;
                        }
                    }
                    i = param_end + 1;
                    continue;
                }
            }
            try result.append(pattern[i]);
            i += 1;
        }

        return try result.toOwnedSlice();
    }

    fn instantiateCondition(self: *const PolicyTemplate, template_cond: TemplateCondition, params: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage)) !Policy.PolicyCondition {
        _ = self;
        _ = params;

        // Simplified condition instantiation
        return Policy.PolicyCondition{
            .condition_type = template_cond.condition_type,
            .active = true,
        };
    }
};

/// Dynamic policy with runtime evaluation
pub const Policy = struct {
    name: []const u8,
    description: []const u8,
    permissions: std.ArrayList(PolicyPermission),
    conditions: std.ArrayList(PolicyCondition),
    conflicts: std.ArrayList(PolicyConflict),
    version: u32,
    created_at: i64,
    updated_at: i64,
    allocator: std.mem.Allocator,

    pub const PolicyPermission = struct {
        permission: advanced_tokens.HierarchicalPermission,
        required: bool,
    };

    pub const PolicyCondition = struct {
        condition_type: PolicyTemplate.TemplateCondition.ConditionType,
        active: bool,
    };

    pub const PolicyConflict = struct {
        policy_a: []const u8,
        policy_b: []const u8,
        conflict_type: ConflictType,
        resolution: ConflictResolution,

        pub const ConflictType = enum {
            permission_overlap,
            condition_contradiction,
            hierarchy_violation,
        };

        pub const ConflictResolution = enum {
            prefer_policy_a,
            prefer_policy_b,
            merge_policies,
            deny_all,
            require_manual,
        };
    };

    pub fn init(allocator: std.mem.Allocator, name: []const u8, description: []const u8) Policy {
        return Policy{
            .name = name,
            .description = description,
            .permissions = std.ArrayList(PolicyPermission).init(allocator),
            .conditions = std.ArrayList(PolicyCondition).init(allocator),
            .conflicts = std.ArrayList(PolicyConflict).init(allocator),
            .version = 1,
            .created_at = std.time.milliTimestamp(),
            .updated_at = std.time.milliTimestamp(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Policy) void {
        for (self.permissions.items) |*perm| {
            perm.permission.deinit();
        }
        self.permissions.deinit();
        self.conditions.deinit();
        self.conflicts.deinit();
    }

    pub fn addPermission(self: *Policy, permission: PolicyPermission) !void {
        try self.permissions.append(permission);
        self.updated_at = std.time.milliTimestamp();
    }

    pub fn addCondition(self: *Policy, condition: PolicyCondition) !void {
        try self.conditions.append(condition);
        self.updated_at = std.time.milliTimestamp();
    }

    pub fn addConflict(self: *Policy, conflict: PolicyConflict) !void {
        try self.conflicts.append(conflict);
    }

    /// Evaluate policy against context
    pub fn evaluate(self: *const Policy, context: *const advanced_tokens.PermissionContext, requested_permission: *const advanced_tokens.HierarchicalPermission) PolicyEvaluationResult {
        var result = PolicyEvaluationResult.init(self.allocator);

        // Check if policy grants the requested permission
        var permission_granted = false;
        for (self.permissions.items) |*policy_perm| {
            if (policy_perm.permission.matches(requested_permission)) {
                permission_granted = true;
                break;
            }
        }

        if (!permission_granted) {
            result.decision = .deny;
            result.reason = "Permission not granted by policy";
            return result;
        }

        // Evaluate conditions
        for (self.conditions.items) |condition| {
            if (!condition.active) continue;

            const condition_result = self.evaluateCondition(condition, context);
            if (!condition_result) {
                result.decision = .deny;
                result.reason = "Policy condition not met";
                return result;
            }
        }

        result.decision = .allow;
        result.reason = "All policy requirements satisfied";
        return result;
    }

    fn evaluateCondition(self: *const Policy, condition: PolicyCondition, context: *const advanced_tokens.PermissionContext) bool {
        _ = self;
        
        switch (condition.condition_type) {
            .time_restriction => {
                // Simple time check - allow during business hours
                const current_hour = @mod(@divTrunc(context.timestamp, 3600), 24);
                return current_hour >= 9 and current_hour <= 17;
            },
            .amount_limit => {
                // Simple amount check
                return context.transaction_amount <= 10000;
            },
            .location_check => {
                // Simple location check
                return context.user_country == null or std.mem.eql(u8, context.user_country.?, "US");
            },
            .device_verification => {
                // Simple device check
                return context.device_type != null;
            },
            .multi_party_approval => {
                // Simplified - always require approval for high amounts
                return context.transaction_amount <= 1000;
            },
        }
    }
};

/// Policy evaluation result
pub const PolicyEvaluationResult = struct {
    decision: Decision,
    reason: []const u8,
    applied_policies: std.ArrayList([]const u8),
    conflicts_detected: std.ArrayList(Policy.PolicyConflict),
    allocator: std.mem.Allocator,

    pub const Decision = enum {
        allow,
        deny,
        conditional,
        require_approval,
    };

    pub fn init(allocator: std.mem.Allocator) PolicyEvaluationResult {
        return PolicyEvaluationResult{
            .decision = .deny,
            .reason = "",
            .applied_policies = std.ArrayList([]const u8).init(allocator),
            .conflicts_detected = std.ArrayList(Policy.PolicyConflict).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PolicyEvaluationResult) void {
        self.applied_policies.deinit();
        self.conflicts_detected.deinit();
    }
};

/// Policy engine with conflict resolution
pub const PolicyEngine = struct {
    policies: std.HashMap([]const u8, Policy, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    templates: std.HashMap([]const u8, PolicyTemplate, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    conflict_resolver: ConflictResolver,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PolicyEngine {
        return PolicyEngine{
            .policies = std.HashMap([]const u8, Policy, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .templates = std.HashMap([]const u8, PolicyTemplate, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .conflict_resolver = ConflictResolver.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PolicyEngine) void {
        var policy_iter = self.policies.iterator();
        while (policy_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.policies.deinit();

        var template_iter = self.templates.iterator();
        while (template_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.templates.deinit();

        self.conflict_resolver.deinit();
    }

    pub fn addPolicy(self: *PolicyEngine, name: []const u8, policy: Policy) !void {
        try self.policies.put(name, policy);
    }

    pub fn addTemplate(self: *PolicyEngine, name: []const u8, template: PolicyTemplate) !void {
        try self.templates.put(name, template);
    }

    /// Evaluate multiple policies for a permission request
    pub fn evaluatePermission(self: *PolicyEngine, context: *const advanced_tokens.PermissionContext, permission: *const advanced_tokens.HierarchicalPermission, applicable_policies: []const []const u8) !PolicyEvaluationResult {
        var results = std.ArrayList(PolicyEvaluationResult).init(self.allocator);
        defer {
            for (results.items) |*result| {
                result.deinit();
            }
            results.deinit();
        }

        // Evaluate each applicable policy
        for (applicable_policies) |policy_name| {
            if (self.policies.get(policy_name)) |*policy| {
                const result = policy.evaluate(context, permission);
                try results.append(result);
            }
        }

        // Resolve conflicts and combine results
        return try self.conflict_resolver.resolveConflicts(results.items);
    }

    /// Create pre-defined policy templates
    pub fn createStandardTemplates(self: *PolicyEngine) !void {
        // Admin Template
        var admin_template = PolicyTemplate.init(self.allocator, "admin", "Full administrative access", "1.0");
        try admin_template.addPermission(.{
            .permission_pattern = "admin.*",
            .required = true,
            .description = "Full admin access",
        });
        try self.addTemplate("admin", admin_template);

        // User Template
        var user_template = PolicyTemplate.init(self.allocator, "user", "Standard user access", "1.0");
        try user_template.addPermission(.{
            .permission_pattern = "user.{department}.read",
            .required = true,
            .description = "Read access to department resources",
        });
        try user_template.addParameter("department", .{
            .name = "department",
            .type = .string,
            .required = true,
            .default_value = null,
            .description = "User's department",
        });
        try self.addTemplate("user", user_template);

        // Payment Template
        var payment_template = PolicyTemplate.init(self.allocator, "payment", "Payment processing access", "1.0");
        try payment_template.addPermission(.{
            .permission_pattern = "payment.send",
            .required = true,
            .description = "Send payment permission",
        });
        try payment_template.addCondition(.{
            .condition_type = .amount_limit,
            .parameters = &[_][]const u8{"max_amount"},
            .description = "Limit transaction amounts",
        });
        try self.addTemplate("payment", payment_template);
    }
};

/// Conflict resolution system
pub const ConflictResolver = struct {
    resolution_strategies: std.HashMap([]const u8, ResolutionStrategy, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,

    pub const ResolutionStrategy = enum {
        deny_all,
        allow_any,
        require_unanimous,
        majority_wins,
        weighted_priority,
    };

    pub fn init(allocator: std.mem.Allocator) ConflictResolver {
        return ConflictResolver{
            .resolution_strategies = std.HashMap([]const u8, ResolutionStrategy, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConflictResolver) void {
        self.resolution_strategies.deinit();
    }

    pub fn setStrategy(self: *ConflictResolver, context: []const u8, strategy: ResolutionStrategy) !void {
        try self.resolution_strategies.put(context, strategy);
    }

    pub fn resolveConflicts(self: *ConflictResolver, results: []const PolicyEvaluationResult) !PolicyEvaluationResult {
        var final_result = PolicyEvaluationResult.init(self.allocator);

        if (results.len == 0) {
            final_result.decision = .deny;
            final_result.reason = "No applicable policies";
            return final_result;
        }

        if (results.len == 1) {
            final_result.decision = results[0].decision;
            final_result.reason = results[0].reason;
            return final_result;
        }

        // Simple conflict resolution: require unanimous allow
        var allow_count: u32 = 0;
        var deny_count: u32 = 0;

        for (results) |result| {
            switch (result.decision) {
                .allow => allow_count += 1,
                .deny => deny_count += 1,
                .conditional => {}, // Treat as neutral
                .require_approval => {}, // Treat as neutral
            }
        }

        if (deny_count > 0) {
            final_result.decision = .deny;
            final_result.reason = "One or more policies deny access";
        } else if (allow_count > 0) {
            final_result.decision = .allow;
            final_result.reason = "All applicable policies allow access";
        } else {
            final_result.decision = .conditional;
            final_result.reason = "Conditional access based on policies";
        }

        return final_result;
    }
};

test "policy template instantiation" {
    var template = PolicyTemplate.init(std.testing.allocator, "test", "Test template", "1.0");
    defer template.deinit();

    try template.addPermission(.{
        .permission_pattern = "user.{department}.read",
        .required = true,
        .description = "Department read access",
    });

    try template.addParameter("department", .{
        .name = "department",
        .type = .string,
        .required = true,
        .default_value = null,
        .description = "Department name",
    });

    var params = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(std.testing.allocator);
    defer params.deinit();
    try params.put("department", "engineering");

    var policy = try template.instantiate(params);
    defer policy.deinit();

    try std.testing.expect(policy.permissions.items.len == 1);
}

test "policy evaluation" {
    var policy = Policy.init(std.testing.allocator, "test", "Test policy");
    defer policy.deinit();

    const perm = try advanced_tokens.HierarchicalPermission.init(std.testing.allocator, "user.read");
    const policy_perm = Policy.PolicyPermission{
        .permission = perm,
        .required = true,
    };
    try policy.addPermission(policy_perm);

    const context = advanced_tokens.PermissionContext{
        .timestamp = std.time.milliTimestamp(),
        .transaction_amount = 100,
        .user_country = "US",
        .device_type = null,
        .transaction_type = null,
        .user_id = "test-user",
        .session_id = "test-session",
    };

    const requested_perm = try advanced_tokens.HierarchicalPermission.init(std.testing.allocator, "user.read.profile");
    defer {
        var mut_perm = requested_perm;
        mut_perm.deinit();
    }

    var result = policy.evaluate(&context, &requested_perm);
    defer result.deinit();

    try std.testing.expect(result.decision == .allow);
}

test "policy engine with conflict resolution" {
    var engine = PolicyEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.createStandardTemplates();

    // Create a test policy
    var policy = Policy.init(std.testing.allocator, "test", "Test policy");
    const perm = try advanced_tokens.HierarchicalPermission.init(std.testing.allocator, "admin.read");
    try policy.addPermission(.{
        .permission = perm,
        .required = true,
    });

    try engine.addPolicy("test", policy);

    const context = advanced_tokens.PermissionContext{
        .timestamp = std.time.milliTimestamp(),
        .transaction_amount = 100,
        .user_country = "US",
        .device_type = null,
        .transaction_type = null,
        .user_id = "admin-user",
        .session_id = "test-session",
    };

    const requested_perm = try advanced_tokens.HierarchicalPermission.init(std.testing.allocator, "admin.read.users");
    defer {
        var mut_perm = requested_perm;
        mut_perm.deinit();
    }

    const applicable_policies = [_][]const u8{"test"};
    var result = try engine.evaluatePermission(&context, &requested_perm, &applicable_policies);
    defer result.deinit();

    try std.testing.expect(result.decision == .allow);
}
