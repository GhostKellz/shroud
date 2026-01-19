//! Advanced Token Features with Hierarchical Permissions
//! Enhanced access control with delegation chains and conditional permissions

const std = @import("std");
const access_token = @import("access_token.zig");
const guardian = @import("guardian.zig");
const time_utils = @import("time_utils.zig");

/// Hierarchical permission structure (e.g., admin.ledger.read)
pub const HierarchicalPermission = struct {
    path: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, path_str: []const u8) !HierarchicalPermission {
        var parts = std.ArrayList([]const u8){};
        var iterator = std.mem.splitSequence(u8, path_str, ".");

        while (iterator.next()) |part| {
            try parts.append(allocator, try allocator.dupe(u8, part));
        }

        return HierarchicalPermission{
            .path = try parts.toOwnedSlice(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *const HierarchicalPermission) void {
        for (self.path) |part| {
            self.allocator.free(part);
        }
        self.allocator.free(self.path);
    }

    pub fn toString(self: *const HierarchicalPermission, buffer: []u8) ![]u8 {
        var written: usize = 0;
        for (self.path, 0..) |part, i| {
            if (i > 0) {
                if (written >= buffer.len) return error.BufferTooSmall;
                buffer[written] = '.';
                written += 1;
            }
            if (written + part.len > buffer.len) return error.BufferTooSmall;
            @memcpy(buffer[written .. written + part.len], part);
            written += part.len;
        }
        return buffer[0..written];
    }

    /// Check if this permission is a parent of another permission
    pub fn isParentOf(self: *const HierarchicalPermission, other: *const HierarchicalPermission) bool {
        if (self.path.len >= other.path.len) return false;

        for (self.path, 0..) |part, i| {
            if (!std.mem.eql(u8, part, other.path[i])) return false;
        }
        return true;
    }

    /// Check if this permission matches another (exact or parent)
    pub fn matches(self: *const HierarchicalPermission, other: *const HierarchicalPermission) bool {
        return self.isParentOf(other) or self.isExactMatch(other);
    }

    /// Check if this permission exactly matches another
    pub fn isExactMatch(self: *const HierarchicalPermission, other: *const HierarchicalPermission) bool {
        if (self.path.len != other.path.len) return false;

        for (self.path, other.path) |self_part, other_part| {
            if (!std.mem.eql(u8, self_part, other_part)) {
                return false;
            }
        }
        return true;
    }

    /// Get depth of permission hierarchy
    pub fn depth(self: *const HierarchicalPermission) usize {
        return self.path.len;
    }
};

/// Conditional permission based on context
pub const ConditionalPermission = struct {
    base_permission: HierarchicalPermission,
    conditions: std.ArrayList(Condition),
    allocator: std.mem.Allocator,

    pub const Condition = union(enum) {
        time_range: TimeRange,
        amount_limit: AmountLimit,
        location_restriction: LocationRestriction,
        device_binding: DeviceBinding,
        transaction_type: TransactionType,

        pub const TimeRange = struct {
            start_hour: u8, // 0-23
            end_hour: u8, // 0-23
            days_of_week: u8, // Bitmask: Sunday=1, Monday=2, etc.
        };

        pub const AmountLimit = struct {
            max_amount: u64,
            currency: []const u8,
            time_window_seconds: u64,
        };

        pub const LocationRestriction = struct {
            allowed_countries: []const []const u8,
            blocked_countries: []const []const u8,
        };

        pub const DeviceBinding = struct {
            required_device_types: []const DeviceType,
            max_devices: u32,
        };

        pub const TransactionType = struct {
            allowed_types: []const []const u8,
            blocked_types: []const []const u8,
        };

        pub const DeviceType = enum {
            mobile,
            desktop,
            hardware_wallet,
            server,
        };
    };

    pub fn init(allocator: std.mem.Allocator, permission: HierarchicalPermission) ConditionalPermission {
        return ConditionalPermission{
            .base_permission = permission,
            .conditions = std.ArrayList(Condition){},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConditionalPermission) void {
        self.base_permission.deinit();
        self.conditions.deinit(self.allocator);
    }

    pub fn addCondition(self: *ConditionalPermission, condition: Condition) !void {
        try self.conditions.append(self.allocator, condition);
    }

    /// Evaluate if permission is granted given current context
    pub fn evaluate(self: *const ConditionalPermission, context: *const PermissionContext) bool {
        for (self.conditions.items) |condition| {
            if (!self.evaluateCondition(condition, context)) return false;
        }
        return true;
    }

    fn evaluateCondition(self: *const ConditionalPermission, condition: Condition, context: *const PermissionContext) bool {
        _ = self; // Suppress unused parameter warning

        switch (condition) {
            .time_range => |time_range| {
                const current_time = std.time.timestamp();
                const current_hour = @mod(@divTrunc(current_time, 3600), 24);
                return current_hour >= time_range.start_hour and current_hour <= time_range.end_hour;
            },
            .amount_limit => |amount_limit| {
                return context.transaction_amount <= amount_limit.max_amount;
            },
            .location_restriction => |location| {
                if (context.user_country) |country| {
                    // Check if country is in allowed list
                    for (location.allowed_countries) |allowed| {
                        if (std.mem.eql(u8, country, allowed)) return true;
                    }
                    // Check if country is in blocked list
                    for (location.blocked_countries) |blocked| {
                        if (std.mem.eql(u8, country, blocked)) return false;
                    }
                }
                return location.allowed_countries.len == 0; // Allow if no restrictions
            },
            .device_binding => |device| {
                if (context.device_type) |dev_type| {
                    for (device.required_device_types) |required| {
                        if (dev_type == required) return true;
                    }
                }
                return device.required_device_types.len == 0;
            },
            .transaction_type => |tx_type| {
                if (context.transaction_type) |tx| {
                    // Check allowed types
                    if (tx_type.allowed_types.len > 0) {
                        for (tx_type.allowed_types) |allowed| {
                            if (std.mem.eql(u8, tx, allowed)) return true;
                        }
                        return false;
                    }
                    // Check blocked types
                    for (tx_type.blocked_types) |blocked| {
                        if (std.mem.eql(u8, tx, blocked)) return false;
                    }
                }
                return true;
            },
        }
    }
};

/// Context for permission evaluation
pub const PermissionContext = struct {
    timestamp: i64,
    transaction_amount: u64,
    user_country: ?[]const u8,
    device_type: ?ConditionalPermission.Condition.DeviceType,
    transaction_type: ?[]const u8,
    user_id: []const u8,
    session_id: []const u8,
};

/// Token delegation chain (A → B → C)
pub const DelegationChain = struct {
    links: std.ArrayList(DelegationLink),
    max_depth: u32,
    allocator: std.mem.Allocator,

    pub const DelegationLink = struct {
        delegator: []const u8,
        delegate: []const u8,
        permissions: std.ArrayList(HierarchicalPermission),
        conditions: std.ArrayList(ConditionalPermission),
        expires_at: i64,
        signature: access_token.Signature,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, delegator: []const u8, delegate: []const u8, expires_in_seconds: u64) DelegationLink {
            const expires_at = time_utils.milliTimestamp() + (@as(i64, @intCast(expires_in_seconds)) * 1000);
            return DelegationLink{
                .delegator = delegator,
                .delegate = delegate,
                .permissions = std.ArrayList(HierarchicalPermission){},
                .conditions = std.ArrayList(ConditionalPermission){},
                .expires_at = expires_at,
                .signature = access_token.Signature{ .bytes = std.mem.zeroes([64]u8) },
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *DelegationLink) void {
            for (self.permissions.items) |*perm| {
                perm.deinit();
            }
            self.permissions.deinit(self.allocator);
            for (self.conditions.items) |*cond| {
                cond.deinit();
            }
            self.conditions.deinit(self.allocator);
        }

        pub fn isExpired(self: *const DelegationLink) bool {
            return time_utils.milliTimestamp() > self.expires_at;
        }

        pub fn addPermission(self: *DelegationLink, permission: HierarchicalPermission) !void {
            try self.permissions.append(self.allocator, permission);
        }

        pub fn addConditionalPermission(self: *DelegationLink, condition: ConditionalPermission) !void {
            try self.conditions.append(self.allocator, condition);
        }
    };

    pub fn init(allocator: std.mem.Allocator, max_depth: u32) DelegationChain {
        return DelegationChain{
            .links = std.ArrayList(DelegationLink){},
            .max_depth = max_depth,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DelegationChain) void {
        for (self.links.items) |*link| {
            link.deinit();
        }
        self.links.deinit(self.allocator);
    }

    pub fn addLink(self: *DelegationChain, link: DelegationLink) !void {
        if (self.links.items.len >= self.max_depth) {
            return error.MaxDepthExceeded;
        }
        try self.links.append(self.allocator, link);
    }

    /// Validate the entire delegation chain
    pub fn validate(self: *const DelegationChain) bool {
        // Check each link is not expired
        for (self.links.items) |link| {
            if (link.isExpired()) return false;
        }

        // Check delegation continuity (delegate of link N is delegator of link N+1)
        for (self.links.items[0 .. self.links.items.len - 1], 1..) |link, i| {
            const next_link = self.links.items[i];
            if (!std.mem.eql(u8, link.delegate, next_link.delegator)) {
                return false;
            }
        }

        return true;
    }

    /// Check if chain grants specific permission
    pub fn hasPermission(self: *const DelegationChain, permission: *const HierarchicalPermission, context: *const PermissionContext) bool {
        if (!self.validate()) return false;

        // Permission must exist in ALL links of the chain
        for (self.links.items) |link| {
            var found = false;

            // Check direct permissions
            for (link.permissions.items) |*link_perm| {
                if (link_perm.matches(permission)) {
                    found = true;
                    break;
                }
            }

            // Check conditional permissions
            if (!found) {
                for (link.conditions.items) |*cond_perm| {
                    if (cond_perm.base_permission.matches(permission) and cond_perm.evaluate(context)) {
                        found = true;
                        break;
                    }
                }
            }

            if (!found) return false;
        }

        return true;
    }
};

/// Advanced access token with enhanced features
pub const AdvancedAccessToken = struct {
    base_token: access_token.AccessToken,
    hierarchical_permissions: std.ArrayList(HierarchicalPermission),
    conditional_permissions: std.ArrayList(ConditionalPermission),
    delegation_chain: ?DelegationChain,
    refresh_token: ?[]const u8,
    scope_restrictions: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, user_id: []const u8, expires_in_seconds: u64) AdvancedAccessToken {
        return AdvancedAccessToken{
            .base_token = access_token.AccessToken.init(allocator, user_id, expires_in_seconds),
            .hierarchical_permissions = std.ArrayList(HierarchicalPermission){},
            .conditional_permissions = std.ArrayList(ConditionalPermission){},
            .delegation_chain = null,
            .refresh_token = null,
            .scope_restrictions = std.ArrayList([]const u8){},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AdvancedAccessToken) void {
        self.base_token.deinit();
        for (self.hierarchical_permissions.items) |*perm| {
            perm.deinit();
        }
        self.hierarchical_permissions.deinit(self.allocator);
        for (self.conditional_permissions.items) |*cond| {
            cond.deinit();
        }
        self.conditional_permissions.deinit(self.allocator);
        if (self.delegation_chain) |*chain| {
            chain.deinit();
        }
        self.scope_restrictions.deinit(self.allocator);
    }

    pub fn addHierarchicalPermission(self: *AdvancedAccessToken, permission: HierarchicalPermission) !void {
        try self.hierarchical_permissions.append(self.allocator, permission);
    }

    pub fn addConditionalPermission(self: *AdvancedAccessToken, permission: ConditionalPermission) !void {
        try self.conditional_permissions.append(self.allocator, permission);
    }

    pub fn setDelegationChain(self: *AdvancedAccessToken, chain: DelegationChain) void {
        self.delegation_chain = chain;
    }

    pub fn addScopeRestriction(self: *AdvancedAccessToken, scope: []const u8) !void {
        try self.scope_restrictions.append(self.allocator, scope);
    }

    /// Check if token grants specific hierarchical permission
    pub fn hasHierarchicalPermission(self: *const AdvancedAccessToken, permission: *const HierarchicalPermission, context: *const PermissionContext) bool {
        // Check direct hierarchical permissions
        for (self.hierarchical_permissions.items) |*token_perm| {
            if (token_perm.matches(permission)) return true;
        }

        // Check conditional permissions
        for (self.conditional_permissions.items) |*cond_perm| {
            if (cond_perm.base_permission.matches(permission) and cond_perm.evaluate(context)) {
                return true;
            }
        }

        // Check delegation chain
        if (self.delegation_chain) |*chain| {
            if (chain.hasPermission(permission, context)) return true;
        }

        return false;
    }

    /// Generate refresh token
    pub fn generateRefreshToken(self: *AdvancedAccessToken) ![]const u8 {
        var random_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        const refresh_token = try self.allocator.alloc(u8, 64);
        _ = std.fmt.bufPrint(refresh_token, "{}", .{std.fmt.fmtSliceHexLower(&random_bytes)}) catch unreachable;

        self.refresh_token = refresh_token;
        return refresh_token;
    }

    /// Create token analytics data
    pub fn getAnalytics(self: *const AdvancedAccessToken) TokenAnalytics {
        return TokenAnalytics{
            .permission_count = @intCast(self.hierarchical_permissions.items.len + self.conditional_permissions.items.len),
            .max_permission_depth = self.getMaxPermissionDepth(),
            .has_delegation_chain = self.delegation_chain != null,
            .delegation_depth = if (self.delegation_chain) |chain| @intCast(chain.links.items.len) else 0,
            .scope_count = @intCast(self.scope_restrictions.items.len),
            .has_refresh_token = self.refresh_token != null,
        };
    }

    pub const TokenAnalytics = struct {
        permission_count: u32,
        max_permission_depth: u32,
        has_delegation_chain: bool,
        delegation_depth: u32,
        scope_count: u32,
        has_refresh_token: bool,
    };

    fn getMaxPermissionDepth(self: *const AdvancedAccessToken) u32 {
        var max_depth: u32 = 0;
        for (self.hierarchical_permissions.items) |*perm| {
            const depth = @as(u32, @intCast(perm.depth()));
            if (depth > max_depth) max_depth = depth;
        }
        return max_depth;
    }
};

test "hierarchical permission creation and matching" {
    var perm1 = try HierarchicalPermission.init(std.testing.allocator, "admin.ledger.read");
    defer perm1.deinit();

    var perm2 = try HierarchicalPermission.init(std.testing.allocator, "admin.ledger");
    defer perm2.deinit();

    var perm3 = try HierarchicalPermission.init(std.testing.allocator, "user.read");
    defer perm3.deinit();

    // Test parent-child relationships
    try std.testing.expect(perm2.isParentOf(&perm1));
    try std.testing.expect(!perm1.isParentOf(&perm2));
    try std.testing.expect(!perm3.isParentOf(&perm1));

    // Test matching
    try std.testing.expect(perm2.matches(&perm1));
    try std.testing.expect(!perm3.matches(&perm1));
}

test "conditional permission evaluation" {
    const base_perm = try HierarchicalPermission.init(std.testing.allocator, "payment.send");
    var cond_perm = ConditionalPermission.init(std.testing.allocator, base_perm);
    defer cond_perm.deinit();

    // Add amount limit condition
    const amount_condition = ConditionalPermission.Condition{
        .amount_limit = .{
            .max_amount = 1000,
            .currency = "USD",
            .time_window_seconds = 3600,
        },
    };
    try cond_perm.addCondition(amount_condition);

    // Test context within limit
    const context_within = PermissionContext{
        .timestamp = time_utils.milliTimestamp(),
        .transaction_amount = 500,
        .user_country = null,
        .device_type = null,
        .transaction_type = null,
        .user_id = "test-user",
        .session_id = "test-session",
    };

    try std.testing.expect(cond_perm.evaluate(&context_within));

    // Test context exceeding limit
    const context_exceeding = PermissionContext{
        .timestamp = time_utils.milliTimestamp(),
        .transaction_amount = 1500,
        .user_country = null,
        .device_type = null,
        .transaction_type = null,
        .user_id = "test-user",
        .session_id = "test-session",
    };

    try std.testing.expect(!cond_perm.evaluate(&context_exceeding));
}

test "delegation chain validation" {
    var chain = DelegationChain.init(std.testing.allocator, 3);
    defer chain.deinit();

    // Create delegation A → B
    var link1 = DelegationChain.DelegationLink.init(std.testing.allocator, "user-a", "user-b", 3600);
    const perm1 = try HierarchicalPermission.init(std.testing.allocator, "admin.read");
    try link1.addPermission(perm1);
    try chain.addLink(link1);

    // Create delegation B → C
    var link2 = DelegationChain.DelegationLink.init(std.testing.allocator, "user-b", "user-c", 3600);
    const perm2 = try HierarchicalPermission.init(std.testing.allocator, "admin.read");
    try link2.addPermission(perm2);
    try chain.addLink(link2);

    // Chain should be valid
    try std.testing.expect(chain.validate());

    // Test permission checking
    var check_perm = try HierarchicalPermission.init(std.testing.allocator, "admin.read.users");
    defer check_perm.deinit();

    const context = PermissionContext{
        .timestamp = time_utils.milliTimestamp(),
        .transaction_amount = 0,
        .user_country = null,
        .device_type = null,
        .transaction_type = null,
        .user_id = "user-c",
        .session_id = "test-session",
    };

    try std.testing.expect(chain.hasPermission(&check_perm, &context));
}
