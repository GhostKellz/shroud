const std = @import("std");
const device = @import("device.zig");

pub const GuardianError = error{
    AccessDenied,
    InvalidPermission,
    RoleNotFound,
    InsufficientPrivileges,
    OperationBlocked,
    QuotaExceeded,
};

pub const Permission = enum {
    read,
    write,
    execute,
    admin,
    delegate,
    
    pub fn toString(self: Permission) []const u8 {
        return switch (self) {
            .read => "read",
            .write => "write", 
            .execute => "execute",
            .admin => "admin",
            .delegate => "delegate",
        };
    }
};

pub const Role = struct {
    name: []const u8,
    permissions: std.ArrayList(Permission),
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8) Role {
        return Role{
            .name = name,
            .permissions = std.ArrayList(Permission).init(allocator),
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

pub const AccessContext = struct {
    user_id: []const u8,
    roles: std.ArrayList([]const u8),
    timestamp: u64,
    resource_path: []const u8,
    operation: Permission,
    
    pub fn init(allocator: std.mem.Allocator, user_id: []const u8, resource: []const u8, operation: Permission) AccessContext {
        return AccessContext{
            .user_id = user_id,
            .roles = std.ArrayList([]const u8).init(allocator),
            .timestamp = @intCast(std.time.timestamp()),
            .resource_path = resource,
            .operation = operation,
        };
    }
    
    pub fn deinit(self: *AccessContext) void {
        self.roles.deinit();
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

pub const Guardian = struct {
    roles: std.HashMap([]const u8, Role, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) Guardian {
        return Guardian{
            .roles = std.HashMap([]const u8, Role, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Guardian) void {
        var role_iter = self.roles.iterator();
        while (role_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.roles.deinit();
    }
    
    pub fn addRole(self: *Guardian, name: []const u8, permissions: []const Permission) !void {
        var role = Role.init(self.allocator, name);
        for (permissions) |permission| {
            try role.addPermission(permission);
        }
        try self.roles.put(name, role);
    }
    
    pub fn canAccess(self: *Guardian, context: *const AccessContext) GuardianError!bool {
        // Check if user has required permission through roles
        for (context.roles.items) |role_name| {
            if (self.roles.get(role_name)) |role| {
                if (role.hasPermission(context.operation)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    pub fn validateRole(self: *Guardian, role_name: []const u8) bool {
        return self.roles.contains(role_name);
    }
};

/// Device-aware access context with device fingerprinting
pub const DeviceAccessContext = struct {
    user_id: []const u8,
    roles: std.ArrayList([]const u8),
    resource_path: []const u8,
    operation: Permission,
    device_fingerprint: ?device.DeviceFingerprint,
    device_policy: ?*const device.DevicePolicy,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, user_id: []const u8, resource: []const u8, operation: Permission) DeviceAccessContext {
        return DeviceAccessContext{
            .user_id = user_id,
            .roles = std.ArrayList([]const u8).init(allocator),
            .resource_path = resource,
            .operation = operation,
            .device_fingerprint = null,
            .device_policy = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DeviceAccessContext) void {
        self.roles.deinit();
        // Note: we don't own device_policy, so don't deinit it
    }

    pub fn addRole(self: *DeviceAccessContext, role: []const u8) !void {
        try self.roles.append(role);
    }

    pub fn setDeviceFingerprint(self: *DeviceAccessContext, fingerprint: device.DeviceFingerprint) void {
        self.device_fingerprint = fingerprint;
    }

    pub fn setDevicePolicy(self: *DeviceAccessContext, policy: *const device.DevicePolicy) void {
        self.device_policy = policy;
    }

    pub fn hasRole(self: *const DeviceAccessContext, role: []const u8) bool {
        for (self.roles.items) |r| {
            if (std.mem.eql(u8, r, role)) return true;
        }
        return false;
    }

    pub fn isDeviceAllowed(self: *const DeviceAccessContext) bool {
        if (self.device_policy) |policy| {
            if (self.device_fingerprint) |fingerprint| {
                return policy.isDeviceAllowed(fingerprint);
            }
            return !policy.require_device_binding;
        }
        return true; // No device policy means allow all devices
    }
};

pub fn createBasicRoles(guardian: *Guardian) !void {
    try guardian.addRole("admin", &[_]Permission{ .read, .write, .execute, .admin, .delegate });
    try guardian.addRole("user", &[_]Permission{ .read, .write });
    try guardian.addRole("viewer", &[_]Permission{.read});
}

pub fn version() []const u8 {
    return "0.1.0";
}

/// Check device permission with device-aware context
pub fn checkDevicePermission(guardian: *const Guardian, context: *const DeviceAccessContext, permission: Permission) GuardianError!void {
    // First check device access
    if (!context.isDeviceAllowed()) {
        return GuardianError.AccessDenied;
    }

    // Then check standard permission
    return checkPermission(guardian, @ptrCast(context), permission);
}

/// Check permission (standard method, kept for compatibility)
pub fn checkPermission(guardian: *const Guardian, context: *const AccessContext, permission: Permission) GuardianError!void {
    // Check if user has any role that grants this permission
    for (context.roles.items) |role_name| {
        if (guardian.roles.get(role_name)) |role| {
            for (role.permissions) |perm| {
                if (perm == permission) return; // Permission granted
            }
        }
    }
    
    return GuardianError.AccessDenied;
}