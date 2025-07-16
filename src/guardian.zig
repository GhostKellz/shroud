const std = @import("std");

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

pub fn createBasicRoles(guardian: *Guardian) !void {
    try guardian.addRole("admin", &[_]Permission{ .read, .write, .execute, .admin, .delegate });
    try guardian.addRole("user", &[_]Permission{ .read, .write });
    try guardian.addRole("viewer", &[_]Permission{.read});
}

pub fn version() []const u8 {
    return "0.1.0";
}