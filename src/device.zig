//! Device Fingerprinting and Binding System
//! Multi-factor authentication through hardware characteristics

const std = @import("std");

/// Device fingerprint - cryptographic hash of device characteristics
pub const DeviceFingerprint = struct {
    bytes: [32]u8,

    /// Check if two fingerprints are equal
    pub fn eql(self: DeviceFingerprint, other: DeviceFingerprint) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Convert to hex string
    pub fn toHexString(self: DeviceFingerprint, buffer: []u8) ![]u8 {
        if (buffer.len < 64) return error.BufferTooSmall;
        
        for (self.bytes, 0..) |byte, i| {
            _ = std.fmt.bufPrint(buffer[i * 2..i * 2 + 2], "{x:0>2}", .{byte}) catch return error.BufferTooSmall;
        }
        
        return buffer[0..64];
    }

    /// Parse from hex string
    pub fn fromHexString(hex_str: []const u8) !DeviceFingerprint {
        if (hex_str.len != 64) return error.InvalidFormat;
        
        var fingerprint = DeviceFingerprint{ .bytes = undefined };
        for (0..32) |i| {
            const byte_hex = hex_str[i * 2..i * 2 + 2];
            fingerprint.bytes[i] = std.fmt.parseInt(u8, byte_hex, 16) catch return error.InvalidFormat;
        }
        return fingerprint;
    }
};

/// Device policy for access control
pub const DevicePolicy = struct {
    allowed_devices: std.ArrayList(DeviceFingerprint),
    require_device_binding: bool,
    allow_new_devices: bool,
    max_devices: ?u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DevicePolicy {
        return DevicePolicy{
            .allowed_devices = std.ArrayList(DeviceFingerprint).init(allocator),
            .require_device_binding = false,
            .allow_new_devices = true,
            .max_devices = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DevicePolicy) void {
        self.allowed_devices.deinit();
    }

    pub fn addDevice(self: *DevicePolicy, device: DeviceFingerprint) !void {
        if (self.max_devices) |max| {
            if (self.allowed_devices.items.len >= max) {
                return error.TooManyDevices;
            }
        }
        try self.allowed_devices.append(device);
    }

    pub fn isDeviceAllowed(self: *const DevicePolicy, device: DeviceFingerprint) bool {
        for (self.allowed_devices.items) |allowed_device| {
            if (device.eql(allowed_device)) return true;
        }
        return !self.require_device_binding or self.allow_new_devices;
    }

    pub fn removeDevice(self: *DevicePolicy, device: DeviceFingerprint) bool {
        for (self.allowed_devices.items, 0..) |allowed_device, i| {
            if (device.eql(allowed_device)) {
                _ = self.allowed_devices.swapRemove(i);
                return true;
            }
        }
        return false;
    }
};

/// Generate device fingerprint from system characteristics
pub fn generateDeviceFingerprint(allocator: std.mem.Allocator) !DeviceFingerprint {
    var fingerprint_data = std.ArrayList(u8).init(allocator);
    defer fingerprint_data.deinit();
    
    // Add consistent prefix for versioning
    try fingerprint_data.appendSlice("SHROUD-Device-v1");

    // Platform-specific system info collection
    try collectSystemInfo(allocator, &fingerprint_data);

    // Hash all collected data
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(fingerprint_data.items);
    const hash = hasher.finalResult();

    return DeviceFingerprint{ .bytes = hash };
}

/// Collect system information for fingerprinting
fn collectSystemInfo(allocator: std.mem.Allocator, data: *std.ArrayList(u8)) !void {
    // Hostname
    if (std.process.getEnvVarOwned(allocator, "HOSTNAME")) |hostname| {
        defer allocator.free(hostname);
        try data.appendSlice(hostname);
    } else |_| {
        if (std.process.getEnvVarOwned(allocator, "COMPUTERNAME")) |computername| {
            defer allocator.free(computername);
            try data.appendSlice(computername);
        } else |_| {
            try data.appendSlice("unknown-host");
        }
    }

    // User info
    if (std.process.getEnvVarOwned(allocator, "USER")) |user| {
        defer allocator.free(user);
        try data.appendSlice(user);
    } else |_| {
        if (std.process.getEnvVarOwned(allocator, "USERNAME")) |username| {
            defer allocator.free(username);
            try data.appendSlice(username);
        } else |_| {
            try data.appendSlice("unknown-user");
        }
    }

    // Home directory
    if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        try data.appendSlice(home);
    } else |_| {
        if (std.process.getEnvVarOwned(allocator, "USERPROFILE")) |userprofile| {
            defer allocator.free(userprofile);
            try data.appendSlice(userprofile);
        } else |_| {
            try data.appendSlice("unknown-home");
        }
    }

    // Platform identifier
    const platform = switch (@import("builtin").target.os.tag) {
        .linux => "linux",
        .macos => "macos",
        .windows => "windows",
        .freebsd => "freebsd",
        else => "unknown",
    };
    try data.appendSlice(platform);

    // Architecture
    const arch = switch (@import("builtin").target.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
        .arm => "arm",
        else => "unknown",
    };
    try data.appendSlice(arch);
}

/// Identity bound to a specific device
pub const BoundIdentity = struct {
    identity_id: []const u8,
    device_fingerprint: DeviceFingerprint,
    binding_timestamp: i64,
    is_primary_device: bool,

    pub fn init(identity_id: []const u8, device: DeviceFingerprint, is_primary: bool) BoundIdentity {
        return BoundIdentity{
            .identity_id = identity_id,
            .device_fingerprint = device,
            .binding_timestamp = std.time.milliTimestamp(),
            .is_primary_device = is_primary,
        };
    }

    pub fn isValid(self: BoundIdentity, current_device: DeviceFingerprint) bool {
        return self.device_fingerprint.eql(current_device);
    }
};

/// Device errors
pub const DeviceError = error{
    InvalidFormat,
    BufferTooSmall,
    TooManyDevices,
    DeviceNotAllowed,
    SystemInfoUnavailable,
};

test "device fingerprint generation" {
    const fingerprint = try generateDeviceFingerprint(std.testing.allocator);
    
    // Should be deterministic for same system
    const fingerprint2 = try generateDeviceFingerprint(std.testing.allocator);
    try std.testing.expect(fingerprint.eql(fingerprint2));
}

test "device policy management" {
    var policy = DevicePolicy.init(std.testing.allocator);
    defer policy.deinit();

    const device1 = DeviceFingerprint{ .bytes = [_]u8{1} ** 32 };
    const device2 = DeviceFingerprint{ .bytes = [_]u8{2} ** 32 };

    // Add devices
    try policy.addDevice(device1);
    try policy.addDevice(device2);

    // Check allowed devices
    try std.testing.expect(policy.isDeviceAllowed(device1));
    try std.testing.expect(policy.isDeviceAllowed(device2));

    // Remove device
    try std.testing.expect(policy.removeDevice(device1));
    try std.testing.expect(!policy.removeDevice(device1)); // Already removed
}

test "device fingerprint hex conversion" {
    const fingerprint = DeviceFingerprint{ .bytes = [_]u8{0xAB} ** 32 };
    
    var buffer: [64]u8 = undefined;
    const hex_str = try fingerprint.toHexString(&buffer);
    
    try std.testing.expect(std.mem.startsWith(u8, hex_str, "abab"));
    
    const parsed = try DeviceFingerprint.fromHexString(hex_str);
    try std.testing.expect(fingerprint.eql(parsed));
}
