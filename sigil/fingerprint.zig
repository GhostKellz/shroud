const std = @import("std");
const zcrypto = @import("ghostcipher").zcrypto;
const types = @import("types.zig");

const DeviceFingerprint = types.DeviceFingerprint;
const RealIDError = types.RealIDError;

/// Generate a device fingerprint based on system characteristics
pub fn generate_device_fingerprint(allocator: std.mem.Allocator) RealIDError!DeviceFingerprint {
    // Collect system info in a buffer
    var fingerprint_data = std.ArrayList(u8).init(allocator);
    defer fingerprint_data.deinit();
    
    // Add a consistent prefix for versioning
    try fingerprint_data.appendSlice("RealID-Device-v1");

    // Add hostname if available
    if (std.process.getEnvVarOwned(allocator, "HOSTNAME")) |hostname| {
        defer allocator.free(hostname);
        try fingerprint_data.appendSlice(hostname);
    } else |_| {
        // If no hostname, try alternative methods
        if (std.process.getEnvVarOwned(allocator, "COMPUTERNAME")) |computername| {
            defer allocator.free(computername);
            try fingerprint_data.appendSlice(computername);
        } else |_| {
            try fingerprint_data.appendSlice("unknown-host");
        }
    }

    // Add user info if available
    if (std.process.getEnvVarOwned(allocator, "USER")) |user| {
        defer allocator.free(user);
        try fingerprint_data.appendSlice(user);
    } else |_| {
        if (std.process.getEnvVarOwned(allocator, "USERNAME")) |username| {
            defer allocator.free(username);
            try fingerprint_data.appendSlice(username);
        } else |_| {
            try fingerprint_data.appendSlice("unknown-user");
        }
    }

    // Add home directory path
    if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        try fingerprint_data.appendSlice(home);
    } else |_| {
        if (std.process.getEnvVarOwned(allocator, "USERPROFILE")) |userprofile| {
            defer allocator.free(userprofile);
            try fingerprint_data.appendSlice(userprofile);
        } else |_| {
            try fingerprint_data.appendSlice("unknown-home");
        }
    }

    // Add OS-specific information
    switch (@import("builtin").os.tag) {
        .windows => {
            try fingerprint_data.appendSlice("windows");
            // Could add Windows-specific machine GUID here
        },
        .linux => {
            try fingerprint_data.appendSlice("linux");
            // Could add /etc/machine-id content here
        },
        .macos => {
            try fingerprint_data.appendSlice("macos");
            // Could add hardware UUID here
        },
        else => {
            try fingerprint_data.appendSlice("unknown-os");
        },
    }

    // Hash all collected data
    const fingerprint_hash = zcrypto.hash.sha256(fingerprint_data.items);

    return DeviceFingerprint{ .bytes = fingerprint_hash };
}

/// Generate a static fingerprint from a string (for testing or fixed devices)
pub fn fingerprint_from_string(input: []const u8) DeviceFingerprint {
    const prefix = "RealID-Device-v1";
    const combined_input = prefix ++ input;
    const fingerprint_hash = zcrypto.hash.sha256(combined_input);
    
    return DeviceFingerprint{ .bytes = fingerprint_hash };
}

/// Convert fingerprint to hex string
pub fn fingerprint_to_hex(fingerprint: DeviceFingerprint, buffer: []u8) ![]u8 {
    if (buffer.len < 64) { // 32 bytes * 2 hex chars per byte
        return error.BufferTooSmall;
    }

    return std.fmt.bufPrint(buffer, "{}", .{std.fmt.fmtSliceHexLower(&fingerprint.bytes)});
}

/// Parse fingerprint from hex string
pub fn fingerprint_from_hex(hex_str: []const u8) !DeviceFingerprint {
    if (hex_str.len != 64) {
        return error.InvalidLength;
    }

    var fingerprint: DeviceFingerprint = undefined;

    for (0..32) |i| {
        const hex_pair = hex_str[i * 2 .. i * 2 + 2];
        fingerprint.bytes[i] = std.fmt.parseInt(u8, hex_pair, 16) catch return error.InvalidFormat;
    }

    return fingerprint;
}
