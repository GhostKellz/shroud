//! Time utilities for Zig 0.16.0-dev compatibility
//! Replaces removed std.time.milliTimestamp() with new std.Io API
const std = @import("std");

/// Thread-local Io instance for timestamp operations
var io_instance: std.Io.Threaded = std.Io.Threaded.init_single_threaded;

/// Get current Unix timestamp in milliseconds using the new std.Io API
/// Equivalent to the removed std.time.milliTimestamp()
pub fn milliTimestamp() i64 {
    const io = io_instance.io();
    const now = std.Io.Clock.now(.real, io) catch {
        // Fallback to posix if Io fails
        const ts = std.posix.clock_gettime(.REALTIME) catch unreachable;
        return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
    };
    return now.toMilliseconds();
}

/// Get current Unix timestamp in seconds
/// Equivalent to the removed std.time.timestamp()
pub fn timestamp() i64 {
    const io = io_instance.io();
    const now = std.Io.Clock.now(.real, io) catch {
        // Fallback to posix if Io fails
        const ts = std.posix.clock_gettime(.REALTIME) catch unreachable;
        return ts.sec;
    };
    return now.toSeconds();
}

/// Get current Unix timestamp in nanoseconds
pub fn nanoTimestamp() i96 {
    const io = io_instance.io();
    const now = std.Io.Clock.now(.real, io) catch {
        // Fallback to posix if Io fails
        const ts = std.posix.clock_gettime(.REALTIME) catch unreachable;
        return @as(i96, ts.sec) * std.time.ns_per_s + @as(i96, ts.nsec);
    };
    return now.toNanoseconds();
}

test "milliTimestamp returns reasonable value" {
    const ms = milliTimestamp();
    // Should be after year 2024 (approximately 1704067200000 ms since epoch)
    try std.testing.expect(ms > 1704067200000);
}

test "timestamp returns reasonable value" {
    const s = timestamp();
    // Should be after year 2024 (approximately 1704067200 seconds since epoch)
    try std.testing.expect(s > 1704067200);
}
