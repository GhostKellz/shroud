//! Shroud v1.0: Unified Cryptographic Framework with zsync Async Runtime
//! Modular architecture integrating all Ghostchain crypto components with massive performance improvements
const std = @import("std");

// Async core - zsync powered
pub const async_runtime = @import("async/root.zig");

// Core modules with async support
pub const ghostcipher = @import("ghostcipher");
pub const sigil = @import("sigil");
pub const zns = @import("zns");
pub const ghostwire = @import("ghostwire");
pub const keystone = @import("keystone");

// Advanced modules
pub const guardian = @import("guardian");
pub const covenant = @import("covenant");
pub const shadowcraft = @import("shadowcraft");
pub const gwallet = @import("gwallet");

// Async runtime types
pub const ZSyncRuntime = async_runtime.ZSyncRuntime;
pub const ShroudRuntime = async_runtime.ShroudRuntime;
pub const AsyncMetrics = async_runtime.AsyncMetrics;

// Global async runtime management
pub const initAsyncRuntime = async_runtime.initGlobalRuntime;
pub const getAsyncRuntime = async_runtime.getGlobalRuntime;
pub const shutdownAsyncRuntime = async_runtime.shutdownGlobalRuntime;
pub const spawnTask = async_runtime.spawnTask;

// Clean v1.0.0 API with async capabilities
// Use: shroud.ghostcipher.zcrypto, shroud.ghostcipher.zsig, shroud.sigil
// Async: shroud.spawnTask(), shroud.getAsyncRuntime()

pub const ShroudError = error{
    ModuleInitFailed,
    CryptoError,
    NetworkError,
    IdentityError,
    LedgerError,
    AsyncRuntimeError,
};

pub fn version() []const u8 {
    return "1.0.0";
}

/// Initialize SHROUD framework with async runtime
pub fn init(allocator: std.mem.Allocator) !*ZSyncRuntime {
    return try initAsyncRuntime(allocator);
}

/// Shutdown SHROUD framework
pub fn deinit() void {
    shutdownAsyncRuntime();
}

/// Get current performance metrics
pub fn getMetrics() AsyncMetrics {
    return async_runtime.getMetrics();
}

test "shroud module imports" {
    std.testing.refAllDecls(@This());
}
