const std = @import("std");

// Export all public modules
pub const resolver = struct {
    pub const types = @import("resolver/types.zig");
    pub const universal = @import("resolver/universal.zig");
    pub const ens = @import("resolver/ens.zig");
    pub const unstoppable = @import("resolver/unstoppable.zig");
    pub const ghost = @import("resolver/ghost.zig");
};

pub const http = struct {
    pub const client = @import("http/client.zig");
};

pub const cli = struct {
    pub const commands = @import("cli/commands.zig");
};

pub const zwallet = struct {
    pub const integration = @import("zwallet/integration.zig");
};

// Re-export commonly used types
pub const CryptoAddress = resolver.types.CryptoAddress;
pub const DomainType = resolver.types.DomainType;
pub const ChainType = resolver.types.ChainType;
pub const UniversalResolver = resolver.universal.UniversalResolver;

// Legacy function for compatibility
pub fn advancedPrint() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("ZNS - Universal Crypto Domain Resolver v0.1.0\n", .{});
    try stdout.print("Run `zns help` to see available commands.\n", .{});

    try bw.flush();
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}

test {
    // Import all test modules
    _ = @import("resolver/types.zig");
    _ = @import("resolver/ens.zig");
    _ = @import("resolver/unstoppable.zig");
    _ = @import("resolver/ghost.zig");
    _ = @import("resolver/universal.zig");
    _ = @import("cli/commands.zig");
    _ = @import("zwallet/integration.zig");
}