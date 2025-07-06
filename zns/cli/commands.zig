const std = @import("std");
const types = @import("../resolver/types.zig");
const universal = @import("../resolver/universal.zig");

/// CLI command types
pub const Command = enum {
    resolve,
    resolve_all,
    batch,
    register,
    cache_stats,
    cache_clear,
    help,
    version,
};

/// CLI arguments structure
pub const Args = struct {
    command: Command,
    domain: ?[]const u8 = null,
    domains: ?[][]const u8 = null,
    chain: ?[]const u8 = null,
    output_format: OutputFormat = .text,
    ghostbridge_endpoint: []const u8 = "http://localhost:9090",
    ethereum_rpc: []const u8 = "https://eth-mainnet.alchemyapi.io/v2/demo",
    unstoppable_api_key: ?[]const u8 = null,

    pub const OutputFormat = enum {
        text,
        json,
        csv,
    };
};

/// CLI command processor
pub const CLI = struct {
    allocator: std.mem.Allocator,
    resolver: universal.UniversalResolver,

    pub fn init(allocator: std.mem.Allocator, args: Args) CLI {
        const resolver = universal.UniversalResolver.init(
            allocator,
            args.ghostbridge_endpoint,
            args.ethereum_rpc,
            args.unstoppable_api_key,
        );

        return CLI{
            .allocator = allocator,
            .resolver = resolver,
        };
    }

    pub fn deinit(self: *CLI) void {
        self.resolver.deinit();
    }

    /// Execute CLI command
    pub fn execute(self: *CLI, args: Args) !void {
        switch (args.command) {
            .resolve => try self.cmdResolve(args),
            .resolve_all => try self.cmdResolveAll(args),
            .batch => try self.cmdBatch(args),
            .register => try self.cmdRegister(args),
            .cache_stats => try self.cmdCacheStats(args),
            .cache_clear => try self.cmdCacheClear(),
            .help => try self.cmdHelp(),
            .version => try self.cmdVersion(),
        }
    }

    /// Resolve single domain
    fn cmdResolve(self: *CLI, args: Args) !void {
        const domain = args.domain orelse {
            std.debug.print("Error: Domain required for resolve command\n", .{});
            return;
        };

        var result = self.resolver.resolve(domain) catch |err| switch (err) {
            error.DomainNotFound => {
                std.debug.print("Domain not found: {s}\n", .{domain});
                return;
            },
            error.UnsupportedDomain => {
                std.debug.print("Unsupported domain: {s}\n", .{domain});
                return;
            },
            else => return err,
        };
        defer result.deinit(self.allocator);

        try self.printCryptoAddress(result, args.output_format);
    }

    /// Resolve all chains for domain
    fn cmdResolveAll(self: *CLI, args: Args) !void {
        const domain = args.domain orelse {
            std.debug.print("Error: Domain required for resolve-all command\n", .{});
            return;
        };

        const results = self.resolver.resolveAll(domain) catch |err| switch (err) {
            error.DomainNotFound => {
                std.debug.print("Domain not found: {s}\n", .{domain});
                return;
            },
            error.UnsupportedDomain => {
                std.debug.print("Unsupported domain: {s}\n", .{domain});
                return;
            },
            else => return err,
        };
        defer {
            for (results) |*result| {
                result.deinit(self.allocator);
            }
            self.allocator.free(results);
        }

        try self.printMultipleAddresses(results, args.output_format);
    }

    /// Batch resolve multiple domains
    fn cmdBatch(self: *CLI, args: Args) !void {
        const domains = args.domains orelse {
            std.debug.print("Error: Domains required for batch command\n", .{});
            return;
        };

        const results = try self.resolver.resolveBatch(domains);
        defer {
            for (results) |*result| {
                result.deinit(self.allocator);
            }
            self.allocator.free(results);
        }

        try self.printMultipleAddresses(results, args.output_format);
    }

    /// Register new domain (placeholder)
    fn cmdRegister(self: *CLI, args: Args) !void {
        _ = self;
        const domain = args.domain orelse {
            std.debug.print("Error: Domain required for register command\n", .{});
            return;
        };

        // TODO: Implement domain registration
        std.debug.print("Domain registration not yet implemented: {s}\n", .{domain});
    }

    /// Show cache statistics
    fn cmdCacheStats(self: *CLI, args: Args) !void {
        const stats = self.resolver.getCacheStats();

        switch (args.output_format) {
            .text => {
                std.debug.print("Cache Statistics:\n", .{});
                std.debug.print("  Total entries: {d}\n", .{stats.total_entries});
                std.debug.print("  Expired entries: {d}\n", .{stats.expired_entries});
                std.debug.print("  Active entries: {d}\n", .{stats.total_entries - stats.expired_entries});
            },
            .json => {
                std.debug.print("{{\"total_entries\":{d},\"expired_entries\":{d},\"active_entries\":{d}}}\n", .{ stats.total_entries, stats.expired_entries, stats.total_entries - stats.expired_entries });
            },
            .csv => {
                std.debug.print("metric,value\n", .{});
                std.debug.print("total_entries,{d}\n", .{stats.total_entries});
                std.debug.print("expired_entries,{d}\n", .{stats.expired_entries});
                std.debug.print("active_entries,{d}\n", .{stats.total_entries - stats.expired_entries});
            },
        }
    }

    /// Clear cache
    fn cmdCacheClear(self: *CLI) !void {
        self.resolver.clearCache();
        std.debug.print("Cache cleared\n", .{});
    }

    /// Show help
    fn cmdHelp(self: *CLI) !void {
        _ = self;
        std.debug.print(
            \\ZNS - Universal Crypto Domain Resolver
            \\
            \\USAGE:
            \\    zns <COMMAND> [OPTIONS]
            \\
            \\COMMANDS:
            \\    resolve <domain>           Resolve domain to crypto address
            \\    resolve-all <domain>       Get all crypto addresses for domain
            \\    batch <domain1,domain2>    Resolve multiple domains
            \\    register <domain>          Register new domain (ghost domains only)
            \\    cache-stats                Show cache statistics
            \\    cache-clear                Clear resolver cache
            \\    help                       Show this help message
            \\    version                    Show version information
            \\
            \\OPTIONS:
            \\    --chain <chain>            Filter by specific blockchain
            \\    --format <format>          Output format: text, json, csv
            \\    --ghostbridge <url>        GhostBridge endpoint
            \\    --ethereum-rpc <url>       Ethereum RPC endpoint
            \\    --unstoppable-key <key>    Unstoppable Domains API key
            \\
            \\EXAMPLES:
            \\    zns resolve alice.eth
            \\    zns resolve vault.crypto --chain ethereum
            \\    zns resolve-all alice.crypto --format json
            \\    zns batch alice.eth,vault.crypto,ghostkellz.ghost
            \\
            \\SUPPORTED DOMAINS:
            \\    .eth              - Ethereum Name Service
            \\    .crypto, .nft, .x - Unstoppable Domains
            \\    .ghost, .bc, .kz  - GhostChain Native Domains
            \\
        , .{});
    }

    /// Show version
    fn cmdVersion(self: *CLI) !void {
        _ = self;
        std.debug.print("ZNS Universal Crypto Domain Resolver v0.1.0\n", .{});
    }

    /// Print single crypto address
    fn printCryptoAddress(self: *CLI, address: types.CryptoAddress, format: Args.OutputFormat) !void {
        _ = self;

        switch (format) {
            .text => {
                std.debug.print("Domain: {s}\n", .{address.domain});
                std.debug.print("Chain:  {s}\n", .{@tagName(address.chain)});
                std.debug.print("Address: {s}\n", .{address.address});
                std.debug.print("TTL:    {d}s\n", .{address.ttl});
            },
            .json => {
                std.debug.print("{{\"domain\":\"{s}\",\"chain\":\"{s}\",\"address\":\"{s}\",\"ttl\":{d}}}\n", .{ address.domain, @tagName(address.chain), address.address, address.ttl });
            },
            .csv => {
                std.debug.print("domain,chain,address,ttl\n", .{});
                std.debug.print("{s},{s},{s},{d}\n", .{ address.domain, @tagName(address.chain), address.address, address.ttl });
            },
        }
    }

    /// Print multiple crypto addresses
    fn printMultipleAddresses(self: *CLI, addresses: []types.CryptoAddress, format: Args.OutputFormat) !void {
        _ = self;

        switch (format) {
            .text => {
                for (addresses, 0..) |address, i| {
                    if (i > 0) std.debug.print("\n", .{});
                    std.debug.print("Domain: {s}\n", .{address.domain});
                    std.debug.print("Chain:  {s}\n", .{@tagName(address.chain)});
                    std.debug.print("Address: {s}\n", .{address.address});
                    std.debug.print("TTL:    {d}s\n", .{address.ttl});
                }
            },
            .json => {
                std.debug.print("[", .{});
                for (addresses, 0..) |address, i| {
                    if (i > 0) std.debug.print(",", .{});
                    std.debug.print("{{\"domain\":\"{s}\",\"chain\":\"{s}\",\"address\":\"{s}\",\"ttl\":{d}}}", .{ address.domain, @tagName(address.chain), address.address, address.ttl });
                }
                std.debug.print("]\n", .{});
            },
            .csv => {
                std.debug.print("domain,chain,address,ttl\n", .{});
                for (addresses) |address| {
                    std.debug.print("{s},{s},{s},{d}\n", .{ address.domain, @tagName(address.chain), address.address, address.ttl });
                }
            },
        }
    }
};

/// Parse command line arguments
pub fn parseArgs(allocator: std.mem.Allocator, argv: [][]const u8) !Args {
    if (argv.len < 2) {
        return Args{ .command = .help };
    }

    var args = Args{ .command = .help };

    // Parse command
    const cmd_str = argv[1];
    if (std.mem.eql(u8, cmd_str, "resolve")) {
        args.command = .resolve;
        if (argv.len > 2) args.domain = argv[2];
    } else if (std.mem.eql(u8, cmd_str, "resolve-all")) {
        args.command = .resolve_all;
        if (argv.len > 2) args.domain = argv[2];
    } else if (std.mem.eql(u8, cmd_str, "batch")) {
        args.command = .batch;
        if (argv.len > 2) {
            // Parse comma-separated domains
            var domain_list = std.ArrayList([]const u8).init(allocator);
            var it = std.mem.splitScalar(u8, argv[2], ',');
            while (it.next()) |domain| {
                const trimmed = std.mem.trim(u8, domain, " \t");
                if (trimmed.len > 0) {
                    try domain_list.append(trimmed);
                }
            }
            args.domains = try domain_list.toOwnedSlice();
        }
    } else if (std.mem.eql(u8, cmd_str, "register")) {
        args.command = .register;
        if (argv.len > 2) args.domain = argv[2];
    } else if (std.mem.eql(u8, cmd_str, "cache-stats")) {
        args.command = .cache_stats;
    } else if (std.mem.eql(u8, cmd_str, "cache-clear")) {
        args.command = .cache_clear;
    } else if (std.mem.eql(u8, cmd_str, "version")) {
        args.command = .version;
    } else {
        args.command = .help;
    }

    // Parse options
    var i: usize = 3;
    while (i < argv.len) {
        const arg = argv[i];

        if (std.mem.eql(u8, arg, "--format") and i + 1 < argv.len) {
            const format_str = argv[i + 1];
            if (std.mem.eql(u8, format_str, "json")) {
                args.output_format = .json;
            } else if (std.mem.eql(u8, format_str, "csv")) {
                args.output_format = .csv;
            } else {
                args.output_format = .text;
            }
            i += 2;
        } else if (std.mem.eql(u8, arg, "--chain") and i + 1 < argv.len) {
            args.chain = argv[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--ghostbridge") and i + 1 < argv.len) {
            args.ghostbridge_endpoint = argv[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--ethereum-rpc") and i + 1 < argv.len) {
            args.ethereum_rpc = argv[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--unstoppable-key") and i + 1 < argv.len) {
            args.unstoppable_api_key = argv[i + 1];
            i += 2;
        } else {
            i += 1;
        }
    }

    return args;
}

test "argument parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const argv = &[_][]const u8{ "zns", "resolve", "alice.eth", "--format", "json" };
    const args = try parseArgs(arena.allocator(), @constCast(argv));

    try std.testing.expectEqual(Command.resolve, args.command);
    try std.testing.expectEqualStrings("alice.eth", args.domain.?);
    try std.testing.expectEqual(Args.OutputFormat.json, args.output_format);
}
