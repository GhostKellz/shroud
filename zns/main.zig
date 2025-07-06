const std = @import("std");
const zns = @import("zns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Get command line arguments
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);
    
    // Convert [:0]u8 to []const u8
    var argv_const = try allocator.alloc([]const u8, argv.len);
    defer allocator.free(argv_const);
    for (argv, 0..) |arg, i| {
        argv_const[i] = arg;
    }
    
    // Parse arguments
    const args = zns.cli.commands.parseArgs(allocator, argv_const) catch {
        std.debug.print("Error parsing arguments\n", .{});
        return;
    };
    defer {
        // Free domains array if it was allocated
        if (args.domains) |domains| {
            allocator.free(domains);
        }
    }
    
    // Initialize CLI
    var cli = zns.cli.commands.CLI.init(allocator, args);
    defer cli.deinit();
    
    // Execute command
    cli.execute(args) catch |err| switch (err) {
        error.DomainNotFound => {
            std.debug.print("Domain not found\n", .{});
            std.process.exit(1);
        },
        error.UnsupportedDomain => {
            std.debug.print("Unsupported domain type\n", .{});
            std.process.exit(1);
        },
        error.OutOfMemory => {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        },
        else => {
            std.debug.print("Unknown error: {}\n", .{err});
            std.process.exit(1);
        },
    };
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit();
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "ZNS integration test" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    
    // Test domain type detection
    try std.testing.expectEqual(zns.DomainType.ens, zns.resolver.types.getDomainType(".eth"));
    try std.testing.expectEqual(zns.DomainType.unstoppable, zns.resolver.types.getDomainType(".crypto"));
    try std.testing.expectEqual(zns.DomainType.ghost, zns.resolver.types.getDomainType(".ghost"));
    
    // Test TLD extraction
    try std.testing.expectEqualStrings(".eth", zns.resolver.types.extractTLD("alice.eth"));
    try std.testing.expectEqualStrings(".crypto", zns.resolver.types.extractTLD("vault.crypto"));
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Test domain type detection with fuzz input
            const tld = zns.resolver.types.extractTLD(input);
            const domain_type = zns.resolver.types.getDomainType(tld);
            
            // Should never crash, always return a valid enum value
            try std.testing.expect(@intFromEnum(domain_type) >= 0);
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}