const std = @import("std");
const zsig = @import("zsig.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // If no arguments provided, show basic info
    if (args.len == 1) {
        try zsig.advancedPrint();
        return;
    }

    // Check if this should be handled by CLI
    const first_arg = args[1];
    const cli_commands = [_][]const u8{ 
        "keygen", "sign", "verify", "pubkey", "help", "version",
        // v0.4.0 token commands
        "token_create", "token_verify", "token_refresh", "jwt_create", "jwt_verify"
    };

    for (cli_commands) |cmd| {
        if (std.mem.eql(u8, first_arg, cmd)) {
            const cli = @import("cli.zig");
            return cli.main();
        }
    }

    // Default behavior for unknown commands
    std.debug.print("Unknown command: {s}\n", .{first_arg});
    std.debug.print("Use 'zsig help' for available commands.\n", .{});
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // Try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
