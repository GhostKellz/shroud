const std = @import("std");
const zledger = @import("zledger");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        try zledger.advancedPrint();
        return;
    }

    var cli = zledger.Cli.init(allocator, ".zledger") catch |err| {
        std.debug.print("Failed to initialize CLI: {}\n", .{err});
        return;
    };
    defer cli.deinit();

    cli.run(args) catch |err| switch (err) {
        zledger.cli.CliError.InvalidCommand,
        zledger.cli.CliError.InvalidArguments => {},
        else => {
            std.debug.print("Error: {}\n", .{err});
        },
    };
}
