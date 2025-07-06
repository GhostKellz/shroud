const std = @import("std");
const gwallet = @import("gwallet");
const print = std.debug.print;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try showUsage();
        return;
    }

    // Check for special flags
    if (std.mem.eql(u8, args[1], "--version")) {
        print("GhostWallet v{s}\n", .{gwallet.version});
        return;
    }

    if (std.mem.eql(u8, args[1], "--bridge")) {
        try startBridgeMode(allocator);
        return;
    }

    // Run CLI
    var cli = gwallet.CLI.init(allocator);
    defer cli.deinit();

    try cli.run(args);
}

fn showUsage() !void {
    print(
        \\GhostWallet - A Secure, Programmable Wallet for Zig
        \\
        \\USAGE:
        \\    gwallet <COMMAND> [OPTIONS]
        \\    gwallet --bridge [--port PORT]
        \\    gwallet --version
        \\
        \\COMMANDS:
        \\    generate     Generate new wallet
        \\    import       Import wallet from mnemonic
        \\    balance      Check account balance
        \\    send         Send tokens
        \\    receive      Generate receive address/QR
        \\    accounts     List accounts
        \\    unlock       Unlock wallet
        \\    lock         Lock wallet
        \\    help         Show help
        \\
        \\OPTIONS:
        \\    --bridge     Start web3 bridge server
        \\    --port       Bridge server port (default: 8080)
        \\    --version    Show version
        \\
        \\EXAMPLES:
        \\    gwallet generate --type ed25519 --name ghostkellz
        \\    gwallet import --mnemonic "word1 word2 ..."
        \\    gwallet balance --token gcc
        \\    gwallet send --to chris.eth --amount 420 --token gcc
        \\    gwallet --bridge --port 8080
        \\
    , .{});
}

fn startBridgeMode(allocator: std.mem.Allocator) !void {
    print("Starting GhostWallet Web3 Bridge...\n", .{});

    var server = try gwallet.startBridge(allocator, 8080);
    defer server.deinit();

    print("Bridge server running on http://localhost:8080\n", .{});
    print("Press Ctrl+C to stop\n", .{});

    // Keep server running
    while (true) {
        std.time.sleep(1000000000); // Sleep 1 second
    }
}

test "main module" {
    try std.testing.expect(true);
}
