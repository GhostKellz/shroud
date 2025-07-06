//! Command-line interface for GhostWallet v0.3.0
//! Enhanced with production-ready features and advanced operations

const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const wallet = @import("../core/wallet_realid.zig");
const transaction = @import("../protocol/transaction.zig");
const ghostd = @import("../protocol/ghostd_integration.zig");
const crypto = @import("../utils/crypto.zig");
// const realid = @import("realid");

pub const Command = enum {
    help,
    generate,
    import,
    balance,
    send,
    receive,
    accounts,
    unlock,
    lock,
    bridge,
    version,
    // v0.3.0 Enhanced Commands
    create_secure,
    export_wallet,
    import_wallet,
    generate_mnemonic,
    restore_mnemonic,
    connect_ghostd,
    batch_sign,
    wallet_stats,
    derive_child,
    privacy_send,
};

pub const CLI = struct {
    allocator: Allocator,
    wallet: ?wallet.Wallet,

    pub fn init(allocator: Allocator) CLI {
        return CLI{
            .allocator = allocator,
            .wallet = null,
        };
    }

    pub fn deinit(self: *CLI) void {
        if (self.wallet) |*w| {
            w.deinit();
        }
    }

    /// Parse command line arguments and execute commands
    pub fn run(self: *CLI, args: [][:0]u8) !void {
        if (args.len < 2) {
            try self.showHelp();
            return;
        }

        const command_str = args[1];
        const command = std.meta.stringToEnum(Command, command_str) orelse {
            print("Unknown command: {s}\n", .{command_str});
            try self.showHelp();
            return;
        };

        switch (command) {
            .help => try self.showHelp(),
            .generate => try self.cmdGenerate(args[2..]),
            .import => try self.cmdImport(args[2..]),
            .balance => try self.cmdBalance(args[2..]),
            .send => try self.cmdSend(args[2..]),
            .receive => try self.cmdReceive(args[2..]),
            .accounts => try self.cmdAccounts(args[2..]),
            .unlock => try self.cmdUnlock(args[2..]),
            .lock => try self.cmdLock(),
            .bridge => try self.cmdBridge(args[2..]),
            .version => try self.showVersion(),
            // New v0.3.0 commands - TODO: implement
            .create_secure => try self.cmdGenerate(args[2..]),
            .export_wallet => try self.showHelp(),
            .import_wallet => try self.cmdImport(args[2..]),
            .generate_mnemonic => try self.showHelp(),
            .restore_mnemonic => try self.cmdImport(args[2..]),
            .connect_ghostd => try self.showHelp(),
            .batch_sign => try self.showHelp(),
            .wallet_stats => try self.showHelp(),
            .derive_child => try self.showHelp(),
            .privacy_send => try self.cmdSend(args[2..]),
        }
    }

    fn showHelp(self: *CLI) !void {
        _ = self;
        print(
            \\Zwallet - A Secure, Programmable Wallet for Zig
            \\
            \\USAGE:
            \\    zwallet <COMMAND> [OPTIONS]
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
            \\    bridge       Start Web3 bridge server
            \\    version      Show version
            \\    help         Show this help
            \\
            \\EXAMPLES:
            \\    zwallet generate --type ed25519 --name ghostkellz
            \\    zwallet import --mnemonic "word1 word2 ..."
            \\    zwallet balance --token gcc
            \\    zwallet send --to chris.eth --amount 420 --token gcc
            \\    zwallet bridge --port 8443 --enable-http3
            \\
        , .{});
    }

    fn showVersion(self: *CLI) !void {
        _ = self;
        print("Zwallet v0.1.0 - Built with Zig {s}\n", .{@import("builtin").zig_version_string});
    }

    fn cmdGenerate(self: *CLI, args: [][:0]u8) !void {
        var key_type: wallet.KeyType = .ed25519;
        var name: ?[]const u8 = null;
        var mode: wallet.WalletMode = .hybrid;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--type") and i + 1 < args.len) {
                key_type = std.meta.stringToEnum(wallet.KeyType, args[i + 1]) orelse .ed25519;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--name") and i + 1 < args.len) {
                name = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--mode") and i + 1 < args.len) {
                mode = std.meta.stringToEnum(wallet.WalletMode, args[i + 1]) orelse .hybrid;
                i += 1;
            }
        }

        // Generate wallet
        self.wallet = try wallet.Wallet.create(self.allocator, "default_passphrase", mode, null);

        // Create default account
        _ = try self.wallet.?.createAccount(.ghostchain, key_type);

        print("Generated new wallet with {s} key\n", .{@tagName(key_type)});
        if (name) |n| {
            print("Account name: {s}\n", .{n});
        }

        print("Wallet generated successfully!\n", .{});
        print("Remember to backup your recovery phrase.\n", .{});
    }

    fn cmdImport(self: *CLI, args: [][:0]u8) !void {
        var mnemonic: ?[]const u8 = null;
        var password: ?[]const u8 = null;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--mnemonic") and i + 1 < args.len) {
                mnemonic = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--password") and i + 1 < args.len) {
                password = args[i + 1];
                i += 1;
            }
        }

        if (mnemonic == null) {
            print("Error: --mnemonic is required\n", .{});
            return;
        }

        self.wallet = try wallet.Wallet.fromMnemonic(self.allocator, mnemonic.?, password, .hybrid);
        print("Wallet imported successfully!\n", .{});
    }

    fn cmdBalance(self: *CLI, args: [][:0]u8) !void {
        if (self.wallet == null) {
            print("Error: No wallet loaded. Use 'generate' or 'import' first.\n", .{});
            return;
        }

        var token: []const u8 = "gcc";
        var address: ?[]const u8 = null;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--token") and i + 1 < args.len) {
                token = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--address") and i + 1 < args.len) {
                address = args[i + 1];
                i += 1;
            }
        }

        // If no address specified, use first account
        if (address == null and self.wallet.?.accounts.items.len > 0) {
            address = self.wallet.?.accounts.items[0].address;
        }

        if (address) |addr| {
            _ = addr;
            // TODO: Get balance by address instead of protocol
            const balance = self.wallet.?.getBalance(.ethereum, token);
            print("Balance: {} {s}\n", .{ balance orelse 0, token });
        } else {
            print("Error: No accounts found\n", .{});
        }
    }

    fn cmdSend(self: *CLI, args: [][:0]u8) !void {
        if (self.wallet == null) {
            print("Error: No wallet loaded. Use 'generate' or 'import' first.\n", .{});
            return;
        }

        var to: ?[]const u8 = null;
        var amount: i64 = 0;
        var token: []const u8 = "gcc";
        var from: ?[]const u8 = null;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--to") and i + 1 < args.len) {
                to = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--amount") and i + 1 < args.len) {
                amount = std.fmt.parseInt(i64, args[i + 1], 10) catch 0;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--token") and i + 1 < args.len) {
                token = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--from") and i + 1 < args.len) {
                from = args[i + 1];
                i += 1;
            }
        }

        if (to == null or amount == 0) {
            print("Error: --to and --amount are required\n", .{});
            return;
        }

        // Use first account if no from address specified
        if (from == null and self.wallet.?.accounts.items.len > 0) {
            from = self.wallet.?.accounts.items[0].address;
        }

        if (from) |from_addr| {
            // Create transaction
            var tx = try transaction.ProtocolFactory.createTransaction(self.allocator, .ghostchain, from_addr, to.?, amount);
            defer tx.deinit(self.allocator);

            // Estimate fee
            const fee = transaction.ProtocolFactory.estimateFee(.ghostchain, amount, null, null);
            tx.fee = fee;

            print("Transaction Preview:\n", .{});
            print("  From: {s}\n", .{tx.from});
            print("  To: {s}\n", .{tx.to});
            print("  Amount: {d} {s}\n", .{ tx.amount, tx.currency });
            print("  Fee: {d} {s}\n", .{ tx.fee, tx.currency });

            print("Transaction sent! (simulated)\n", .{});
        } else {
            print("Error: No accounts found\n", .{});
        }
    }

    fn cmdReceive(self: *CLI, args: [][:0]u8) !void {
        _ = args;

        if (self.wallet == null) {
            print("Error: No wallet loaded. Use 'generate' or 'import' first.\n", .{});
            return;
        }

        if (self.wallet.?.accounts.items.len > 0) {
            const address = self.wallet.?.accounts.items[0].address;
            print("Receive Address: {s}\n", .{address});
            print("QR Code: [Generated QR would appear here]\n", .{});
        } else {
            print("Error: No accounts found\n", .{});
        }
    }

    fn cmdAccounts(self: *CLI, args: [][:0]u8) !void {
        _ = args;

        if (self.wallet == null) {
            print("Error: No wallet loaded. Use 'generate' or 'import' first.\n", .{});
            return;
        }

        print("Accounts:\n", .{});
        for (self.wallet.?.accounts.items, 0..) |account, idx| {
            print("  {d}. ({s}) - Address: {s}\n", .{ idx + 1, @tagName(account.protocol), account.address });
        }
    }

    fn cmdUnlock(self: *CLI, args: [][:0]u8) !void {
        _ = args;

        if (self.wallet == null) {
            print("Error: No wallet loaded. Use 'generate' or 'import' first.\n", .{});
            return;
        }

        // TODO: Prompt for password securely
        try self.wallet.?.unlock("password");
        print("Wallet unlocked.\n", .{});
    }

    fn cmdBridge(self: *CLI, args: [][:0]u8) !void {
        _ = args;

        if (self.wallet == null) {
            print("Error: No wallet loaded. Use 'generate' or 'import' first.\n", .{});
            return;
        }

        // TODO: Parse args for port, http3 options, etc.
        const port: u16 = 8443;
        const enable_http3 = true;

        print("Starting Zwallet Web3 bridge server...\n", .{});
        print("Port: {}\n", .{port});
        print("HTTP/3 enabled: {}\n", .{enable_http3});
        print("Wraith integration: {s}\n", .{if (enable_http3) "enabled" else "disabled"});

        // When Wraith is available, this will create and start the enhanced bridge
        const wraith_bridge = @import("../bridge/wraith_bridge.zig");
        const config = wraith_bridge.WraithConfig{
            .port = port,
            .enable_http3 = enable_http3,
            .enable_auto_cert = true,
            .cors_origins = &[_][]const u8{
                "https://localhost:3000",
                "https://wallet.app",
            },
            .rate_limit_rpm = 100,
        };

        var bridge = try wraith_bridge.createWraithBridge(self.allocator, &self.wallet.?, config);
        try bridge.start();
    }

    fn cmdLock(self: *CLI) !void {
        if (self.wallet == null) {
            print("Error: No wallet loaded.\n", .{});
            return;
        }

        self.wallet.?.lock();
        print("Wallet locked.\n", .{});
    }
};

test "CLI initialization" {
    var cli = CLI.init(std.testing.allocator);
    defer cli.deinit();

    try std.testing.expect(cli.wallet == null);
}
