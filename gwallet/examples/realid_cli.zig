//! Example CLI demonstrating RealID-integrated GhostWallet functionality
//! This shows how to use the modular wallet system with RealID passphrases

const std = @import("std");
const print = std.debug.print;
const wallet = @import("wallet_realid.zig");
const tx = @import("tx.zig");
const qid = @import("qid.zig");
const ffi = @import("ffi.zig");

const Command = enum {
    create,
    load,
    unlock,
    lock,
    account,
    balance,
    send,
    qid,
    sign,
    verify,
    help,
};

const ExampleCLI = struct {
    allocator: std.mem.Allocator,
    wallet: ?wallet.Wallet,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .wallet = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.wallet) |*w| {
            w.deinit();
        }
    }

    pub fn run(self: *Self, args: [][:0]u8) !void {
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
            .create => try self.cmdCreate(args[2..]),
            .load => try self.cmdLoad(args[2..]),
            .unlock => try self.cmdUnlock(args[2..]),
            .lock => try self.cmdLock(),
            .account => try self.cmdAccount(args[2..]),
            .balance => try self.cmdBalance(args[2..]),
            .send => try self.cmdSend(args[2..]),
            .qid => try self.cmdQID(args[2..]),
            .sign => try self.cmdSign(args[2..]),
            .verify => try self.cmdVerify(args[2..]),
            .help => try self.showHelp(),
        }
    }

    fn showHelp(self: *Self) !void {
        _ = self;
        print(
            \\ZWallet RealID CLI - Secure Wallet with Identity Integration
            \\
            \\USAGE:
            \\    zwallet_cli <COMMAND> [OPTIONS]
            \\
            \\COMMANDS:
            \\    create       Create new wallet with RealID passphrase
            \\    load         Load existing wallet
            \\    unlock       Unlock wallet with passphrase
            \\    lock         Lock wallet
            \\    account      Create account for protocol
            \\    balance      Check account balance
            \\    send         Send transaction
            \\    qid          Show QID information
            \\    sign         Sign data with RealID
            \\    verify       Verify signature
            \\    help         Show this help
            \\
            \\EXAMPLES:
            \\    # Create device-bound wallet
            \\    zwallet_cli create --passphrase "my_secure_phrase" --name "main_wallet" --device-bound
            \\    
            \\    # Create account for different protocols
            \\    zwallet_cli account --protocol ghostchain --keytype ed25519
            \\    zwallet_cli account --protocol ethereum --keytype secp256k1
            \\    
            \\    # Check balance
            \\    zwallet_cli balance --protocol ghostchain --token gcc
            \\    
            \\    # Send transaction
            \\    zwallet_cli send --to "ghost1abc123" --amount 1000000 --protocol ghostchain
            \\    
            \\    # Show QID
            \\    zwallet_cli qid
            \\    
            \\    # Sign arbitrary data
            \\    zwallet_cli sign --data "Hello, GhostNet!"
            \\
        );
    }

    fn cmdCreate(self: *Self, args: [][:0]u8) !void {
        var passphrase: ?[]const u8 = null;
        var name: ?[]const u8 = null;
        var device_bound = false;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--passphrase") and i + 1 < args.len) {
                passphrase = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--name") and i + 1 < args.len) {
                name = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--device-bound")) {
                device_bound = true;
            }
        }

        if (passphrase == null) {
            print("Error: --passphrase is required\n");
            return;
        }

        const mode: wallet.WalletMode = if (device_bound) .device_bound else .hybrid;

        print("Creating wallet with RealID integration...\n");
        print("Mode: {s}\n", .{if (device_bound) "Device-bound" else "Hybrid"});

        var new_wallet = wallet.Wallet.create(self.allocator, passphrase.?, mode, name) catch |err| {
            print("Error creating wallet: {}\n", .{err});
            return;
        };

        // Show master QID
        var qid_buffer: [64]u8 = undefined;
        const master_qid_str = try new_wallet.getMasterQID(&qid_buffer);
        print("Wallet created successfully!\n");
        print("Master QID: {s}\n", .{master_qid_str});

        if (name) |wallet_name| {
            print("Name: {s}\n", .{wallet_name});
        }

        self.wallet = new_wallet;
    }

    fn cmdLoad(self: *Self, args: [][:0]u8) !void {
        // For demonstration, just recreate from passphrase
        if (args.len < 1) {
            print("Usage: load <passphrase>\n");
            return;
        }

        const passphrase = args[0];
        print("Loading wallet from passphrase...\n");

        // In real implementation, would load from file
        const dummy_data = "dummy_wallet_data";
        const loaded_wallet = wallet.Wallet.load(self.allocator, dummy_data, passphrase) catch |err| {
            print("Error loading wallet: {}\n", .{err});
            return;
        };

        print("Wallet loaded successfully!\n");
        self.wallet = loaded_wallet;
    }

    fn cmdUnlock(self: *Self, args: [][:0]u8) !void {
        if (self.wallet == null) {
            print("No wallet loaded. Use 'create' or 'load' first.\n");
            return;
        }

        if (args.len < 1) {
            print("Usage: unlock <passphrase>\n");
            return;
        }

        const passphrase = args[0];
        self.wallet.?.unlock(passphrase) catch |err| {
            print("Error unlocking wallet: {}\n", .{err});
            return;
        };

        print("Wallet unlocked successfully!\n");
    }

    fn cmdLock(self: *Self) !void {
        if (self.wallet == null) {
            print("No wallet loaded.\n");
            return;
        }

        self.wallet.?.lock();
        print("Wallet locked.\n");
    }

    fn cmdAccount(self: *Self, args: [][:0]u8) !void {
        if (self.wallet == null) {
            print("No wallet loaded. Use 'create' or 'load' first.\n");
            return;
        }

        var protocol: wallet.Protocol = .ghostchain;
        var key_type: wallet.KeyType = .ed25519;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--protocol") and i + 1 < args.len) {
                const proto_str = args[i + 1];
                protocol = std.meta.stringToEnum(wallet.Protocol, proto_str) orelse .ghostchain;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--keytype") and i + 1 < args.len) {
                const key_str = args[i + 1];
                key_type = std.meta.stringToEnum(wallet.KeyType, key_str) orelse .ed25519;
                i += 1;
            }
        }

        print("Creating account for protocol: {}\n", .{protocol});
        print("Key type: {}\n", .{key_type});

        const account = self.wallet.?.createAccount(protocol, key_type) catch |err| {
            print("Error creating account: {}\n", .{err});
            return;
        };

        print("Account created successfully!\n");
        print("Address: {s}\n", .{account.address});

        var qid_buffer: [64]u8 = undefined;
        const qid_str = try account.getQIDString(&qid_buffer);
        print("QID: {s}\n", .{qid_str});
    }

    fn cmdBalance(self: *Self, args: [][:0]u8) !void {
        if (self.wallet == null) {
            print("No wallet loaded.\n");
            return;
        }

        var protocol: wallet.Protocol = .ghostchain;
        var token: []const u8 = "gcc";

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--protocol") and i + 1 < args.len) {
                const proto_str = args[i + 1];
                protocol = std.meta.stringToEnum(wallet.Protocol, proto_str) orelse .ghostchain;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--token") and i + 1 < args.len) {
                token = args[i + 1];
                i += 1;
            }
        }

        const balance = self.wallet.?.getBalance(protocol, token) orelse 0;
        print("Balance for {} {s}: {}\n", .{ protocol, token, balance });

        // Update balance for demonstration
        if (balance == 0) {
            print("Setting demo balance of 1000000...\n");
            try self.wallet.?.updateBalance(protocol, token, 1000000, 18);
            print("Updated balance: 1000000\n");
        }
    }

    fn cmdSend(self: *Self, args: [][:0]u8) !void {
        if (self.wallet == null) {
            print("No wallet loaded.\n");
            return;
        }

        var to_address: ?[]const u8 = null;
        var amount: u64 = 0;
        var protocol: wallet.Protocol = .ghostchain;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--to") and i + 1 < args.len) {
                to_address = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--amount") and i + 1 < args.len) {
                amount = std.fmt.parseInt(u64, args[i + 1], 10) catch 0;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--protocol") and i + 1 < args.len) {
                const proto_str = args[i + 1];
                protocol = std.meta.stringToEnum(wallet.Protocol, proto_str) orelse .ghostchain;
                i += 1;
            }
        }

        if (to_address == null or amount == 0) {
            print("Usage: send --to <address> --amount <amount> [--protocol <protocol>]\n");
            return;
        }

        // Get wallet address
        const from_address = self.wallet.?.getAddress(protocol) catch |err| {
            print("Error getting wallet address: {}\n", .{err});
            return;
        };
        defer self.allocator.free(from_address);

        print("Creating transaction...\n");
        print("From: {s}\n", .{from_address});
        print("To: {s}\n", .{to_address.?});
        print("Amount: {}\n", .{amount});
        print("Protocol: {}\n", .{protocol});

        // Create transaction
        var transaction = tx.Transaction.createTransfer(
            self.allocator,
            protocol,
            from_address,
            to_address.?,
            amount,
            1000, // Fixed fee for demo
        ) catch |err| {
            print("Error creating transaction: {}\n", .{err});
            return;
        };
        defer transaction.deinit(self.allocator);

        // Sign transaction
        self.wallet.?.signTransaction(&transaction) catch |err| {
            print("Error signing transaction: {}\n", .{err});
            return;
        };

        // Verify transaction
        const is_valid = transaction.verify() catch false;
        print("Transaction created and signed!\n");
        print("Valid: {}\n", .{is_valid});

        var tx_hash: [64]u8 = undefined;
        const hash_str = try transaction.getHashHex(&tx_hash);
        print("Transaction hash: {s}\n", .{hash_str});
    }

    fn cmdQID(self: *Self, args: [][:0]u8) !void {
        _ = args;

        if (self.wallet == null) {
            print("No wallet loaded.\n");
            return;
        }

        var qid_buffer: [64]u8 = undefined;
        const master_qid_str = self.wallet.?.getMasterQID(&qid_buffer) catch |err| {
            print("Error getting QID: {}\n", .{err});
            return;
        };

        print("Master QID: {s}\n", .{master_qid_str});

        // Show QID for each account
        print("Account QIDs:\n");
        for (self.wallet.?.accounts.items) |account| {
            var account_qid_buffer: [64]u8 = undefined;
            const account_qid_str = try account.getQIDString(&account_qid_buffer);
            print("  {} - {s}: {s}\n", .{ account.protocol, account.address, account_qid_str });
        }
    }

    fn cmdSign(self: *Self, args: [][:0]u8) !void {
        if (self.wallet == null) {
            print("No wallet loaded.\n");
            return;
        }

        var data_to_sign: ?[]const u8 = null;

        // Parse arguments
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--data") and i + 1 < args.len) {
                data_to_sign = args[i + 1];
                i += 1;
            }
        }

        if (data_to_sign == null) {
            print("Usage: sign --data <data_to_sign>\n");
            return;
        }

        if (self.wallet.?.is_locked) {
            print("Wallet is locked. Unlock first.\n");
            return;
        }

        if (self.wallet.?.realid_identity == null) {
            print("No RealID identity available.\n");
            return;
        }

        const identity = self.wallet.?.realid_identity.?;
        const signature = @import("realid").realid_sign(data_to_sign.?, identity.keypair.private_key) catch |err| {
            print("Error signing data: {}\n", .{err});
            return;
        };

        print("Data signed successfully!\n");
        print("Data: {s}\n", .{data_to_sign.?});
        print("Signature: {}\n", .{std.fmt.fmtSliceHexLower(&signature.bytes)});
    }

    fn cmdVerify(self: *Self, args: [][:0]u8) !void {
        _ = self;
        if (args.len < 3) {
            print("Usage: verify <data> <signature_hex> <public_key_hex>\n");
            return;
        }

        const data = args[0];
        const signature_hex = args[1];
        const pubkey_hex = args[2];

        // Parse hex strings
        var signature_bytes: [64]u8 = undefined;
        var pubkey_bytes: [32]u8 = undefined;

        _ = std.fmt.hexToBytes(&signature_bytes, signature_hex) catch {
            print("Invalid signature hex format\n");
            return;
        };

        _ = std.fmt.hexToBytes(&pubkey_bytes, pubkey_hex) catch {
            print("Invalid public key hex format\n");
            return;
        };

        const signature = @import("realid").RealIDSignature{ .bytes = signature_bytes };
        const public_key = @import("realid").RealIDPublicKey{ .bytes = pubkey_bytes };

        const is_valid = @import("realid").realid_verify(signature, data, public_key);

        print("Signature verification result: {}\n", .{is_valid});
        print("Data: {s}\n", .{data});
        print("Valid: {s}\n", .{if (is_valid) "YES" else "NO"});
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var cli = ExampleCLI.init(allocator);
    defer cli.deinit();

    try cli.run(args);
}
