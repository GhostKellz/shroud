//! Core wallet functionality
//! Manages keys, accounts, and transactions

const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("../utils/crypto.zig");
const keystore = @import("../utils/keystore.zig");

pub const WalletError = error{
    InvalidMnemonic,
    InvalidKey,
    InvalidAddress,
    InsufficientFunds,
    NetworkError,
    KeyDerivationFailed,
    UnknownProtocol,
    WalletLocked,
    InvalidPassword,
};

pub const WalletMode = enum {
    public_identity,
    private_cold,
    hybrid,
};

pub const Protocol = enum {
    ghostchain,
    ethereum,
    stellar,
    hedera,
    ripple,
};

pub const KeyType = crypto.KeyType;

pub const Account = struct {
    address: []const u8,
    protocol: Protocol,
    key_type: KeyType,
    keypair: ?crypto.KeyPair,
    name: ?[]const u8,
    balance: i64, // in micro-units
    currency: []const u8,

    pub fn init(allocator: Allocator, protocol: Protocol, key_type: KeyType, name: ?[]const u8) !Account {
        // Generate keypair
        var keypair = try crypto.KeyPair.generate(key_type);

        // Generate address from public key (simplified)
        const address = try generateAddress(allocator, &keypair.public_key, protocol);

        return Account{
            .address = address,
            .protocol = protocol,
            .key_type = key_type,
            .keypair = keypair,
            .name = if (name) |n| try allocator.dupe(u8, n) else null,
            .balance = 0,
            .currency = try allocator.dupe(u8, getDefaultCurrency(protocol)),
        };
    }

    pub fn deinit(self: *Account, allocator: Allocator) void {
        allocator.free(self.address);
        if (self.keypair) |*kp| {
            kp.deinit();
        }
        if (self.name) |n| allocator.free(n);
        allocator.free(self.currency);
    }

    pub fn getPublicKey(self: *const Account) ?[32]u8 {
        if (self.keypair) |kp| {
            return kp.public_key;
        }
        return null;
    }

    pub fn sign(self: *const Account, message: []const u8, allocator: Allocator) ![]u8 {
        if (self.keypair) |kp| {
            return try kp.sign(message, allocator);
        }
        return WalletError.InvalidKey;
    }
};

pub const Wallet = struct {
    allocator: Allocator,
    mode: WalletMode,
    accounts: std.ArrayList(Account),
    keystore_path: ?[]const u8,
    is_locked: bool,
    master_seed: ?[32]u8,

    pub fn init(allocator: Allocator, mode: WalletMode, keystore_path: ?[]const u8) Wallet {
        return Wallet{
            .allocator = allocator,
            .mode = mode,
            .accounts = std.ArrayList(Account).init(allocator),
            .keystore_path = keystore_path,
            .is_locked = true,
            .master_seed = null,
        };
    }

    pub fn deinit(self: *Wallet) void {
        for (self.accounts.items) |*account| {
            account.deinit(self.allocator);
        }
        self.accounts.deinit();

        // Zero out master seed
        if (self.master_seed) |*seed| {
            @memset(seed, 0);
        }
    }

    /// Generate new wallet from mnemonic
    pub fn fromMnemonic(allocator: Allocator, mnemonic: []const u8, password: ?[]const u8, mode: WalletMode) !Wallet {
        _ = mnemonic;
        _ = password;

        var wallet = Wallet.init(allocator, mode, null);
        // TODO: Implement BIP-39 mnemonic to seed derivation
        wallet.is_locked = false;
        return wallet;
    }

    /// Generate new random wallet
    pub fn generate(allocator: Allocator, mode: WalletMode) !Wallet {
        var wallet = Wallet.init(allocator, mode, null);

        // Generate random seed
        var seed: [32]u8 = undefined;
        std.crypto.random.bytes(&seed);
        wallet.master_seed = seed;
        wallet.is_locked = false;

        return wallet;
    }

    /// Create new account for specified protocol
    pub fn createAccount(self: *Wallet, protocol: Protocol, key_type: KeyType, name: ?[]const u8) !void {
        if (self.is_locked) return WalletError.WalletLocked;

        const account = try Account.init(self.allocator, protocol, key_type, name);
        try self.accounts.append(account);
    }

    /// Get account by address
    pub fn getAccount(self: *Wallet, address: []const u8) ?*Account {
        for (self.accounts.items) |*account| {
            if (std.mem.eql(u8, account.address, address)) {
                return account;
            }
        }
        return null;
    }

    /// Get balance for account
    pub fn getBalance(self: *Wallet, address: []const u8, currency: []const u8) !i64 {
        _ = currency;

        if (self.getAccount(address)) |account| {
            return account.balance;
        }
        return WalletError.InvalidAddress;
    }

    /// Lock wallet (clear sensitive data from memory)
    pub fn lock(self: *Wallet) void {
        self.is_locked = true;
        if (self.master_seed) |*seed| {
            @memset(seed, 0);
            self.master_seed = null;
        }

        // Clear private keys from accounts
        for (self.accounts.items) |*account| {
            if (account.keypair) |*kp| {
                kp.deinit();
                account.keypair = null;
            }
        }
    }

    /// Unlock wallet with password
    pub fn unlock(self: *Wallet, password: []const u8) !void {
        _ = password;
        // TODO: Implement keystore decryption
        self.is_locked = false;
    }

    /// Save wallet to encrypted keystore
    pub fn save(self: *Wallet, path: []const u8, password: []const u8) !void {
        _ = self;
        _ = path;
        _ = password;
        // TODO: Implement encrypted keystore format
    }

    /// Load wallet from encrypted keystore
    pub fn load(allocator: Allocator, path: []const u8, password: []const u8) !Wallet {
        _ = path;
        _ = password;
        // TODO: Implement keystore loading
        return Wallet.init(allocator, .hybrid, null);
    }
};

/// Generate address from public key for a specific protocol
fn generateAddress(allocator: Allocator, public_key: *const [32]u8, protocol: Protocol) ![]const u8 {
    switch (protocol) {
        .ghostchain => {
            // GhostChain address format: gc_ + base58(hash(public_key))
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(public_key, &hash, .{});
            const hex = try std.fmt.allocPrint(allocator, "gc_{}", .{std.fmt.fmtSliceHexLower(hash[0..20])});
            return hex;
        },
        .ethereum => {
            // Ethereum address: 0x + last 20 bytes of keccak256(public_key)
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(public_key, &hash, .{}); // TODO: Use Keccak256
            const hex = try std.fmt.allocPrint(allocator, "0x{}", .{std.fmt.fmtSliceHexLower(hash[12..32])});
            return hex;
        },
        .stellar => {
            // Stellar address: G + base32(public_key + checksum)
            const hex = try std.fmt.allocPrint(allocator, "G{}", .{std.fmt.fmtSliceHexUpper(public_key[0..28])});
            return hex;
        },
        .hedera => {
            // Hedera account ID format: 0.0.xxxxx
            const account_num = @as(u64, @intCast(public_key[0])) |
                (@as(u64, @intCast(public_key[1])) << 8) |
                (@as(u64, @intCast(public_key[2])) << 16);
            const address = try std.fmt.allocPrint(allocator, "0.0.{}", .{account_num});
            return address;
        },
        .ripple => {
            // XRPL address: r + base58(public_key + checksum)
            const hex = try std.fmt.allocPrint(allocator, "r{}", .{std.fmt.fmtSliceHexUpper(public_key[0..25])});
            return hex;
        },
    }
}

/// Get default currency for protocol
fn getDefaultCurrency(protocol: Protocol) []const u8 {
    return switch (protocol) {
        .ghostchain => "GCC",
        .ethereum => "ETH",
        .stellar => "XLM",
        .hedera => "HBAR",
        .ripple => "XRP",
    };
}

test "wallet creation" {
    var wallet = Wallet.generate(std.testing.allocator, .hybrid) catch unreachable;
    defer wallet.deinit();

    try std.testing.expect(!wallet.is_locked);
    try std.testing.expect(wallet.accounts.items.len == 0);
}

test "account management" {
    var wallet = Wallet.generate(std.testing.allocator, .hybrid) catch unreachable;
    defer wallet.deinit();

    try wallet.createAccount(.ghostchain, .ed25519, "test-account");
    try std.testing.expect(wallet.accounts.items.len == 1);
}
