//! Core wallet functionality with RealID integration
const std = @import("std");
const sigil = @import("sigil");
const qid = @import("qid.zig");
const tx = @import("tx.zig");

pub const WalletError = error{
    InvalidPassphrase,
    WalletLocked,
    InsufficientFunds,
    InvalidAddress,
    SigningFailed,
    QIDGenerationFailed,
    DeviceBindingFailed,
    InvalidAccountType,
    AccountNotFound,
};

pub const WalletMode = enum {
    public_identity,
    private_cold,
    hybrid,
    device_bound,
};

pub const Protocol = enum {
    ghostchain,
    ethereum,
    stellar,
    hedera,
    bitcoin,

    pub fn format(self: Protocol, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        return writer.print("{s}", .{@tagName(self)});
    }
};

pub const KeyType = enum {
    ed25519,
    secp256k1,

    pub fn format(self: KeyType, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        return writer.print("{s}", .{@tagName(self)});
    }
};

pub const Balance = struct {
    protocol: Protocol,
    token: []const u8,
    amount: u64,
    decimals: u8,

    pub fn deinit(self: *Balance, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
    }
};

pub const WalletMetadata = struct {
    name: ?[]const u8,
    created_at: i64,
    last_used: i64,
    device_bound: bool,
    version: []const u8,

    pub fn deinit(self: *WalletMetadata, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        allocator.free(self.version);
    }
};

pub const Account = struct {
    address: []const u8,
    public_key: sigil.RealIDPublicKey,
    key_type: KeyType,
    protocol: Protocol,
    qid: qid.QID,
    derivation_path: ?[]const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        if (self.derivation_path) |path| {
            allocator.free(path);
        }
    }

    pub fn getQIDString(self: Self, buffer: []u8) ![]u8 {
        return self.qid.toString(buffer);
    }
};

pub const Wallet = struct {
    allocator: std.mem.Allocator,
    realid_identity: ?sigil.RealIDKeyPair,
    master_qid: ?qid.QID,
    mode: WalletMode,
    is_locked: bool,
    accounts: std.ArrayList(Account),
    balances: std.ArrayList(Balance),
    metadata: WalletMetadata,
    passphrase_hash: ?[32]u8,

    const Self = @This();

    /// Create a new wallet using RealID passphrase
    pub fn create(allocator: std.mem.Allocator, passphrase: []const u8, mode: WalletMode, name: ?[]const u8) !Self {
        // Generate RealID identity
        const identity = if (mode == .device_bound) blk: {
            const device_fp = try sigil.generate_device_fingerprint(allocator);
            break :blk try sigil.realid_generate_from_passphrase_with_device(passphrase, device_fp);
        } else try sigil.realid_generate_from_passphrase(passphrase);

        // Generate master QID from public key
        const wallet_qid = qid.QID.fromPublicKey(identity.public_key.bytes);

        // Hash passphrase for verification
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(passphrase);
        var passphrase_hash: [32]u8 = undefined;
        hasher.final(&passphrase_hash);

        const current_time = std.time.timestamp();

        return Self{
            .allocator = allocator,
            .realid_identity = identity,
            .master_qid = wallet_qid,
            .mode = mode,
            .is_locked = false,
            .accounts = std.ArrayList(Account).init(allocator),
            .balances = std.ArrayList(Balance).init(allocator),
            .metadata = WalletMetadata{
                .name = if (name) |n| try allocator.dupe(u8, n) else null,
                .created_at = current_time,
                .last_used = current_time,
                .device_bound = mode == .device_bound,
                .version = try allocator.dupe(u8, "0.1.0"),
            },
            .passphrase_hash = passphrase_hash,
        };
    }

    /// Load wallet from stored data and unlock with passphrase
    pub fn load(allocator: std.mem.Allocator, stored_data: []const u8, passphrase: []const u8) !Self {
        // In a real implementation, this would deserialize stored wallet data
        // For now, recreate from passphrase
        _ = stored_data;
        return Self.create(allocator, passphrase, .hybrid, "loaded_wallet");
    }

    /// Import wallet from mnemonic phrase
    pub fn fromMnemonic(allocator: std.mem.Allocator, mnemonic: []const u8, password: ?[]const u8, mode: WalletMode) !Self {
        // In a real implementation, this would derive keys from mnemonic
        // For now, use the mnemonic as passphrase (with optional password)
        const passphrase = if (password) |pwd| 
            try std.fmt.allocPrint(allocator, "{s}:{s}", .{mnemonic, pwd})
        else 
            try allocator.dupe(u8, mnemonic);
        defer allocator.free(passphrase);
        
        return Self.create(allocator, passphrase, mode, "imported_wallet");
    }

    /// Verify passphrase without unlocking
    pub fn verifyPassphrase(self: *const Self, passphrase: []const u8) bool {
        if (self.passphrase_hash == null) return false;

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(passphrase);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        return std.mem.eql(u8, &hash, &self.passphrase_hash.?);
    }

    /// Lock the wallet (clear sensitive data)
    pub fn lock(self: *Self) void {
        self.is_locked = true;
        // In production, would securely clear sensitive memory
        if (self.realid_identity) |*identity| {
            std.crypto.utils.secureZero(u8, &identity.private_key.bytes);
        }
    }

    /// Unlock the wallet with passphrase
    pub fn unlock(self: *Self, passphrase: []const u8) !void {
        if (!self.verifyPassphrase(passphrase)) {
            return WalletError.InvalidPassphrase;
        }

        // Regenerate RealID identity from passphrase
        const identity = if (self.metadata.device_bound) blk: {
            const device_fp = try sigil.generate_device_fingerprint(self.allocator);
            break :blk try sigil.realid_generate_from_passphrase_with_device(passphrase, device_fp);
        } else try sigil.realid_generate_from_passphrase(passphrase);

        self.realid_identity = identity;
        self.is_locked = false;
        self.metadata.last_used = std.time.timestamp();
    }

    /// Get wallet address for protocol
    pub fn getAddress(self: *const Self, protocol: Protocol) ![]const u8 {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;

        const identity = self.realid_identity.?;

        switch (protocol) {
            .ghostchain => {
                // GhostChain uses QID-based addressing
                if (self.master_qid) |master_qid| {
                    var buffer: [64]u8 = undefined;
                    const qid_str = try master_qid.toString(&buffer);
                    return try self.allocator.dupe(u8, qid_str);
                }
                return WalletError.QIDGenerationFailed;
            },
            .ethereum => {
                // Ethereum address from public key
                return try self.deriveEthereumAddress(identity.public_key);
            },
            .bitcoin => {
                // Bitcoin address from public key
                return try self.deriveBitcoinAddress(identity.public_key);
            },
            .stellar, .hedera => {
                // Use public key directly for these protocols
                const pubkey_hex = try std.fmt.allocPrint(self.allocator, "{}", .{std.fmt.fmtSliceHexLower(&identity.public_key.bytes)});
                return pubkey_hex;
            },
        }
    }

    /// Create account for specific protocol
    pub fn createAccount(self: *Self, protocol: Protocol, key_type: KeyType) !Account {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;

        const identity = self.realid_identity.?;
        const address = try self.getAddress(protocol);
        const account_qid = qid.QID.fromPublicKey(identity.public_key.bytes);

        const account = Account{
            .address = address,
            .public_key = identity.public_key,
            .key_type = key_type,
            .protocol = protocol,
            .qid = account_qid,
            .derivation_path = null,
        };

        try self.accounts.append(account);
        return account;
    }

    /// Sign transaction with wallet
    pub fn signTransaction(self: *Self, transaction: *tx.Transaction) !void {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;

        const identity = self.realid_identity.?;
        try transaction.sign(identity);
    }

    /// Get account balance for protocol and token
    pub fn getBalance(self: *const Self, protocol: Protocol, token: []const u8) ?u64 {
        for (self.balances.items) |balance| {
            if (balance.protocol == protocol and std.mem.eql(u8, balance.token, token)) {
                return balance.amount;
            }
        }
        return null;
    }

    /// Update account balance
    pub fn updateBalance(self: *Self, protocol: Protocol, token: []const u8, amount: u64, decimals: u8) !void {
        // Find existing balance entry
        for (self.balances.items) |*balance| {
            if (balance.protocol == protocol and std.mem.eql(u8, balance.token, token)) {
                balance.amount = amount;
                return;
            }
        }

        // Create new balance entry
        const balance = Balance{
            .protocol = protocol,
            .token = try self.allocator.dupe(u8, token),
            .amount = amount,
            .decimals = decimals,
        };

        try self.balances.append(balance);
    }

    /// Get master QID string
    pub fn getMasterQID(self: *const Self, buffer: []u8) ![]u8 {
        if (self.master_qid) |master_qid| {
            return master_qid.toString(buffer);
        }
        return WalletError.QIDGenerationFailed;
    }

    /// Get RealID identity
    pub fn getRealIdIdentity(self: *const Self) !sigil.RealIDKeyPair {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity) |identity| {
            return identity;
        }
        return WalletError.WalletLocked;
    }

    /// Derive Ethereum address from public key
    fn deriveEthereumAddress(self: *const Self, public_key: sigil.RealIDPublicKey) ![]const u8 {
        // Ethereum address is last 20 bytes of Keccak256(public_key)
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&public_key.bytes);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        // Take last 20 bytes and format as hex with 0x prefix
        const addr_bytes = hash[12..32];
        return try std.fmt.allocPrint(self.allocator, "0x{}", .{std.fmt.fmtSliceHexLower(addr_bytes)});
    }

    /// Derive Bitcoin address from public key
    fn deriveBitcoinAddress(self: *const Self, public_key: sigil.RealIDPublicKey) ![]const u8 {
        // Simplified Bitcoin address derivation (P2PKH)
        // Real implementation would use proper Base58Check encoding
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&public_key.bytes);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        return try std.fmt.allocPrint(self.allocator, "bc1q{}", .{std.fmt.fmtSliceHexLower(hash[0..20])});
    }

    pub fn deinit(self: *Self) void {
        // Clear accounts
        for (self.accounts.items) |*account| {
            account.deinit(self.allocator);
        }
        self.accounts.deinit();

        // Clear balances
        for (self.balances.items) |*balance| {
            balance.deinit(self.allocator);
        }
        self.balances.deinit();

        // Clear metadata
        self.metadata.deinit(self.allocator);

        // Securely clear sensitive data
        if (self.realid_identity) |*identity| {
            std.crypto.utils.secureZero(u8, &identity.private_key.bytes);
        }
    }
};

test "wallet creation with RealID" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var wallet = try Wallet.create(allocator, "test_passphrase_123", .hybrid, "test_wallet");
    defer wallet.deinit();

    try std.testing.expect(!wallet.is_locked);
    try std.testing.expect(wallet.master_qid != null);
    try std.testing.expect(wallet.realid_identity != null);
}

test "wallet lock and unlock" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var wallet = try Wallet.create(allocator, "secure_passphrase", .device_bound, "secure_wallet");
    defer wallet.deinit();

    try std.testing.expect(!wallet.is_locked);

    // Lock wallet
    wallet.lock();
    try std.testing.expect(wallet.is_locked);

    // Unlock with correct passphrase
    try wallet.unlock("secure_passphrase");
    try std.testing.expect(!wallet.is_locked);

    // Try to unlock with wrong passphrase
    wallet.lock();
    const result = wallet.unlock("wrong_passphrase");
    try std.testing.expectError(WalletError.InvalidPassphrase, result);
}

test "account creation and addressing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var wallet = try Wallet.create(allocator, "test_passphrase", .hybrid, "multi_protocol_wallet");
    defer wallet.deinit();

    // Create accounts for different protocols
    const ghost_account = try wallet.createAccount(.ghostchain, .ed25519);
    const eth_account = try wallet.createAccount(.ethereum, .secp256k1);

    try std.testing.expect(ghost_account.protocol == .ghostchain);
    try std.testing.expect(eth_account.protocol == .ethereum);
    try std.testing.expect(wallet.accounts.items.len == 2);
}
