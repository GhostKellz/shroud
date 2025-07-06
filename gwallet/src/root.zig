//! GWallet - A Secure, Programmable Wallet for Zig with RealID Integration
//! Core wallet functionality with multi-protocol support

const std = @import("std");

// Re-export core modules
pub const wallet = @import("core/wallet_realid.zig");
pub const tx = @import("core/tx.zig");
pub const qid = @import("core/qid.zig");
pub const ffi = @import("core/ffi.zig");
pub const transaction = @import("protocol/transaction.zig");
pub const identity = @import("identity/resolver.zig");
pub const bridge = @import("bridge/api.zig");
pub const wraith_bridge = @import("bridge/wraith_bridge.zig");
pub const cli = @import("cli/commands.zig");

// Re-export key types
pub const Wallet = wallet.Wallet;
pub const Account = wallet.Account;
pub const Transaction = tx.Transaction;
pub const QID = qid.QID;
pub const Identity = identity.Identity;
pub const CLI = cli.CLI;
pub const Bridge = bridge.Bridge;
pub const WraithBridge = wraith_bridge.WraithBridge;
pub const WraithConfig = wraith_bridge.WraithConfig;

// Re-export FFI types for Rust integration
pub const GWalletContext = ffi.GWalletContext;
pub const WalletAccount = ffi.WalletAccount;
pub const RealIdContext = ffi.RealIdContext;
pub const ZidIdentity = ffi.ZidIdentity;
pub const SignatureResult = ffi.SignatureResult;

// Re-export enums
pub const WalletMode = wallet.WalletMode;
pub const Protocol = wallet.Protocol;
pub const KeyType = wallet.KeyType;
pub const DomainType = identity.DomainType;

// Re-export errors
pub const WalletError = wallet.WalletError;
pub const IdentityError = identity.IdentityError;
pub const BridgeError = bridge.BridgeError;

/// Library version
pub const version = "0.3.0";

/// Initialize a new wallet
pub fn createWallet(allocator: std.mem.Allocator, passphrase: []const u8, mode: WalletMode) !Wallet {
    return Wallet.create(allocator, passphrase, mode, null);
}

/// Import wallet from mnemonic
pub fn importWallet(allocator: std.mem.Allocator, mnemonic: []const u8, password: ?[]const u8, mode: WalletMode) !Wallet {
    return Wallet.fromMnemonic(allocator, mnemonic, password, mode);
}

/// Resolve identity to address
pub fn resolveIdentity(allocator: std.mem.Allocator, domain: []const u8) ![]const u8 {
    var resolver = identity.IdentityResolver.init(allocator);
    defer resolver.deinit();

    return resolver.resolve(domain);
}

/// Start bridge server for web3 integration
pub fn startBridge(allocator: std.mem.Allocator, port: u16) !bridge.BridgeServer {
    var server = bridge.BridgeServer.init(allocator, port);
    try server.start();
    return server;
}

// Re-export utility modules
pub const crypto = @import("utils/crypto.zig");
pub const keystore = @import("utils/keystore.zig");

test "wallet creation" {
    var w = try createWallet(std.testing.allocator, "test_passphrase", .hybrid);
    defer w.deinit();

    try std.testing.expect(!w.is_locked);
}

test "identity resolution" {
    const domain = "test.eth";
    const address = try resolveIdentity(std.testing.allocator, domain);
    defer std.testing.allocator.free(address);

    try std.testing.expect(address.len > 0);
}
