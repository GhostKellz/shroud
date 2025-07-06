//! Keystone - Advanced Ledger Engine (evolved from Zledger)
//! Part of Shroud v1.0 modular architecture
const std = @import("std");

pub const tx = @import("tx.zig");
pub const account = @import("account.zig");
pub const journal = @import("journal.zig");
pub const audit = @import("audit.zig");
pub const cli = @import("cli.zig");
pub const fixed_point = @import("fixed_point.zig");
pub const crypto_storage = @import("crypto_storage.zig");
pub const zwallet_integration = @import("zwallet_integration.zig");

// Comprehensive crypto tests
test {
    @import("crypto_tests.zig");
}

pub const Transaction = tx.Transaction;
pub const Account = account.Account;
pub const AccountType = account.AccountType;
pub const Ledger = account.Ledger;
pub const Journal = journal.Journal;
pub const JournalEntry = journal.JournalEntry;
pub const Auditor = audit.Auditor;
pub const AuditReport = audit.AuditReport;
pub const Cli = cli.Cli;
pub const FixedPoint = fixed_point.FixedPoint;
pub const EncryptedStorage = crypto_storage.EncryptedStorage;
pub const EncryptedData = crypto_storage.EncryptedData;
pub const SecureFile = crypto_storage.SecureFile;
pub const WalletKeypair = zwallet_integration.WalletKeypair;
pub const TransactionSigner = zwallet_integration.TransactionSigner;
pub const WalletInfo = zwallet_integration.WalletInfo;
pub const HDWallet = zwallet_integration.HDWallet;
pub const SignatureAlgorithm = zwallet_integration.SignatureAlgorithm;

pub fn advancedPrint() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Keystone - Advanced Ledger Engine v1.0\n", .{});
    try stdout.print("Run `zig build test` to run the tests.\n", .{});
    try stdout.print("Use `keystone --help` for CLI usage.\n", .{});

    try bw.flush();
}
