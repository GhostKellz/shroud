//! Async wallet operations using zsync
//! Demonstrates zsync patterns for wallet and transaction processing

const std = @import("std");
const zsync = @import("zsync");

pub const AsyncWallet = struct {
    allocator: std.mem.Allocator,
    balance: std.atomic.Value(u64),
    transaction_pool: std.ArrayList(Transaction),

    const Transaction = struct {
        id: [32]u8,
        from: []const u8,
        to: []const u8,
        amount: u64,
        timestamp: i64,
    };

    pub fn init(allocator: std.mem.Allocator) AsyncWallet {
        return AsyncWallet{
            .allocator = allocator,
            .balance = std.atomic.Value(u64).init(0),
            .transaction_pool = std.ArrayList(Transaction).init(allocator),
        };
    }

    pub fn deinit(self: *AsyncWallet) void {
        for (self.transaction_pool.items) |tx| {
            self.allocator.free(tx.from);
            self.allocator.free(tx.to);
        }
        self.transaction_pool.deinit();
    }

    /// Async balance check using BlockingIo
    pub fn getBalanceAsync(self: *AsyncWallet) !u64 {
        const io = zsync.BlockingIo{};
        var future = io.async(getBalanceWorker, .{self});
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn getBalanceWorker(self: *AsyncWallet) !u64 {
        zsync.yieldNow();
        return self.balance.load(.monotonic);
    }

    /// Async transaction creation using BlockingIo for crypto operations
    pub fn createTransactionAsync(self: *AsyncWallet, from: []const u8, to: []const u8, amount: u64) !Transaction {
        const io = zsync.BlockingIo{};
        var future = io.async(createTransactionWorker, .{ self, from, to, amount });
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn createTransactionWorker(self: *AsyncWallet, from: []const u8, to: []const u8, amount: u64) !Transaction {
        // Yield before expensive crypto operation
        zsync.yieldNow();

        // Generate transaction ID using crypto hash
        var hasher = std.crypto.hash.blake3.Blake3.init(.{});
        hasher.update(from);
        hasher.update(to);
        hasher.update(std.mem.asBytes(&amount));
        hasher.update(std.mem.asBytes(&std.time.timestamp()));

        const tx = Transaction{
            .id = hasher.final(),
            .from = try self.allocator.dupe(u8, from),
            .to = try self.allocator.dupe(u8, to),
            .amount = amount,
            .timestamp = std.time.timestamp(),
        };

        return tx;
    }

    /// Async transaction processing using ThreadPoolIo for concurrent validation
    pub fn processTransactionAsync(self: *AsyncWallet, transaction: Transaction) !bool {
        const io = zsync.ThreadPoolIo{};
        var future = io.async(processTransactionWorker, .{ self, transaction });
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn processTransactionWorker(self: *AsyncWallet, transaction: Transaction) !bool {
        // Simulate transaction validation with yields
        for (0..1000) |_| {
            zsync.yieldNow();
        }

        // Validate transaction (simplified)
        if (transaction.amount == 0) return false;
        if (transaction.from.len == 0 or transaction.to.len == 0) return false;

        // Add to transaction pool
        try self.transaction_pool.append(transaction);

        return true;
    }

    /// Batch transaction processing using channels
    pub fn batchProcessTransactionsAsync(self: *AsyncWallet, transactions: []const Transaction) ![]bool {
        const io = zsync.ThreadPoolIo{};

        var results = std.ArrayList(bool).init(self.allocator);
        defer results.deinit();

        // Create channels for work distribution
        const work_channel = try zsync.bounded(Transaction, transactions.len);
        defer work_channel.close();

        const result_channel = try zsync.bounded(bool, transactions.len);
        defer result_channel.close();

        // Send transactions to work channel
        for (transactions) |tx| {
            var send_future = io.async(sendTransaction, .{ work_channel.sender(), tx });
            defer send_future.cancel(io) catch {};
            try send_future.await(io);
        }

        // Process transactions concurrently
        for (0..transactions.len) |_| {
            var process_future = io.async(processTransactionFromChannel, .{
                self,
                work_channel.receiver(),
                result_channel.sender(),
            });
            defer process_future.cancel(io) catch {};
            try process_future.await(io);
        }

        // Collect results
        for (0..transactions.len) |_| {
            var recv_future = io.async(recvTransactionResult, .{result_channel.receiver()});
            defer recv_future.cancel(io) catch {};
            const result = try recv_future.await(io);
            try results.append(result);
        }

        return try results.toOwnedSlice();
    }

    fn sendTransaction(sender: zsync.Sender(Transaction), tx: Transaction) !void {
        try sender.send(tx);
    }

    fn processTransactionFromChannel(
        self: *AsyncWallet,
        work_receiver: zsync.Receiver(Transaction),
        result_sender: zsync.Sender(bool),
    ) !void {
        const tx = try work_receiver.recv();
        const result = try self.processTransactionWorker(tx);
        try result_sender.send(result);
    }

    fn recvTransactionResult(receiver: zsync.Receiver(bool)) !bool {
        return try receiver.recv();
    }
};

/// Async audit logging using zsync
pub const AsyncAuditor = struct {
    allocator: std.mem.Allocator,
    log_entries: std.ArrayList(AuditEntry),

    const AuditEntry = struct {
        event: []const u8,
        timestamp: i64,
        details: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) AsyncAuditor {
        return AsyncAuditor{
            .allocator = allocator,
            .log_entries = std.ArrayList(AuditEntry).init(allocator),
        };
    }

    pub fn deinit(self: *AsyncAuditor) void {
        for (self.log_entries.items) |entry| {
            self.allocator.free(entry.event);
            self.allocator.free(entry.details);
        }
        self.log_entries.deinit();
    }

    /// Async audit logging using GreenThreadsIo for I/O operations
    pub fn logEventAsync(self: *AsyncAuditor, event: []const u8, details: []const u8) !void {
        const io = zsync.GreenThreadsIo{};
        var future = io.async(logEventWorker, .{ self, event, details });
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn logEventWorker(self: *AsyncAuditor, event: []const u8, details: []const u8) !void {
        zsync.yieldNow();

        const entry = AuditEntry{
            .event = try self.allocator.dupe(u8, event),
            .timestamp = std.time.timestamp(),
            .details = try self.allocator.dupe(u8, details),
        };

        try self.log_entries.append(entry);
    }

    /// Async audit report generation using BlockingIo
    pub fn generateReportAsync(self: *AsyncAuditor) ![]const u8 {
        const io = zsync.BlockingIo{};
        var future = io.async(generateReportWorker, .{self});
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn generateReportWorker(self: *AsyncAuditor) ![]const u8 {
        var report = std.ArrayList(u8).init(self.allocator);
        defer report.deinit();

        try report.appendSlice("=== AUDIT REPORT ===\n");

        for (self.log_entries.items) |entry| {
            zsync.yieldNow(); // Yield during report generation

            try report.writer().print("[{}] {}: {}\n", .{
                entry.timestamp,
                entry.event,
                entry.details,
            });
        }

        return try report.toOwnedSlice();
    }
};

test "async wallet operations" {
    const allocator = std.testing.allocator;

    var wallet = AsyncWallet.init(allocator);
    defer wallet.deinit();

    // Test balance check
    const balance = try wallet.getBalanceAsync();
    try std.testing.expectEqual(@as(u64, 0), balance);

    // Test transaction creation
    const tx = try wallet.createTransactionAsync("alice", "bob", 100);
    try std.testing.expectEqual(@as(u64, 100), tx.amount);
    try std.testing.expectEqualStrings("alice", tx.from);
    try std.testing.expectEqualStrings("bob", tx.to);

    // Test transaction processing
    const result = try wallet.processTransactionAsync(tx);
    try std.testing.expect(result);
}

test "async audit logging" {
    const allocator = std.testing.allocator;

    var auditor = AsyncAuditor.init(allocator);
    defer auditor.deinit();

    // Test event logging
    try auditor.logEventAsync("TRANSACTION_CREATED", "tx_id: 12345");
    try auditor.logEventAsync("BALANCE_UPDATED", "new_balance: 1000");

    // Test report generation
    const report = try auditor.generateReportAsync();
    defer allocator.free(report);

    try std.testing.expect(std.mem.indexOf(u8, report, "TRANSACTION_CREATED") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "BALANCE_UPDATED") != null);
}
