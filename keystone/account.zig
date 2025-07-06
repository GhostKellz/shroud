const std = @import("std");
const tx = @import("tx.zig");

pub const AccountType = enum {
    asset,
    liability,
    equity,
    revenue,
    expense,
};

pub const Account = struct {
    name: []const u8,
    account_type: AccountType,
    balance: i64,
    currency: []const u8,
    created_at: i64,

    pub fn init(allocator: std.mem.Allocator, name: []const u8, account_type: AccountType, currency: []const u8) !Account {
        return Account{
            .name = try allocator.dupe(u8, name),
            .account_type = account_type,
            .balance = 0,
            .currency = try allocator.dupe(u8, currency),
            .created_at = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *Account, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.currency);
    }

    pub fn credit(self: *Account, amount: i64) void {
        switch (self.account_type) {
            .liability, .equity, .revenue => self.balance += amount,
            .asset, .expense => self.balance -= amount,
        }
    }

    pub fn debit(self: *Account, amount: i64) void {
        switch (self.account_type) {
            .asset, .expense => self.balance += amount,
            .liability, .equity, .revenue => self.balance -= amount,
        }
    }
};

pub const Ledger = struct {
    accounts: std.HashMap([]const u8, Account, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Ledger {
        return Ledger{
            .accounts = std.HashMap([]const u8, Account, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Ledger) void {
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            var account = entry.value_ptr;
            account.deinit(self.allocator);
        }
        self.accounts.deinit();
    }

    pub fn createAccount(self: *Ledger, name: []const u8, account_type: AccountType, currency: []const u8) !void {
        if (self.accounts.contains(name)) {
            return error.AccountExists;
        }

        const account = try Account.init(self.allocator, name, account_type, currency);
        const owned_name = try self.allocator.dupe(u8, name);
        try self.accounts.put(owned_name, account);
    }

    pub fn getAccount(self: *Ledger, name: []const u8) ?*Account {
        return self.accounts.getPtr(name);
    }

    pub fn getBalance(self: *Ledger, account_name: []const u8) ?i64 {
        if (self.getAccount(account_name)) |account| {
            return account.balance;
        }
        return null;
    }

    pub fn processTransaction(self: *Ledger, transaction: tx.Transaction) !void {
        var from_account = self.getAccount(transaction.from_account) orelse return error.FromAccountNotFound;
        var to_account = self.getAccount(transaction.to_account) orelse return error.ToAccountNotFound;

        if (!std.mem.eql(u8, from_account.currency, transaction.currency) or
            !std.mem.eql(u8, to_account.currency, transaction.currency)) {
            return error.CurrencyMismatch;
        }

        from_account.credit(transaction.amount);
        to_account.debit(transaction.amount);
    }

    pub fn verifyDoubleEntry(self: *Ledger) bool {
        var total_assets: i64 = 0;
        var total_liabilities: i64 = 0;
        var total_equity: i64 = 0;
        var total_revenue: i64 = 0;
        var total_expenses: i64 = 0;

        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            const account = entry.value_ptr;
            switch (account.account_type) {
                .asset => total_assets += account.balance,
                .liability => total_liabilities += account.balance,
                .equity => total_equity += account.balance,
                .revenue => total_revenue += account.balance,
                .expense => total_expenses += account.balance,
            }
        }

        return total_assets == total_liabilities + total_equity + total_revenue - total_expenses;
    }

    pub fn getTrialBalance(self: *Ledger, allocator: std.mem.Allocator) !std.ArrayList(TrialBalanceEntry) {
        var trial_balance = std.ArrayList(TrialBalanceEntry).init(allocator);
        
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            const account = entry.value_ptr;
            try trial_balance.append(TrialBalanceEntry{
                .account_name = try allocator.dupe(u8, account.name),
                .account_type = account.account_type,
                .balance = account.balance,
                .currency = try allocator.dupe(u8, account.currency),
            });
        }

        return trial_balance;
    }
};

pub const TrialBalanceEntry = struct {
    account_name: []const u8,
    account_type: AccountType,
    balance: i64,
    currency: []const u8,

    pub fn deinit(self: *TrialBalanceEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.account_name);
        allocator.free(self.currency);
    }
};

test "account creation and balance operations" {
    const allocator = std.testing.allocator;
    
    var ledger = Ledger.init(allocator);
    defer ledger.deinit();

    try ledger.createAccount("cash", .asset, "USD");
    try ledger.createAccount("accounts_payable", .liability, "USD");

    const cash_account = ledger.getAccount("cash").?;
    cash_account.debit(10000);

    const ap_account = ledger.getAccount("accounts_payable").?;
    ap_account.credit(10000);

    try std.testing.expectEqual(@as(i64, 10000), cash_account.balance);
    try std.testing.expectEqual(@as(i64, 10000), ap_account.balance);
    try std.testing.expect(ledger.verifyDoubleEntry());
}

test "transaction processing" {
    const allocator = std.testing.allocator;
    
    var ledger = Ledger.init(allocator);
    defer ledger.deinit();

    try ledger.createAccount("alice", .asset, "USD");
    try ledger.createAccount("bob", .asset, "USD");

    const alice = ledger.getAccount("alice").?;
    alice.debit(100000);

    var transaction = try tx.Transaction.init(allocator, 50000, "USD", "alice", "bob", "Payment to Bob");
    defer transaction.deinit(allocator);

    try ledger.processTransaction(transaction);

    try std.testing.expectEqual(@as(i64, 50000), alice.balance);
    try std.testing.expectEqual(@as(i64, 50000), ledger.getAccount("bob").?.balance);
}