const std = @import("std");
const tx = @import("tx.zig");
const account = @import("account.zig");
const journal = @import("journal.zig");
const audit = @import("audit.zig");

pub const CliError = error{
    InvalidCommand,
    InvalidArguments,
    FileError,
    LedgerError,
};

pub const Cli = struct {
    allocator: std.mem.Allocator,
    ledger: account.Ledger,
    journal_ref: journal.Journal,
    data_dir: []const u8,

    pub fn init(allocator: std.mem.Allocator, data_dir: []const u8) !Cli {
        const ledger_path = try std.fmt.allocPrint(allocator, "{s}/ledger.json", .{data_dir});
        defer allocator.free(ledger_path);
        
        const journal_path = try std.fmt.allocPrint(allocator, "{s}/journal.log", .{data_dir});
        defer allocator.free(journal_path);

        const ledger_instance = account.Ledger.init(allocator);
        var journal_instance = journal.Journal.init(allocator, try allocator.dupe(u8, journal_path));

        std.fs.cwd().makeDir(data_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        journal_instance.loadFromFile(journal_path) catch {};

        return Cli{
            .allocator = allocator,
            .ledger = ledger_instance,
            .journal_ref = journal_instance,
            .data_dir = try allocator.dupe(u8, data_dir),
        };
    }

    pub fn deinit(self: *Cli) void {
        self.ledger.deinit();
        self.journal_ref.deinit();
        self.allocator.free(self.data_dir);
    }

    pub fn run(self: *Cli, args: [][:0]u8) !void {
        if (args.len < 2) {
            try self.printUsage();
            return;
        }

        const command = args[1];
        const cmd_args = if (args.len > 2) args[2..] else &[_][:0]u8{};

        if (std.mem.eql(u8, command, "account")) {
            try self.handleAccountCommand(cmd_args);
        } else if (std.mem.eql(u8, command, "tx")) {
            try self.handleTransactionCommand(cmd_args);
        } else if (std.mem.eql(u8, command, "balance")) {
            try self.handleBalanceCommand(cmd_args);
        } else if (std.mem.eql(u8, command, "audit")) {
            try self.handleAuditCommand(cmd_args);
        } else if (std.mem.eql(u8, command, "journal")) {
            try self.handleJournalCommand(cmd_args);
        } else {
            std.debug.print("Unknown command: {s}\n", .{command});
            try self.printUsage();
            return CliError.InvalidCommand;
        }
    }

    fn printUsage(self: *Cli) !void {
        _ = self;
        const usage =
            \\Zledger - Lightweight Ledger Engine
            \\
            \\Usage: zledger <command> [options]
            \\
            \\Commands:
            \\  account create <name> <type> <currency>  Create a new account
            \\  account list                             List all accounts
            \\  tx add --from <account> --to <account> --amount <amount> --currency <currency> [--memo <memo>]
            \\  balance <account>                        Show account balance
            \\  audit verify                             Run integrity audit
            \\  audit report                             Generate audit report
            \\  journal list                             List all transactions
            \\  journal export <file>                    Export journal to file
            \\
            \\Account Types: asset, liability, equity, revenue, expense
            \\
        ;
        std.debug.print("{s}", .{usage});
    }

    fn handleAccountCommand(self: *Cli, args: []const [:0]u8) !void {
        if (args.len == 0) {
            std.debug.print("account command requires a subcommand\n", .{});
            return CliError.InvalidArguments;
        }

        const subcommand = args[0];
        
        if (std.mem.eql(u8, subcommand, "create")) {
            if (args.len != 4) {
                std.debug.print("Usage: account create <name> <type> <currency>\n", .{});
                return CliError.InvalidArguments;
            }
            
            const name = args[1];
            const type_str = args[2];
            const currency = args[3];
            
            const account_type = std.meta.stringToEnum(account.AccountType, type_str) orelse {
                std.debug.print("Invalid account type: {s}\n", .{type_str});
                std.debug.print("Valid types: asset, liability, equity, revenue, expense\n", .{});
                return CliError.InvalidArguments;
            };
            
            self.ledger.createAccount(name, account_type, currency) catch |err| switch (err) {
                error.AccountExists => {
                    std.debug.print("Account '{s}' already exists\n", .{name});
                    return;
                },
                else => return err,
            };
            
            std.debug.print("Created {s} account '{s}' with currency {s}\n", .{ type_str, name, currency });
            
        } else if (std.mem.eql(u8, subcommand, "list")) {
            var iterator = self.ledger.accounts.iterator();
            std.debug.print("Accounts:\n", .{});
            while (iterator.next()) |entry| {
                const acc = entry.value_ptr;
                std.debug.print("  {s}: {s} ({s}) - Balance: {d}\n", .{ 
                    acc.name, 
                    @tagName(acc.account_type), 
                    acc.currency, 
                    acc.balance 
                });
            }
        } else {
            std.debug.print("Unknown account subcommand: {s}\n", .{subcommand});
            return CliError.InvalidCommand;
        }
    }

    fn handleTransactionCommand(self: *Cli, args: []const [:0]u8) !void {
        if (args.len == 0) {
            std.debug.print("tx command requires a subcommand\n", .{});
            return CliError.InvalidArguments;
        }

        const subcommand = args[0];
        
        if (std.mem.eql(u8, subcommand, "add")) {
            var from_account: ?[]const u8 = null;
            var to_account: ?[]const u8 = null;
            var amount: ?i64 = null;
            var currency: ?[]const u8 = null;
            var memo: ?[]const u8 = null;
            
            var i: usize = 1;
            while (i < args.len) : (i += 2) {
                if (i + 1 >= args.len) break;
                
                const flag = args[i];
                const value = args[i + 1];
                
                if (std.mem.eql(u8, flag, "--from")) {
                    from_account = value;
                } else if (std.mem.eql(u8, flag, "--to")) {
                    to_account = value;
                } else if (std.mem.eql(u8, flag, "--amount")) {
                    amount = std.fmt.parseInt(i64, value, 10) catch {
                        std.debug.print("Invalid amount: {s}\n", .{value});
                        return CliError.InvalidArguments;
                    };
                } else if (std.mem.eql(u8, flag, "--currency")) {
                    currency = value;
                } else if (std.mem.eql(u8, flag, "--memo")) {
                    memo = value;
                }
            }
            
            if (from_account == null or to_account == null or amount == null or currency == null) {
                std.debug.print("Usage: tx add --from <account> --to <account> --amount <amount> --currency <currency> [--memo <memo>]\n", .{});
                return CliError.InvalidArguments;
            }
            
            var transaction = try tx.Transaction.init(
                self.allocator,
                amount.?,
                currency.?,
                from_account.?,
                to_account.?,
                memo
            );
            
            self.ledger.processTransaction(transaction) catch |err| switch (err) {
                error.FromAccountNotFound => {
                    std.debug.print("From account '{s}' not found\n", .{from_account.?});
                    transaction.deinit(self.allocator);
                    return;
                },
                error.ToAccountNotFound => {
                    std.debug.print("To account '{s}' not found\n", .{to_account.?});
                    transaction.deinit(self.allocator);
                    return;
                },
                error.CurrencyMismatch => {
                    std.debug.print("Currency mismatch\n", .{});
                    transaction.deinit(self.allocator);
                    return;
                },
            };
            
            try self.journal_ref.append(transaction);
            
            std.debug.print("Transaction added: {s} -> {s}: {d} {s}\n", .{
                from_account.?, to_account.?, amount.?, currency.?
            });
            
        } else {
            std.debug.print("Unknown tx subcommand: {s}\n", .{subcommand});
            return CliError.InvalidCommand;
        }
    }

    fn handleBalanceCommand(self: *Cli, args: []const [:0]u8) !void {
        if (args.len != 1) {
            std.debug.print("Usage: balance <account>\n", .{});
            return CliError.InvalidArguments;
        }
        
        const account_name = args[0];
        if (self.ledger.getBalance(account_name)) |balance| {
            const acc = self.ledger.getAccount(account_name).?;
            std.debug.print("Account '{s}': {d} {s}\n", .{ account_name, balance, acc.currency });
        } else {
            std.debug.print("Account '{s}' not found\n", .{account_name});
        }
    }

    fn handleAuditCommand(self: *Cli, args: []const [:0]u8) !void {
        if (args.len == 0) {
            std.debug.print("audit command requires a subcommand\n", .{});
            return CliError.InvalidArguments;
        }

        const subcommand = args[0];
        
        if (std.mem.eql(u8, subcommand, "verify")) {
            var auditor = audit.Auditor.init(self.allocator);
            var report = try auditor.auditLedger(&self.ledger, &self.journal_ref);
            defer report.deinit(self.allocator);
            
            std.debug.print("Audit Results:\n", .{});
            std.debug.print("  Total Transactions: {d}\n", .{report.total_transactions});
            std.debug.print("  Integrity Valid: {}\n", .{report.integrity_valid});
            std.debug.print("  Double Entry Valid: {}\n", .{report.double_entry_valid});
            std.debug.print("  Balance Discrepancies: {d}\n", .{report.balance_discrepancies.items.len});
            std.debug.print("  Duplicate Transactions: {d}\n", .{report.duplicate_transactions.items.len});
            std.debug.print("  Orphaned Transactions: {d}\n", .{report.orphaned_transactions.items.len});
            std.debug.print("  Overall Valid: {}\n", .{report.isValid()});
            
        } else if (std.mem.eql(u8, subcommand, "report")) {
            var auditor = audit.Auditor.init(self.allocator);
            var report = try auditor.auditLedger(&self.ledger, &self.journal_ref);
            defer report.deinit(self.allocator);
            
            const json = try report.toJson(self.allocator);
            defer self.allocator.free(json);
            
            std.debug.print("{s}\n", .{json});
            
        } else {
            std.debug.print("Unknown audit subcommand: {s}\n", .{subcommand});
            return CliError.InvalidCommand;
        }
    }

    fn handleJournalCommand(self: *Cli, args: []const [:0]u8) !void {
        if (args.len == 0) {
            std.debug.print("journal command requires a subcommand\n", .{});
            return CliError.InvalidArguments;
        }

        const subcommand = args[0];
        
        if (std.mem.eql(u8, subcommand, "list")) {
            std.debug.print("Journal Entries ({d} total):\n", .{self.journal_ref.entries.items.len});
            for (self.journal_ref.entries.items, 0..) |entry, i| {
                const t = entry.transaction;
                std.debug.print("  {d}: {s} -> {s}: {d} {s}", .{ i, t.from_account, t.to_account, t.amount, t.currency });
                if (t.memo) |memo| {
                    std.debug.print(" ({s})", .{memo});
                }
                std.debug.print("\n", .{});
            }
            
        } else if (std.mem.eql(u8, subcommand, "export")) {
            if (args.len != 2) {
                std.debug.print("Usage: journal export <file>\n", .{});
                return CliError.InvalidArguments;
            }
            
            const filename = args[1];
            try self.journal_ref.saveToFile(filename);
            std.debug.print("Journal exported to {s}\n", .{filename});
            
        } else {
            std.debug.print("Unknown journal subcommand: {s}\n", .{subcommand});
            return CliError.InvalidCommand;
        }
    }
};

test "cli initialization" {
    const allocator = std.testing.allocator;
    
    var cli = try Cli.init(allocator, "test_data");
    defer cli.deinit();
    
    std.fs.cwd().deleteTree("test_data") catch {};
}