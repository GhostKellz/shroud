const std = @import("std");
const crypto = std.crypto;
const zcrypto = @import("zcrypto");

pub const Transaction = struct {
    id: []const u8,
    timestamp: i64,
    amount: i64,
    currency: []const u8,
    from_account: []const u8,
    to_account: []const u8,
    memo: ?[]const u8,
    signature: ?[64]u8,
    integrity_hmac: ?[32]u8,
    nonce: [12]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        amount: i64,
        currency: []const u8,
        from_account: []const u8,
        to_account: []const u8,
        memo: ?[]const u8,
    ) !Transaction {
        const timestamp = std.time.timestamp();
        const id = try generateTxId(allocator, timestamp, from_account, to_account, amount);
        
        var nonce: [12]u8 = undefined;
        zcrypto.rand.fillBytes(&nonce);
        
        return Transaction{
            .id = id,
            .timestamp = timestamp,
            .amount = amount,
            .currency = try allocator.dupe(u8, currency),
            .from_account = try allocator.dupe(u8, from_account),
            .to_account = try allocator.dupe(u8, to_account),
            .memo = if (memo) |m| try allocator.dupe(u8, m) else null,
            .signature = null,
            .integrity_hmac = null,
            .nonce = nonce,
        };
    }

    pub fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.currency);
        allocator.free(self.from_account);
        allocator.free(self.to_account);
        if (self.memo) |memo| {
            allocator.free(memo);
        }
    }

    pub fn toJson(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
        var json_obj = std.json.ObjectMap.init(allocator);
        defer json_obj.deinit();

        try json_obj.put("id", std.json.Value{ .string = self.id });
        try json_obj.put("timestamp", std.json.Value{ .integer = self.timestamp });
        try json_obj.put("amount", std.json.Value{ .integer = self.amount });
        try json_obj.put("currency", std.json.Value{ .string = self.currency });
        try json_obj.put("from_account", std.json.Value{ .string = self.from_account });
        try json_obj.put("to_account", std.json.Value{ .string = self.to_account });
        
        if (self.memo) |memo| {
            try json_obj.put("memo", std.json.Value{ .string = memo });
        } else {
            try json_obj.put("memo", std.json.Value.null);
        }

        // Add cryptographic fields
        const nonce_hex = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&self.nonce)});
        defer allocator.free(nonce_hex);
        try json_obj.put("nonce", std.json.Value{ .string = nonce_hex });

        if (self.signature) |sig| {
            const sig_hex = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&sig)});
            defer allocator.free(sig_hex);
            try json_obj.put("signature", std.json.Value{ .string = sig_hex });
        } else {
            try json_obj.put("signature", std.json.Value.null);
        }

        if (self.integrity_hmac) |hmac| {
            const hmac_hex = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&hmac)});
            defer allocator.free(hmac_hex);
            try json_obj.put("integrity_hmac", std.json.Value{ .string = hmac_hex });
        } else {
            try json_obj.put("integrity_hmac", std.json.Value.null);
        }

        const json_value = std.json.Value{ .object = json_obj };
        return try std.json.stringifyAlloc(allocator, json_value, .{});
    }

    pub fn fromJson(allocator: std.mem.Allocator, json_str: []const u8) !Transaction {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        const obj = parsed.value.object;
        
        const id = try allocator.dupe(u8, obj.get("id").?.string);
        const timestamp = obj.get("timestamp").?.integer;
        const amount = obj.get("amount").?.integer;
        const currency = try allocator.dupe(u8, obj.get("currency").?.string);
        const from_account = try allocator.dupe(u8, obj.get("from_account").?.string);
        const to_account = try allocator.dupe(u8, obj.get("to_account").?.string);
        
        var memo: ?[]u8 = null;
        if (obj.get("memo")) |memo_value| {
            if (memo_value != .null) {
                memo = try allocator.dupe(u8, memo_value.string);
            }
        }

        return Transaction{
            .id = id,
            .timestamp = timestamp,
            .amount = amount,
            .currency = currency,
            .from_account = from_account,
            .to_account = to_account,
            .memo = memo,
        };
    }

    pub fn getHash(self: Transaction, allocator: std.mem.Allocator) ![32]u8 {
        const tx_data = try self.toJson(allocator);
        defer allocator.free(tx_data);
        
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(tx_data, &hash, .{});
        return hash;
    }

    pub fn signTransaction(self: *Transaction, allocator: std.mem.Allocator, _: [32]u8) !void {
        const tx_data = try self.getTransactionDataForSigning(allocator);
        defer allocator.free(tx_data);
        
        const keypair = zcrypto.asym.ed25519.generate();
        const signature = keypair.sign(tx_data);
        self.signature = signature;
    }

    pub fn verifySignature(self: Transaction, allocator: std.mem.Allocator, public_key: [32]u8) !bool {
        if (self.signature == null) return false;
        
        const tx_data = try self.getTransactionDataForSigning(allocator);
        defer allocator.free(tx_data);
        
        const keypair = zcrypto.asym.ed25519.KeyPair{ .public_key = public_key, .private_key = undefined };
        return keypair.verify(tx_data, self.signature.?);
    }

    pub fn generateIntegrityHMAC(self: *Transaction, allocator: std.mem.Allocator, hmac_key: [32]u8) !void {
        const tx_data = try self.getTransactionDataForSigning(allocator);
        defer allocator.free(tx_data);
        
        self.integrity_hmac = zcrypto.auth.hmac.sha256(tx_data, &hmac_key);
    }

    pub fn verifyIntegrityHMAC(self: Transaction, allocator: std.mem.Allocator, hmac_key: [32]u8) !bool {
        if (self.integrity_hmac == null) return false;
        
        const tx_data = try self.getTransactionDataForSigning(allocator);
        defer allocator.free(tx_data);
        
        const computed_hmac = zcrypto.auth.hmac.sha256(tx_data, &hmac_key);
        return zcrypto.util.constantTimeCompare(&self.integrity_hmac.?, &computed_hmac);
    }

    fn getTransactionDataForSigning(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{d}|{d}|{s}|{s}|{s}|{s}|{x}", 
            .{ self.timestamp, self.amount, self.currency, self.from_account, 
               self.to_account, self.memo orelse "", std.fmt.fmtSliceHexLower(&self.nonce) });
    }
};

fn generateTxId(allocator: std.mem.Allocator, timestamp: i64, from: []const u8, to: []const u8, amount: i64) ![]u8 {
    const id_data = try std.fmt.allocPrint(allocator, "{d}-{s}-{s}-{d}", .{ timestamp, from, to, amount });
    defer allocator.free(id_data);
    
    var hash: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(id_data, &hash, .{});
    
    return try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(hash[0..8])});
}

test "transaction creation and serialization" {
    const allocator = std.testing.allocator;
    
    var tx = try Transaction.init(
        allocator,
        100000,
        "USD",
        "alice",
        "bob",
        "Test payment"
    );
    defer tx.deinit(allocator);

    const json = try tx.toJson(allocator);
    defer allocator.free(json);

    var tx2 = try Transaction.fromJson(allocator, json);
    defer tx2.deinit(allocator);

    try std.testing.expectEqualStrings(tx.currency, tx2.currency);
    try std.testing.expectEqual(tx.amount, tx2.amount);
    try std.testing.expectEqualStrings(tx.from_account, tx2.from_account);
    try std.testing.expectEqualStrings(tx.to_account, tx2.to_account);
}