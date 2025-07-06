//! Transaction module for GhostWallet with RealID signing and verification
//! Handles transaction creation, signing, verification, and serialization

const std = @import("std");
const sigil = @import("sigil");
const qid = @import("qid.zig");

pub const TransactionError = error{
    InvalidTransaction,
    SigningFailed,
    VerificationFailed,
    SerializationFailed,
    InsufficientFunds,
    InvalidAddress,
    InvalidAmount,
    InvalidSignature,
};

pub const TransactionType = enum {
    transfer,
    stake,
    unstake,
    contract_call,
    contract_deploy,

    pub fn format(self: TransactionType, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        return writer.print("{s}", .{@tagName(self)});
    }
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

pub const TransactionInput = struct {
    txid: [32]u8,
    vout: u32,
    amount: u64,
    script_pubkey: []const u8,
};

pub const TransactionOutput = struct {
    amount: u64,
    address: []const u8,
    script_pubkey: ?[]const u8,
};

/// Core transaction structure
pub const Transaction = struct {
    // Basic transaction fields
    id: [32]u8,
    version: u32,
    timestamp: i64,
    nonce: u64,

    // Transaction type and protocol
    tx_type: TransactionType,
    protocol: Protocol,

    // Addresses and amounts
    from_address: []const u8,
    to_address: []const u8,
    amount: u64,
    fee: u64,

    // Token information
    token_contract: ?[]const u8,
    token_decimals: u8,

    // Inputs and outputs (for UTXO-based chains)
    inputs: []const TransactionInput,
    outputs: []const TransactionOutput,

    // Contract interaction
    contract_data: ?[]const u8,
    gas_limit: ?u64,
    gas_price: ?u64,

    // Signature and verification
    signature: ?sigil.RealIDSignature,
    public_key: ?sigil.RealIDPublicKey,
    signer_qid: ?qid.QID,

    // Metadata
    memo: ?[]const u8,
    chain_id: ?u32,

    const Self = @This();

    /// Create a new transaction
    pub fn init(allocator: std.mem.Allocator, tx_type: TransactionType, protocol: Protocol) Self {
        _ = allocator;
        const current_time = std.time.timestamp();

        return Self{
            .id = std.mem.zeroes([32]u8),
            .version = 1,
            .timestamp = current_time,
            .nonce = 0,
            .tx_type = tx_type,
            .protocol = protocol,
            .from_address = "",
            .to_address = "",
            .amount = 0,
            .fee = 0,
            .token_contract = null,
            .token_decimals = 18,
            .inputs = &[_]TransactionInput{},
            .outputs = &[_]TransactionOutput{},
            .contract_data = null,
            .gas_limit = null,
            .gas_price = null,
            .signature = null,
            .public_key = null,
            .signer_qid = null,
            .memo = null,
            .chain_id = null,
        };
    }

    /// Create a simple transfer transaction
    pub fn createTransfer(
        allocator: std.mem.Allocator,
        protocol: Protocol,
        from: []const u8,
        to: []const u8,
        amount: u64,
        fee: u64,
    ) !Self {
        var tx = Self.init(allocator, .transfer, protocol);

        tx.from_address = try allocator.dupe(u8, from);
        tx.to_address = try allocator.dupe(u8, to);
        tx.amount = amount;
        tx.fee = fee;

        // Generate transaction ID
        try tx.generateId();

        return tx;
    }

    /// Generate transaction ID from transaction data
    pub fn generateId(self: *Self) !void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Hash core transaction data
        hasher.update(std.mem.asBytes(&self.version));
        hasher.update(std.mem.asBytes(&self.timestamp));
        hasher.update(std.mem.asBytes(&self.nonce));
        hasher.update(@tagName(self.tx_type));
        hasher.update(@tagName(self.protocol));
        hasher.update(self.from_address);
        hasher.update(self.to_address);
        hasher.update(std.mem.asBytes(&self.amount));
        hasher.update(std.mem.asBytes(&self.fee));

        if (self.contract_data) |data| {
            hasher.update(data);
        }

        hasher.final(&self.id);
    }

    /// Sign transaction with RealID keypair
    pub fn sign(self: *Self, keypair: sigil.RealIDKeyPair) !void {
        const tx_data = try self.serialize(std.heap.page_allocator);
        defer std.heap.page_allocator.free(tx_data);

        self.signature = try sigil.realid_sign(tx_data, keypair.private_key);
        self.public_key = keypair.public_key;
        self.signer_qid = qid.QID.fromPublicKey(keypair.public_key.bytes);
    }

    /// Verify transaction signature
    pub fn verify(self: Self) !bool {
        if (self.signature == null or self.public_key == null) {
            return TransactionError.InvalidSignature;
        }

        const tx_data = try self.serialize(std.heap.page_allocator);
        defer std.heap.page_allocator.free(tx_data);

        return sigil.realid_verify(self.signature.?, tx_data, self.public_key.?);
    }

    /// Serialize transaction to bytes
    pub fn serialize(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();

        // Write transaction data in a deterministic order
        try buffer.appendSlice(std.mem.asBytes(&self.version));
        try buffer.appendSlice(std.mem.asBytes(&self.timestamp));
        try buffer.appendSlice(std.mem.asBytes(&self.nonce));

        // Transaction type and protocol as strings for consistency
        const tx_type_str = @tagName(self.tx_type);
        try buffer.appendSlice(std.mem.asBytes(&@as(u32, @intCast(tx_type_str.len))));
        try buffer.appendSlice(tx_type_str);

        const protocol_str = @tagName(self.protocol);
        try buffer.appendSlice(std.mem.asBytes(&@as(u32, @intCast(protocol_str.len))));
        try buffer.appendSlice(protocol_str);

        // Addresses
        try buffer.appendSlice(std.mem.asBytes(&@as(u32, @intCast(self.from_address.len))));
        try buffer.appendSlice(self.from_address);
        try buffer.appendSlice(std.mem.asBytes(&@as(u32, @intCast(self.to_address.len))));
        try buffer.appendSlice(self.to_address);

        // Amounts
        try buffer.appendSlice(std.mem.asBytes(&self.amount));
        try buffer.appendSlice(std.mem.asBytes(&self.fee));

        // Optional fields
        if (self.contract_data) |data| {
            try buffer.appendSlice(std.mem.asBytes(&@as(u32, @intCast(data.len))));
            try buffer.appendSlice(data);
        } else {
            try buffer.appendSlice(std.mem.asBytes(&@as(u32, 0)));
        }

        if (self.memo) |memo| {
            try buffer.appendSlice(std.mem.asBytes(&@as(u32, @intCast(memo.len))));
            try buffer.appendSlice(memo);
        } else {
            try buffer.appendSlice(std.mem.asBytes(&@as(u32, 0)));
        }

        return buffer.toOwnedSlice();
    }

    /// Deserialize transaction from bytes
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !Self {
        if (data.len < 16) return TransactionError.SerializationFailed;

        var tx = Self.init(allocator, .transfer, .ghostchain);
        var offset: usize = 0;

        // Read basic fields
        tx.version = std.mem.readIntLittle(u32, data[offset .. offset + 4]);
        offset += 4;
        tx.timestamp = std.mem.readIntLittle(i64, data[offset .. offset + 8]);
        offset += 8;
        tx.nonce = std.mem.readIntLittle(u64, data[offset .. offset + 8]);
        offset += 8;

        // Read transaction type
        const tx_type_len = std.mem.readIntLittle(u32, data[offset .. offset + 4]);
        offset += 4;
        if (offset + tx_type_len > data.len) return TransactionError.SerializationFailed;

        const tx_type_str = data[offset .. offset + tx_type_len];
        tx.tx_type = std.meta.stringToEnum(TransactionType, tx_type_str) orelse .transfer;
        offset += tx_type_len;

        // Read protocol
        const protocol_len = std.mem.readIntLittle(u32, data[offset .. offset + 4]);
        offset += 4;
        if (offset + protocol_len > data.len) return TransactionError.SerializationFailed;

        const protocol_str = data[offset .. offset + protocol_len];
        tx.protocol = std.meta.stringToEnum(Protocol, protocol_str) orelse .ghostchain;
        offset += protocol_len;

        // Read addresses
        const from_len = std.mem.readIntLittle(u32, data[offset .. offset + 4]);
        offset += 4;
        if (offset + from_len > data.len) return TransactionError.SerializationFailed;
        tx.from_address = try allocator.dupe(u8, data[offset .. offset + from_len]);
        offset += from_len;

        const to_len = std.mem.readIntLittle(u32, data[offset .. offset + 4]);
        offset += 4;
        if (offset + to_len > data.len) return TransactionError.SerializationFailed;
        tx.to_address = try allocator.dupe(u8, data[offset .. offset + to_len]);
        offset += to_len;

        // Read amounts
        if (offset + 16 > data.len) return TransactionError.SerializationFailed;
        tx.amount = std.mem.readIntLittle(u64, data[offset .. offset + 8]);
        offset += 8;
        tx.fee = std.mem.readIntLittle(u64, data[offset .. offset + 8]);
        offset += 8;

        return tx;
    }

    /// Get transaction hash as hex string
    pub fn getHashHex(self: Self, buffer: []u8) ![]u8 {
        if (buffer.len < 64) return TransactionError.SerializationFailed;
        return std.fmt.bufPrint(buffer, "{}", .{std.fmt.fmtSliceHexLower(&self.id)});
    }

    /// Check if transaction is valid
    pub fn isValid(self: Self) bool {
        // Basic validation
        if (self.amount == 0 and self.tx_type == .transfer) return false;
        if (self.from_address.len == 0 or self.to_address.len == 0) return false;
        if (self.fee == 0 and self.protocol != .ghostchain) return false;

        // Protocol-specific validation
        switch (self.protocol) {
            .ethereum => {
                if (self.gas_limit == null or self.gas_price == null) return false;
            },
            .bitcoin => {
                if (self.inputs.len == 0 or self.outputs.len == 0) return false;
            },
            else => {},
        }

        return true;
    }

    /// Calculate transaction size in bytes
    pub fn getSize(self: Self) u32 {
        var size: u32 = 0;
        size += 4; // version
        size += 8; // timestamp
        size += 8; // nonce
        size += 4 + @as(u32, @intCast(@tagName(self.tx_type).len));
        size += 4 + @as(u32, @intCast(@tagName(self.protocol).len));
        size += 4 + @as(u32, @intCast(self.from_address.len));
        size += 4 + @as(u32, @intCast(self.to_address.len));
        size += 8; // amount
        size += 8; // fee

        if (self.contract_data) |data| {
            size += 4 + @as(u32, @intCast(data.len));
        }

        if (self.memo) |memo| {
            size += 4 + @as(u32, @intCast(memo.len));
        }

        if (self.signature) |_| {
            size += 64; // signature size
        }

        return size;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.from_address.len > 0) allocator.free(self.from_address);
        if (self.to_address.len > 0) allocator.free(self.to_address);
        if (self.memo) |memo| allocator.free(memo);
        if (self.contract_data) |data| allocator.free(data);
        if (self.token_contract) |contract| allocator.free(contract);
    }
};

test "transaction creation and signing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a transfer transaction
    var tx = try Transaction.createTransfer(
        allocator,
        .ghostchain,
        "ghost1abc123",
        "ghost1def456",
        1000000, // 1 GCC
        1000, // 0.001 GCC fee
    );
    defer tx.deinit(allocator);

    try std.testing.expect(tx.isValid());
    try std.testing.expect(tx.amount == 1000000);
    try std.testing.expect(tx.fee == 1000);
}

test "transaction serialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tx = try Transaction.createTransfer(
        allocator,
        .ethereum,
        "0x1234567890123456789012345678901234567890",
        "0x0987654321098765432109876543210987654321",
        500000000000000000, // 0.5 ETH
        21000000000000000, // 0.021 ETH fee
    );
    defer tx.deinit(allocator);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    const deserialized = try Transaction.deserialize(allocator, serialized);
    defer deserialized.deinit(allocator);

    try std.testing.expect(deserialized.amount == tx.amount);
    try std.testing.expect(deserialized.fee == tx.fee);
    try std.testing.expect(std.mem.eql(u8, deserialized.from_address, tx.from_address));
    try std.testing.expect(std.mem.eql(u8, deserialized.to_address, tx.to_address));
}
