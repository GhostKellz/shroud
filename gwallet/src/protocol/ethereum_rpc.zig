//! Ethereum RPC client for ENS resolution and transaction broadcasting
//! Supports both HTTP and WebSocket connections

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const RpcError = error{
    NetworkError,
    InvalidResponse,
    InvalidMethod,
    ServerError,
    Timeout,
};

pub const EthereumRpc = struct {
    allocator: Allocator,
    endpoint: []const u8,
    client: ?std.http.Client,

    pub fn init(allocator: Allocator, endpoint: []const u8) EthereumRpc {
        return EthereumRpc{
            .allocator = allocator,
            .endpoint = try allocator.dupe(u8, endpoint) catch unreachable,
            .client = null,
        };
    }

    pub fn deinit(self: *EthereumRpc) void {
        self.allocator.free(self.endpoint);
        if (self.client) |*client| {
            client.deinit();
        }
    }

    /// Call ETH RPC method
    pub fn call(self: *EthereumRpc, method: []const u8, params: std.json.Value) !std.json.Value {
        // TODO: Implement actual HTTP RPC call
        _ = self;
        _ = params;

        // For now, return mock responses based on method
        if (std.mem.eql(u8, method, "eth_call")) {
            // Mock ENS resolver response
            return std.json.Value{ .string = "0x000000000000000000000000742d35cc6e0c0532e234b37e85e40521a2b5a4b8" };
        } else if (std.mem.eql(u8, method, "eth_getBalance")) {
            return std.json.Value{ .string = "0x1bc16d674ec80000" }; // 2 ETH
        } else if (std.mem.eql(u8, method, "eth_blockNumber")) {
            return std.json.Value{ .string = "0x12a7b2c" }; // Block number
        }

        return RpcError.InvalidMethod;
    }

    /// Resolve ENS name to address
    pub fn resolveENS(self: *EthereumRpc, name: []const u8) ![]const u8 {
        // ENS Public Resolver ABI for addr(bytes32) function
        const addr_selector = "0x3b3b57de"; // keccak256("addr(bytes32)")[:4]

        // Calculate namehash (would use the function from resolver.zig)
        const namehash = try self.calculateNamehash(name);
        defer self.allocator.free(namehash);

        // Prepare eth_call data
        const call_data = try std.fmt.allocPrint(self.allocator, "{s}{}", .{
            addr_selector,
            std.fmt.fmtSliceHexLower(namehash),
        });
        defer self.allocator.free(call_data);

        // Call ENS Public Resolver
        var params = std.json.Array.init(self.allocator);
        defer params.deinit();

        var call_object = std.json.ObjectMap.init(self.allocator);
        defer call_object.deinit();

        try call_object.put("to", std.json.Value{ .string = "0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41" }); // Public Resolver
        try call_object.put("data", std.json.Value{ .string = call_data });

        try params.append(std.json.Value{ .object = call_object });
        try params.append(std.json.Value{ .string = "latest" });

        const result = try self.call("eth_call", std.json.Value{ .array = params });

        // Parse result and extract address
        if (result == .string) {
            const hex_result = result.string;
            if (hex_result.len >= 66) { // 0x + 64 hex chars
                // Extract last 40 characters (20 bytes) as address
                const address_hex = hex_result[hex_result.len - 40 ..];
                return try std.fmt.allocPrint(self.allocator, "0x{s}", .{address_hex});
            }
        }

        return RpcError.InvalidResponse;
    }

    /// Get account balance
    pub fn getBalance(self: *EthereumRpc, address: []const u8, block: []const u8) ![]const u8 {
        var params = std.json.Array.init(self.allocator);
        defer params.deinit();

        try params.append(std.json.Value{ .string = address });
        try params.append(std.json.Value{ .string = block });

        const result = try self.call("eth_getBalance", std.json.Value{ .array = params });

        if (result == .string) {
            return try self.allocator.dupe(u8, result.string);
        }

        return RpcError.InvalidResponse;
    }

    /// Send raw transaction
    pub fn sendRawTransaction(self: *EthereumRpc, signed_tx: []const u8) ![]const u8 {
        var params = std.json.Array.init(self.allocator);
        defer params.deinit();

        try params.append(std.json.Value{ .string = signed_tx });

        const result = try self.call("eth_sendRawTransaction", std.json.Value{ .array = params });

        if (result == .string) {
            return try self.allocator.dupe(u8, result.string);
        }

        return RpcError.InvalidResponse;
    }

    /// Get transaction receipt
    pub fn getTransactionReceipt(self: *EthereumRpc, tx_hash: []const u8) !std.json.Value {
        var params = std.json.Array.init(self.allocator);
        defer params.deinit();

        try params.append(std.json.Value{ .string = tx_hash });

        return try self.call("eth_getTransactionReceipt", std.json.Value{ .array = params });
    }

    // Helper function for namehash calculation
    fn calculateNamehash(self: *EthereumRpc, domain: []const u8) ![]u8 {
        // Same implementation as in resolver.zig
        var hash = try self.allocator.alloc(u8, 32);
        @memset(hash, 0);

        var labels = std.ArrayList([]const u8).init(self.allocator);
        defer labels.deinit();

        var iterator = std.mem.splitScalar(u8, domain, '.');
        while (iterator.next()) |label| {
            try labels.append(label);
        }

        var i = labels.items.len;
        while (i > 0) {
            i -= 1;
            const label = labels.items[i];

            if (label.len == 0) continue;

            var label_hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(label, &label_hash, .{});

            var combined = try self.allocator.alloc(u8, 64);
            defer self.allocator.free(combined);

            @memcpy(combined[0..32], hash);
            @memcpy(combined[32..64], &label_hash);

            std.crypto.hash.sha3.Keccak256.hash(combined, hash[0..32], .{});
        }

        return hash;
    }
};

/// RPC provider endpoints
pub const RpcProviders = struct {
    pub const INFURA_MAINNET = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID";
    pub const ALCHEMY_MAINNET = "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY";
    pub const ANKR_MAINNET = "https://rpc.ankr.com/eth";
    pub const QUICKNODE_MAINNET = "https://YOUR_ENDPOINT.quiknode.pro/YOUR_API_KEY/";

    // Testnets
    pub const INFURA_GOERLI = "https://goerli.infura.io/v3/YOUR_PROJECT_ID";
    pub const INFURA_SEPOLIA = "https://sepolia.infura.io/v3/YOUR_PROJECT_ID";

    // Local development
    pub const LOCALHOST = "http://127.0.0.1:8545";
    pub const HARDHAT = "http://127.0.0.1:8545";
    pub const GANACHE = "http://127.0.0.1:7545";
};

test "rpc client creation" {
    var rpc = EthereumRpc.init(std.testing.allocator, RpcProviders.LOCALHOST);
    defer rpc.deinit();

    try std.testing.expect(std.mem.eql(u8, rpc.endpoint, RpcProviders.LOCALHOST));
}

test "ens resolution mock" {
    var rpc = EthereumRpc.init(std.testing.allocator, RpcProviders.LOCALHOST);
    defer rpc.deinit();

    const address = try rpc.resolveENS("vitalik.eth");
    defer std.testing.allocator.free(address);

    try std.testing.expect(std.mem.startsWith(u8, address, "0x"));
}
