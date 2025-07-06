//! Web API bridge for browser integration
//! Provides HTTP endpoints for web3 dApps

const std = @import("std");
const Allocator = std.mem.Allocator;
const wallet = @import("../core/wallet.zig");
const identity = @import("../identity/resolver.zig");

pub const BridgeError = error{
    InvalidRequest,
    Unauthorized,
    MethodNotFound,
    InternalError,
};

pub const JsonRpcRequest = struct {
    jsonrpc: []const u8,
    id: ?std.json.Value,
    method: []const u8,
    params: ?std.json.Value,
};

pub const JsonRpcResponse = struct {
    jsonrpc: []const u8,
    id: ?std.json.Value,
    result: ?std.json.Value,
    @"error": ?JsonRpcError,
};

pub const JsonRpcError = struct {
    code: i32,
    message: []const u8,
    data: ?std.json.Value,
};

pub const Bridge = struct {
    allocator: Allocator,
    wallet: ?*wallet.Wallet,
    resolver: identity.IdentityResolver,
    authorized_origins: std.ArrayList([]const u8),

    pub fn init(allocator: Allocator) Bridge {
        return Bridge{
            .allocator = allocator,
            .wallet = null,
            .resolver = identity.IdentityResolver.init(allocator),
            .authorized_origins = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Bridge) void {
        for (self.authorized_origins.items) |origin| {
            self.allocator.free(origin);
        }
        self.authorized_origins.deinit();
        self.resolver.deinit();
    }

    /// Set the wallet instance
    pub fn setWallet(self: *Bridge, w: *wallet.Wallet) void {
        self.wallet = w;
    }

    /// Add authorized origin for CORS
    pub fn addAuthorizedOrigin(self: *Bridge, origin: []const u8) !void {
        const origin_copy = try self.allocator.dupe(u8, origin);
        try self.authorized_origins.append(origin_copy);
    }

    /// Process JSON-RPC request
    pub fn processRequest(self: *Bridge, request_json: []const u8, origin: ?[]const u8) ![]const u8 {
        // Check origin authorization
        if (origin) |org| {
            if (!self.isOriginAuthorized(org)) {
                return try self.createErrorResponse(null, -32600, "Unauthorized origin");
            }
        }

        // Parse JSON-RPC request
        var parsed = std.json.parseFromSlice(JsonRpcRequest, self.allocator, request_json, .{}) catch {
            return try self.createErrorResponse(null, -32700, "Parse error");
        };
        defer parsed.deinit();

        const request = parsed.value;

        // Validate JSON-RPC version
        if (!std.mem.eql(u8, request.jsonrpc, "2.0")) {
            return try self.createErrorResponse(request.id, -32600, "Invalid Request");
        }

        // Route method
        const result = self.routeMethod(request.method, request.params) catch |err| {
            const message = switch (err) {
                BridgeError.MethodNotFound => "Method not found",
                BridgeError.InvalidRequest => "Invalid params",
                BridgeError.Unauthorized => "Unauthorized",
                else => "Internal error",
            };
            const code: i32 = switch (err) {
                BridgeError.MethodNotFound => -32601,
                BridgeError.InvalidRequest => -32602,
                BridgeError.Unauthorized => -32600,
                else => -32603,
            };
            return try self.createErrorResponse(request.id, code, message);
        };

        return try self.createSuccessResponse(request.id, result);
    }

    /// Route method to appropriate handler
    fn routeMethod(self: *Bridge, method: []const u8, params: ?std.json.Value) !std.json.Value {
        if (std.mem.eql(u8, method, "eth_accounts")) {
            return try self.handleEthAccounts();
        } else if (std.mem.eql(u8, method, "eth_requestAccounts")) {
            return try self.handleEthRequestAccounts();
        } else if (std.mem.eql(u8, method, "eth_getBalance")) {
            return try self.handleEthGetBalance(params);
        } else if (std.mem.eql(u8, method, "eth_sendTransaction")) {
            return try self.handleEthSendTransaction(params);
        } else if (std.mem.eql(u8, method, "eth_signMessage")) {
            return try self.handleEthSignMessage(params);
        } else if (std.mem.eql(u8, method, "wallet_addEthereumChain")) {
            return try self.handleWalletAddChain(params);
        } else if (std.mem.eql(u8, method, "wallet_switchEthereumChain")) {
            return try self.handleWalletSwitchChain(params);
        } else if (std.mem.eql(u8, method, "zwallet_getInfo")) {
            return try self.handleZwalletGetInfo();
        } else if (std.mem.eql(u8, method, "zwallet_resolveIdentity")) {
            return try self.handleZwalletResolveIdentity(params);
        }

        return BridgeError.MethodNotFound;
    }

    /// Handle eth_accounts
    fn handleEthAccounts(self: *Bridge) !std.json.Value {
        if (self.wallet == null) {
            return std.json.Value{ .array = std.json.Array.init(self.allocator) };
        }

        var accounts = std.json.Array.init(self.allocator);
        for (self.wallet.?.accounts.items) |account| {
            if (account.protocol == .ethereum) {
                try accounts.append(std.json.Value{ .string = account.address });
            }
        }

        return std.json.Value{ .array = accounts };
    }

    /// Handle eth_requestAccounts
    fn handleEthRequestAccounts(self: *Bridge) !std.json.Value {
        // TODO: Prompt user for permission
        return try self.handleEthAccounts();
    }

    /// Handle eth_getBalance
    fn handleEthGetBalance(self: *Bridge, params: ?std.json.Value) !std.json.Value {
        _ = params;

        if (self.wallet == null) {
            return BridgeError.Unauthorized;
        }

        // TODO: Parse address and block params
        // For now, return dummy balance
        return std.json.Value{ .string = "0x1bc16d674ec80000" }; // 2 ETH in wei
    }

    /// Handle eth_sendTransaction
    fn handleEthSendTransaction(self: *Bridge, params: ?std.json.Value) !std.json.Value {
        _ = params;

        if (self.wallet == null) {
            return BridgeError.Unauthorized;
        }

        // TODO: Parse transaction params and create transaction
        // TODO: Prompt user for approval
        // For now, return dummy transaction hash
        return std.json.Value{ .string = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" };
    }

    /// Handle eth_signMessage
    fn handleEthSignMessage(self: *Bridge, params: ?std.json.Value) !std.json.Value {
        _ = params;

        if (self.wallet == null) {
            return BridgeError.Unauthorized;
        }

        // TODO: Parse message and sign with user approval
        // For now, return dummy signature
        return std.json.Value{ .string = "0x1234...abcd" };
    }

    /// Handle wallet_addEthereumChain
    fn handleWalletAddChain(self: *Bridge, params: ?std.json.Value) !std.json.Value {
        _ = self;
        _ = params;

        // TODO: Implement chain management
        return std.json.Value{ .null = {} };
    }

    /// Handle wallet_switchEthereumChain
    fn handleWalletSwitchChain(self: *Bridge, params: ?std.json.Value) !std.json.Value {
        _ = self;
        _ = params;

        // TODO: Implement chain switching
        return std.json.Value{ .null = {} };
    }

    /// Handle zwallet_getInfo
    fn handleZwalletGetInfo(self: *Bridge) !std.json.Value {
        var info = std.json.ObjectMap.init(self.allocator);
        try info.put("name", std.json.Value{ .string = "Zwallet" });
        try info.put("version", std.json.Value{ .string = "0.1.0" });
        try info.put("icon", std.json.Value{ .string = "data:image/png;base64,..." });

        return std.json.Value{ .object = info };
    }

    /// Handle zwallet_resolveIdentity
    fn handleZwalletResolveIdentity(self: *Bridge, params: ?std.json.Value) !std.json.Value {
        if (params == null) {
            return BridgeError.InvalidRequest;
        }

        // TODO: Parse domain from params
        const domain = "example.eth"; // Placeholder

        const address = self.resolver.resolve(domain) catch {
            return BridgeError.InternalError;
        };
        defer self.allocator.free(address);

        return std.json.Value{ .string = address };
    }

    /// Check if origin is authorized
    fn isOriginAuthorized(self: *Bridge, origin: []const u8) bool {
        for (self.authorized_origins.items) |authorized| {
            if (std.mem.eql(u8, authorized, origin)) {
                return true;
            }
        }
        return false;
    }

    /// Create success response
    fn createSuccessResponse(self: *Bridge, id: ?std.json.Value, result: std.json.Value) ![]const u8 {
        const response = JsonRpcResponse{
            .jsonrpc = "2.0",
            .id = id,
            .result = result,
            .@"error" = null,
        };

        return try std.json.stringifyAlloc(self.allocator, response, .{});
    }

    /// Create error response
    fn createErrorResponse(self: *Bridge, id: ?std.json.Value, code: i32, message: []const u8) ![]const u8 {
        const error_obj = JsonRpcError{
            .code = code,
            .message = message,
            .data = null,
        };

        const response = JsonRpcResponse{
            .jsonrpc = "2.0",
            .id = id,
            .result = null,
            .@"error" = error_obj,
        };

        return try std.json.stringifyAlloc(self.allocator, response, .{});
    }
};

/// HTTP server for the bridge
pub const BridgeServer = struct {
    allocator: Allocator,
    bridge: Bridge,
    port: u16,

    pub fn init(allocator: Allocator, port: u16) BridgeServer {
        return BridgeServer{
            .allocator = allocator,
            .bridge = Bridge.init(allocator),
            .port = port,
        };
    }

    pub fn deinit(self: *BridgeServer) void {
        self.bridge.deinit();
    }

    /// Start HTTP server
    pub fn start(self: *BridgeServer) !void {
        // TODO: Implement HTTP server using tokioz
        // Listen on localhost:port
        // Handle CORS headers
        // Route POST requests to bridge.processRequest
        std.debug.print("Bridge server would start on port {}\n", .{self.port});
    }
};

test "bridge initialization" {
    var bridge = Bridge.init(std.testing.allocator);
    defer bridge.deinit();

    try bridge.addAuthorizedOrigin("https://example.com");
    try std.testing.expect(bridge.isOriginAuthorized("https://example.com"));
    try std.testing.expect(!bridge.isOriginAuthorized("https://malicious.com"));
}
