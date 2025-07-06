const std = @import("std");
const types = @import("types.zig");
const client = @import("../http/client.zig");

/// ENS resolver for .eth domains
pub const ENSResolver = struct {
    allocator: std.mem.Allocator,
    rpc_client: client.JsonRpcClient,
    
    // ENS contract addresses on Ethereum mainnet
    const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
    const PUBLIC_RESOLVER = "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63";
    
    pub fn init(allocator: std.mem.Allocator, ethereum_rpc_url: []const u8) ENSResolver {
        return ENSResolver{
            .allocator = allocator,
            .rpc_client = client.JsonRpcClient.init(allocator, ethereum_rpc_url),
        };
    }
    
    /// Resolve ENS domain to crypto address
    pub fn resolve(self: *ENSResolver, domain: []const u8) !types.CryptoAddress {
        // 1. Calculate namehash
        const namehash = try self.calculateNamehash(domain);
        defer self.allocator.free(namehash);
        
        // 2. Get resolver from ENS registry
        const resolver_addr = try self.getResolver(namehash);
        defer self.allocator.free(resolver_addr);
        
        // 3. Get address from resolver
        const eth_address = try self.getAddressFromResolver(resolver_addr, namehash);
        defer self.allocator.free(eth_address);
        
        return types.CryptoAddress.init(self.allocator, domain, .ethereum, eth_address);
    }
    
    /// Calculate ENS namehash (EIP-137)
    fn calculateNamehash(self: *ENSResolver, domain: []const u8) ![]u8 {
        // Split domain by dots
        var parts = std.ArrayList([]const u8).init(self.allocator);
        defer parts.deinit();
        
        var it = std.mem.splitScalar(u8, domain, '.');
        while (it.next()) |part| {
            try parts.append(part);
        }
        
        // Start with zero hash
        var hash: [32]u8 = std.mem.zeroes([32]u8);
        
        // Process parts in reverse order
        var i = parts.items.len;
        while (i > 0) {
            i -= 1;
            const part = parts.items[i];
            
            // Hash the label
            var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            hasher.update(part);
            var label_hash: [32]u8 = undefined;
            hasher.final(&label_hash);
            
            // Hash(current_hash + label_hash)
            var combined_hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            combined_hasher.update(&hash);
            combined_hasher.update(&label_hash);
            combined_hasher.final(&hash);
        }
        
        // Convert to hex string
        var hex_hash = try self.allocator.alloc(u8, 66); // "0x" + 64 hex chars
        hex_hash[0] = '0';
        hex_hash[1] = 'x';
        
        const hex_chars = "0123456789abcdef";
        for (hash, 0..) |byte, idx| {
            hex_hash[2 + idx * 2] = hex_chars[byte >> 4];
            hex_hash[2 + idx * 2 + 1] = hex_chars[byte & 0xF];
        }
        
        return hex_hash;
    }
    
    /// Get resolver address from ENS registry
    fn getResolver(self: *ENSResolver, namehash: []const u8) ![]u8 {
        // Function signature: resolver(bytes32)
        const function_sig = "0x0178b8bf"; // Keccak256("resolver(bytes32)")[0:4]
        
        // Encode call data
        var call_data = try self.allocator.alloc(u8, 74); // 0x + 8 + 64 chars
        defer self.allocator.free(call_data);
        
        // Copy function signature
        @memcpy(call_data[0..10], function_sig);
        
        // Copy namehash (remove 0x prefix)
        @memcpy(call_data[10..], namehash[2..]);
        
        // Make eth_call
        const result = try self.rpc_client.ethCall(ENS_REGISTRY, call_data);
        
        // Extract address from result (last 20 bytes)
        if (result.len >= 42) { // 0x + 40 hex chars
            return self.allocator.dupe(u8, result[result.len - 40..]);
        }
        
        return error.InvalidResponse;
    }
    
    /// Get address from resolver contract
    fn getAddressFromResolver(self: *ENSResolver, resolver: []const u8, namehash: []const u8) ![]u8 {
        // Function signature: addr(bytes32)
        const function_sig = "0x3b3b57de"; // Keccak256("addr(bytes32)")[0:4]
        
        // Encode call data
        var call_data = try self.allocator.alloc(u8, 74); // 0x + 8 + 64 chars
        defer self.allocator.free(call_data);
        
        // Copy function signature
        @memcpy(call_data[0..10], function_sig);
        
        // Copy namehash (remove 0x prefix)
        @memcpy(call_data[10..], namehash[2..]);
        
        // Add 0x prefix to resolver if needed
        var resolver_addr = resolver;
        var resolver_buf: [42]u8 = undefined;
        if (!std.mem.startsWith(u8, resolver, "0x")) {
            resolver_buf[0] = '0';
            resolver_buf[1] = 'x';
            @memcpy(resolver_buf[2..], resolver);
            resolver_addr = &resolver_buf;
        }
        
        // Make eth_call
        const result = try self.rpc_client.ethCall(resolver_addr, call_data);
        
        // Extract address from result (last 20 bytes)
        if (result.len >= 42) { // 0x + 40 hex chars
            var address = try self.allocator.alloc(u8, 42);
            address[0] = '0';
            address[1] = 'x';
            @memcpy(address[2..], result[result.len - 40..]);
            return address;
        }
        
        return error.InvalidResponse;
    }
    
    /// Check if domain is ENS domain
    pub fn supports(domain: []const u8) bool {
        return std.mem.endsWith(u8, domain, ".eth");
    }
};

test "ENS namehash calculation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    
    var resolver = ENSResolver.init(arena.allocator(), "http://localhost:8545");
    
    // Test empty string
    const empty_hash = try resolver.calculateNamehash("");
    defer arena.allocator().free(empty_hash);
    
    // Should be 32 zero bytes
    try std.testing.expectEqualStrings("0x0000000000000000000000000000000000000000000000000000000000000000", empty_hash);
    
    // Test actual domain
    const eth_hash = try resolver.calculateNamehash("eth");
    defer arena.allocator().free(eth_hash);
    
    // Should not be all zeros
    try std.testing.expect(!std.mem.eql(u8, empty_hash, eth_hash));
}

test "ENS domain support check" {
    try std.testing.expect(ENSResolver.supports("alice.eth"));
    try std.testing.expect(!ENSResolver.supports("alice.crypto"));
    try std.testing.expect(!ENSResolver.supports("alice.ghost"));
}