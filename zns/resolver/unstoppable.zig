const std = @import("std");
const types = @import("types.zig");
const client = @import("../http/client.zig");

/// Unstoppable Domains resolver
pub const UnstoppableResolver = struct {
    allocator: std.mem.Allocator,
    http_client: client.HttpClient,
    api_key: ?[]const u8 = null,
    
    const UNSTOPPABLE_API = "https://resolve.unstoppabledomains.com";
    
    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8) UnstoppableResolver {
        return UnstoppableResolver{
            .allocator = allocator,
            .http_client = client.HttpClient.init(allocator),
            .api_key = api_key,
        };
    }
    
    /// Resolve Unstoppable domain to crypto addresses
    pub fn resolve(self: *UnstoppableResolver, domain: []const u8) !types.CryptoAddress {
        const url = try std.fmt.allocPrint(self.allocator, 
            "{s}/domains/{s}", .{ UNSTOPPABLE_API, domain });
        defer self.allocator.free(url);
        
        // Make request
        var response = try self.http_client.get(url, .{});
        defer response.deinit(self.allocator);
        
        if (response.status_code != 200) {
            return error.DomainNotFound;
        }
        
        // Parse response to find crypto addresses
        const crypto_addr = try self.extractCryptoAddressFromJson(domain, response.body);
        return crypto_addr;
    }
    
    /// Extract crypto address from JSON response
    fn extractCryptoAddressFromJson(self: *UnstoppableResolver, domain: []const u8, json_str: []const u8) !types.CryptoAddress {
        // Priority order for crypto currencies
        const crypto_keys = [_]struct {
            key: []const u8,
            chain: types.ChainType,
        }{
            .{ .key = "\"crypto.ETH.address\":\"", .chain = .ethereum },
            .{ .key = "\"crypto.BTC.address\":\"", .chain = .bitcoin },
            .{ .key = "\"crypto.MATIC.address\":\"", .chain = .polygon },
            .{ .key = "\"crypto.SOL.address\":\"", .chain = .solana },
            .{ .key = "\"crypto.AVAX.address\":\"", .chain = .avalanche },
            .{ .key = "\"crypto.BNB.address\":\"", .chain = .bsc },
            .{ .key = "\"crypto.FTM.address\":\"", .chain = .fantom },
        };
        
        // Try to find crypto addresses in priority order
        for (crypto_keys) |crypto_key| {
            if (std.mem.indexOf(u8, json_str, crypto_key.key)) |key_pos| {
                const addr_start = key_pos + crypto_key.key.len;
                if (std.mem.indexOf(u8, json_str[addr_start..], "\"")) |quote_pos| {
                    const address = json_str[addr_start..addr_start + quote_pos];
                    if (address.len > 0) {
                        return types.CryptoAddress.init(
                            self.allocator, 
                            domain, 
                            crypto_key.chain,
                            address
                        );
                    }
                }
            }
        }
        
        return error.DomainNotFound;
    }
    
    /// Get all crypto addresses for a domain
    pub fn resolveAll(self: *UnstoppableResolver, domain: []const u8) ![]types.CryptoAddress {
        const url = try std.fmt.allocPrint(self.allocator, 
            "{s}/domains/{s}", .{ UNSTOPPABLE_API, domain });
        defer self.allocator.free(url);
        
        // Make request
        var response = try self.http_client.get(url, .{});
        defer response.deinit(self.allocator);
        
        if (response.status_code != 200) {
            return error.DomainNotFound;
        }
        
        // Extract all crypto addresses
        var addresses = std.ArrayList(types.CryptoAddress).init(self.allocator);
        defer addresses.deinit();
        
        // Search for all crypto addresses in JSON
        const crypto_patterns = [_]struct {
            pattern: []const u8,
            chain: types.ChainType,
        }{
            .{ .pattern = "\"crypto.ETH.address\":\"", .chain = .ethereum },
            .{ .pattern = "\"crypto.BTC.address\":\"", .chain = .bitcoin },
            .{ .pattern = "\"crypto.MATIC.address\":\"", .chain = .polygon },
            .{ .pattern = "\"crypto.SOL.address\":\"", .chain = .solana },
            .{ .pattern = "\"crypto.AVAX.address\":\"", .chain = .avalanche },
            .{ .pattern = "\"crypto.BNB.address\":\"", .chain = .bsc },
            .{ .pattern = "\"crypto.FTM.address\":\"", .chain = .fantom },
        };
        
        for (crypto_patterns) |pattern| {
            if (std.mem.indexOf(u8, response.body, pattern.pattern)) |key_pos| {
                const addr_start = key_pos + pattern.pattern.len;
                if (std.mem.indexOf(u8, response.body[addr_start..], "\"")) |quote_pos| {
                    const address = response.body[addr_start..addr_start + quote_pos];
                    if (address.len > 0) {
                        const addr = try types.CryptoAddress.init(
                            self.allocator, 
                            domain, 
                            pattern.chain,
                            address
                        );
                        try addresses.append(addr);
                    }
                }
            }
        }
        
        return addresses.toOwnedSlice();
    }
    
    /// Check if domain is supported by Unstoppable Domains
    pub fn supports(domain: []const u8) bool {
        const supported_tlds = [_][]const u8{
            ".crypto", ".nft", ".x", ".wallet", ".bitcoin", 
            ".dao", ".888", ".zil", ".blockchain", ".coin"
        };
        
        for (supported_tlds) |tld| {
            if (std.mem.endsWith(u8, domain, tld)) {
                return true;
            }
        }
        return false;
    }
};

test "Unstoppable domain support check" {
    try std.testing.expect(UnstoppableResolver.supports("alice.crypto"));
    try std.testing.expect(UnstoppableResolver.supports("vault.nft"));
    try std.testing.expect(UnstoppableResolver.supports("dao.x"));
    try std.testing.expect(!UnstoppableResolver.supports("alice.eth"));
    try std.testing.expect(!UnstoppableResolver.supports("alice.ghost"));
}