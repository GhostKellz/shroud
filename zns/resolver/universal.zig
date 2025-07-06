const std = @import("std");
const types = @import("types.zig");
const ens = @import("ens.zig");
const unstoppable = @import("unstoppable.zig");
const ghost = @import("ghost.zig");

/// Universal resolver for all crypto domains
pub const UniversalResolver = struct {
    allocator: std.mem.Allocator,
    
    // Individual resolvers
    ghost_resolver: ghost.GhostResolver,
    ens_resolver: ens.ENSResolver,
    unstoppable_resolver: unstoppable.UnstoppableResolver,
    
    // Cache for resolved domains
    cache: std.HashMap([]const u8, CacheEntry, std.hash_map.StringContext, 80),
    
    const CacheEntry = struct {
        address: types.CryptoAddress,
        expires_at: i64,
        
        pub fn isExpired(self: *const CacheEntry) bool {
            return std.time.timestamp() > self.expires_at;
        }
    };
    
    pub fn init(
        allocator: std.mem.Allocator,
        ghostbridge_endpoint: []const u8,
        ethereum_rpc_url: []const u8,
        unstoppable_api_key: ?[]const u8,
    ) UniversalResolver {
        return UniversalResolver{
            .allocator = allocator,
            .ghost_resolver = ghost.GhostResolver.init(allocator, ghostbridge_endpoint),
            .ens_resolver = ens.ENSResolver.init(allocator, ethereum_rpc_url),
            .unstoppable_resolver = unstoppable.UnstoppableResolver.init(allocator, unstoppable_api_key),
            .cache = std.HashMap([]const u8, CacheEntry, std.hash_map.StringContext, 80).init(allocator),
        };
    }
    
    pub fn deinit(self: *UniversalResolver) void {
        // Clean up cache
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.address.deinit(self.allocator);
        }
        self.cache.deinit();
    }
    
    /// Resolve any crypto domain to address
    pub fn resolve(self: *UniversalResolver, domain: []const u8) !types.CryptoAddress {
        // Check cache first
        if (self.cache.get(domain)) |entry| {
            if (!entry.isExpired()) {
                // Return cached result (clone to avoid memory issues)
                return types.CryptoAddress.init(
                    self.allocator,
                    entry.address.domain,
                    entry.address.chain,
                    entry.address.address
                );
            } else {
                // Remove expired entry
                _ = self.cache.remove(domain);
            }
        }
        
        const tld = types.extractTLD(domain);
        const domain_type = types.getDomainType(tld);
        
        // Route to appropriate resolver
        const result = switch (domain_type) {
            .ghost => try self.ghost_resolver.resolve(domain),
            .ens => try self.ens_resolver.resolve(domain),
            .unstoppable => try self.unstoppable_resolver.resolve(domain),
            .traditional => try self.resolveDNS(domain),
            .unknown => return error.UnsupportedDomain,
            .handshake => return error.UnsupportedDomain, // TODO: Implement Handshake
        };
        
        // Cache the result
        try self.cacheResult(domain, result);
        
        return result;
    }
    
    /// Resolve multiple domains in parallel
    pub fn resolveBatch(self: *UniversalResolver, domains: []const []const u8) ![]types.CryptoAddress {
        var results = try self.allocator.alloc(types.CryptoAddress, domains.len);
        
        // For now, resolve sequentially
        // TODO: Implement parallel resolution with threading
        for (domains, 0..) |domain, i| {
            results[i] = self.resolve(domain) catch |err| switch (err) {
                error.DomainNotFound => try types.CryptoAddress.init(self.allocator, domain, .unknown, ""),
                else => return err,
            };
        }
        
        return results;
    }
    
    /// Get all crypto addresses for a domain (multi-chain)
    pub fn resolveAll(self: *UniversalResolver, domain: []const u8) ![]types.CryptoAddress {
        const tld = types.extractTLD(domain);
        const domain_type = types.getDomainType(tld);
        
        switch (domain_type) {
            .unstoppable => {
                // Unstoppable Domains support multiple chains
                return self.unstoppable_resolver.resolveAll(domain);
            },
            .ens, .ghost => {
                // Single chain domains
                const result = try self.resolve(domain);
                var results = try self.allocator.alloc(types.CryptoAddress, 1);
                results[0] = result;
                return results;
            },
            else => return error.UnsupportedDomain,
        }
    }
    
    /// Resolve traditional DNS TXT records for crypto addresses
    fn resolveDNS(self: *UniversalResolver, domain: []const u8) !types.CryptoAddress {
        _ = self;
        _ = domain;
        
        // TODO: Implement DNS TXT record resolution
        // Look for records like "crypto.ETH.address=0x..."
        
        return error.DomainNotFound;
    }
    
    /// Cache resolution result
    fn cacheResult(self: *UniversalResolver, domain: []const u8, address: types.CryptoAddress) !void {
        const domain_key = try self.allocator.dupe(u8, domain);
        
        // Clone the address for cache storage
        const cached_address = try types.CryptoAddress.init(
            self.allocator,
            address.domain,
            address.chain,
            address.address
        );
        
        const cache_entry = CacheEntry{
            .address = cached_address,
            .expires_at = std.time.timestamp() + address.ttl,
        };
        
        try self.cache.put(domain_key, cache_entry);
    }
    
    /// Check if domain is supported
    pub fn supports(domain: []const u8) bool {
        return ghost.GhostResolver.supports(domain) or
               ens.ENSResolver.supports(domain) or
               unstoppable.UnstoppableResolver.supports(domain);
    }
    
    /// Get resolver type for domain
    pub fn getResolverType(domain: []const u8) types.DomainType {
        const tld = types.extractTLD(domain);
        return types.getDomainType(tld);
    }
    
    /// Clear cache
    pub fn clearCache(self: *UniversalResolver) void {
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.address.deinit(self.allocator);
        }
        self.cache.clearAndFree();
    }
    
    /// Get cache statistics
    pub fn getCacheStats(self: *UniversalResolver) struct {
        total_entries: u32,
        expired_entries: u32,
    } {
        var total: u32 = 0;
        var expired: u32 = 0;
        
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            total += 1;
            if (entry.value_ptr.isExpired()) {
                expired += 1;
            }
        }
        
        return .{
            .total_entries = total,
            .expired_entries = expired,
        };
    }
};

test "Universal resolver domain type detection" {
    try std.testing.expect(UniversalResolver.supports("alice.eth"));
    try std.testing.expect(UniversalResolver.supports("vault.crypto"));
    try std.testing.expect(UniversalResolver.supports("ghostkellz.ghost"));
    try std.testing.expect(!UniversalResolver.supports("example.com"));
    
    try std.testing.expectEqual(types.DomainType.ens, UniversalResolver.getResolverType("alice.eth"));
    try std.testing.expectEqual(types.DomainType.unstoppable, UniversalResolver.getResolverType("vault.crypto"));
    try std.testing.expectEqual(types.DomainType.ghost, UniversalResolver.getResolverType("ghostkellz.ghost"));
}