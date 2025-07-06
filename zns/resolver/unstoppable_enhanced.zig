const std = @import("std");
const types = @import("types.zig");
const client = @import("../http/client.zig");

/// Enhanced Unstoppable Domains resolver with full JSON parsing
pub const UnstoppableEnhancedResolver = struct {
    allocator: std.mem.Allocator,
    http_client: client.HttpClient,
    api_key: ?[]const u8 = null,
    
    const UNSTOPPABLE_API = "https://resolve.unstoppabledomains.com";
    
    /// MX Record structure
    pub const MXRecord = struct {
        exchange: []const u8,
        priority: u16,
    };
    
    /// Full Unstoppable Domains record
    pub const UDRecord = struct {
        // Metadata
        domain: []const u8,
        owner: ?[]const u8 = null,
        resolver: ?[]const u8 = null,
        registry: ?[]const u8 = null,
        
        // Crypto addresses (key: chain symbol, value: address)
        crypto_addresses: std.StringHashMap([]const u8),
        
        // Web/IPFS content
        browser_redirect: ?[]const u8 = null,
        ipfs_html: ?[]const u8 = null,
        ipfs_redirect_domain: ?[]const u8 = null,
        
        // DNS records
        dns_a: ?[][]const u8 = null,
        dns_aaaa: ?[][]const u8 = null,
        dns_cname: ?[]const u8 = null,
        dns_mx: ?[]MXRecord = null,
        
        // Social profiles (key: platform, value: username)
        social_profiles: std.StringHashMap([]const u8),
        
        pub fn deinit(self: *UDRecord, allocator: std.mem.Allocator) void {
            // Free hashmaps
            self.crypto_addresses.deinit();
            self.social_profiles.deinit();
            
            // Free arrays
            if (self.dns_a) |records| allocator.free(records);
            if (self.dns_aaaa) |records| allocator.free(records);
            if (self.dns_mx) |records| allocator.free(records);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8) UnstoppableEnhancedResolver {
        return UnstoppableEnhancedResolver{
            .allocator = allocator,
            .http_client = client.HttpClient.init(allocator),
            .api_key = api_key,
        };
    }
    
    /// Resolve domain to primary crypto address
    pub fn resolve(self: *UnstoppableEnhancedResolver, domain: []const u8) !types.CryptoAddress {
        const record = try self.getFullRecord(domain);
        defer record.deinit(self.allocator);
        
        // Priority order for primary address
        const priority_chains = [_]struct { symbol: []const u8, chain: types.ChainType }{
            .{ .symbol = "ETH", .chain = .ethereum },
            .{ .symbol = "BTC", .chain = .bitcoin },
            .{ .symbol = "MATIC", .chain = .polygon },
            .{ .symbol = "SOL", .chain = .solana },
            .{ .symbol = "AVAX", .chain = .avalanche },
            .{ .symbol = "BNB", .chain = .bsc },
        };
        
        for (priority_chains) |pc| {
            if (record.crypto_addresses.get(pc.symbol)) |address| {
                return types.CryptoAddress.init(
                    self.allocator,
                    domain,
                    pc.chain,
                    address
                );
            }
        }
        
        return error.DomainNotFound;
    }
    
    /// Get full domain record with all fields
    pub fn getFullRecord(self: *UnstoppableEnhancedResolver, domain: []const u8) !UDRecord {
        const url = try std.fmt.allocPrint(self.allocator, 
            "{s}/domains/{s}", .{ UNSTOPPABLE_API, domain });
        defer self.allocator.free(url);
        
        // Make request
        var response = try self.http_client.get(url, .{});
        defer response.deinit(self.allocator);
        
        if (response.status_code != 200) {
            return error.DomainNotFound;
        }
        
        return try self.parseFullRecord(domain, response.body);
    }
    
    /// Parse full record from JSON response
    fn parseFullRecord(self: *UnstoppableEnhancedResolver, domain: []const u8, json_str: []const u8) !UDRecord {
        var record = UDRecord{
            .domain = try self.allocator.dupe(u8, domain),
            .crypto_addresses = std.StringHashMap([]const u8).init(self.allocator),
            .social_profiles = std.StringHashMap([]const u8).init(self.allocator),
        };
        errdefer record.deinit(self.allocator);
        
        // Parse metadata
        if (self.extractJsonString(json_str, "\"owner\":\"")) |owner| {
            record.owner = try self.allocator.dupe(u8, owner);
        }
        
        if (self.extractJsonString(json_str, "\"resolver\":\"")) |resolver| {
            record.resolver = try self.allocator.dupe(u8, resolver);
        }
        
        // Parse crypto addresses
        const crypto_patterns = [_][]const u8{
            "ETH", "BTC", "MATIC", "SOL", "AVAX", "BNB", "FTM",
            "ATOM", "NEAR", "ALGO", "XLM", "XRP", "ADA", "DOT",
        };
        
        for (crypto_patterns) |symbol| {
            const key = try std.fmt.allocPrint(self.allocator, 
                "\"crypto.{s}.address\":\"", .{symbol});
            defer self.allocator.free(key);
            
            if (self.extractJsonString(json_str, key)) |address| {
                try record.crypto_addresses.put(
                    try self.allocator.dupe(u8, symbol),
                    try self.allocator.dupe(u8, address)
                );
            }
        }
        
        // Parse web content
        if (self.extractJsonString(json_str, "\"browser.redirect_url\":\"")) |url| {
            record.browser_redirect = try self.allocator.dupe(u8, url);
        }
        
        if (self.extractJsonString(json_str, "\"ipfs.html.value\":\"")) |ipfs| {
            record.ipfs_html = try self.allocator.dupe(u8, ipfs);
        }
        
        // Parse social profiles
        const social_platforms = [_][]const u8{
            "twitter", "telegram", "discord", "reddit", "youtube"
        };
        
        for (social_platforms) |platform| {
            const key = try std.fmt.allocPrint(self.allocator, 
                "\"social.{s}.username\":\"", .{platform});
            defer self.allocator.free(key);
            
            if (self.extractJsonString(json_str, key)) |username| {
                try record.social_profiles.put(
                    try self.allocator.dupe(u8, platform),
                    try self.allocator.dupe(u8, username)
                );
            }
        }
        
        // Parse DNS records
        if (self.extractJsonString(json_str, "\"dns.CNAME\":\"")) |cname| {
            record.dns_cname = try self.allocator.dupe(u8, cname);
        }
        
        return record;
    }
    
    /// Extract string value from JSON
    fn extractJsonString(self: *UnstoppableEnhancedResolver, json: []const u8, key: []const u8) ?[]const u8 {
        _ = self;
        if (std.mem.indexOf(u8, json, key)) |start_pos| {
            const value_start = start_pos + key.len;
            if (std.mem.indexOf(u8, json[value_start..], "\"")) |end_pos| {
                return json[value_start..value_start + end_pos];
            }
        }
        return null;
    }
    
    /// Get all crypto addresses with full metadata
    pub fn resolveAll(self: *UnstoppableEnhancedResolver, domain: []const u8) ![]types.CryptoAddress {
        const record = try self.getFullRecord(domain);
        defer record.deinit(self.allocator);
        
        var addresses = std.ArrayList(types.CryptoAddress).init(self.allocator);
        defer addresses.deinit();
        
        // Convert all crypto addresses
        var it = record.crypto_addresses.iterator();
        while (it.next()) |entry| {
            const chain = types.ChainType.fromString(entry.key_ptr.*);
            const addr = try types.CryptoAddress.init(
                self.allocator,
                domain,
                chain,
                entry.value_ptr.*
            );
            try addresses.append(addr);
        }
        
        return addresses.toOwnedSlice();
    }
    
    /// Get web metadata (redirect URL, IPFS, etc)
    pub fn getWebMetadata(self: *UnstoppableEnhancedResolver, domain: []const u8) !WebMetadata {
        const record = try self.getFullRecord(domain);
        defer record.deinit(self.allocator);
        
        return WebMetadata{
            .redirect_url = if (record.browser_redirect) |url| 
                try self.allocator.dupe(u8, url) else null,
            .ipfs_hash = if (record.ipfs_html) |hash| 
                try self.allocator.dupe(u8, hash) else null,
        };
    }
    
    pub const WebMetadata = struct {
        redirect_url: ?[]const u8,
        ipfs_hash: ?[]const u8,
        
        pub fn deinit(self: *WebMetadata, allocator: std.mem.Allocator) void {
            if (self.redirect_url) |url| allocator.free(url);
            if (self.ipfs_hash) |hash| allocator.free(hash);
        }
    };
    
    /// Check if domain is supported
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