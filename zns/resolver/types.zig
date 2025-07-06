const std = @import("std");

/// Supported blockchain/domain types
pub const DomainType = enum {
    ghost,       // .ghost, .bc, .kz, .zkellz (via GhostBridge)
    ens,         // .eth (via Ethereum RPC)
    unstoppable, // .crypto, .nft, .x, .wallet, .bitcoin, etc.
    handshake,   // Handshake blockchain domains
    traditional, // .com, .org, etc.
    unknown,
};

/// Supported blockchain networks
pub const ChainType = enum {
    ethereum,
    bitcoin,
    ghostchain,
    stellar,
    polygon,
    solana,
    avalanche,
    arbitrum,
    optimism,
    bsc,
    fantom,
    unknown,
    
    pub fn fromString(chain: []const u8) ChainType {
        const map = std.static_string_map.StaticStringMap(ChainType).initComptime(.{
            .{ "ethereum", .ethereum },
            .{ "eth", .ethereum },
            .{ "bitcoin", .bitcoin },
            .{ "btc", .bitcoin },
            .{ "ghostchain", .ghostchain },
            .{ "ghost", .ghostchain },
            .{ "stellar", .stellar },
            .{ "xlm", .stellar },
            .{ "polygon", .polygon },
            .{ "matic", .polygon },
            .{ "solana", .solana },
            .{ "sol", .solana },
            .{ "avalanche", .avalanche },
            .{ "avax", .avalanche },
            .{ "arbitrum", .arbitrum },
            .{ "optimism", .optimism },
            .{ "bsc", .bsc },
            .{ "fantom", .fantom },
        });
        return map.get(chain) orelse .unknown;
    }
};

/// Universal crypto address format
pub const CryptoAddress = struct {
    domain: []const u8,
    chain: ChainType,
    address: []const u8,
    metadata: ?std.json.Value = null,
    ttl: u32 = 300,
    resolved_at: i64,
    
    pub fn init(allocator: std.mem.Allocator, domain: []const u8, chain: ChainType, address: []const u8) !CryptoAddress {
        return CryptoAddress{
            .domain = try allocator.dupe(u8, domain),
            .chain = chain,
            .address = try allocator.dupe(u8, address),
            .resolved_at = std.time.timestamp(),
        };
    }
    
    pub fn deinit(self: *CryptoAddress, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.address);
    }
};

/// Domain registry mapping TLDs to domain types
pub const DOMAIN_REGISTRY = std.static_string_map.StaticStringMap(DomainType).initComptime(.{
    // GhostChain native domains
    .{ ".ghost", .ghost },
    .{ ".bc", .ghost },
    .{ ".kz", .ghost },
    .{ ".zkellz", .ghost },
    
    // ENS domains
    .{ ".eth", .ens },
    
    // Unstoppable Domains
    .{ ".crypto", .unstoppable },
    .{ ".nft", .unstoppable },
    .{ ".x", .unstoppable },
    .{ ".wallet", .unstoppable },
    .{ ".bitcoin", .unstoppable },
    .{ ".dao", .unstoppable },
    .{ ".888", .unstoppable },
    .{ ".zil", .unstoppable },
    .{ ".blockchain", .unstoppable },
    .{ ".coin", .unstoppable },
    
    // Traditional domains (for fallback)
    .{ ".com", .traditional },
    .{ ".org", .traditional },
    .{ ".net", .traditional },
    .{ ".io", .traditional },
});

/// Extract TLD from domain name
pub fn extractTLD(domain: []const u8) []const u8 {
    if (std.mem.lastIndexOf(u8, domain, ".")) |dot_idx| {
        return domain[dot_idx..];
    }
    return "";
}

/// Get domain type from TLD
pub fn getDomainType(tld: []const u8) DomainType {
    return DOMAIN_REGISTRY.get(tld) orelse .unknown;
}

/// DNS record types
pub const DNSRecordType = enum {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
    SRV,
    
    pub fn fromString(record_type: []const u8) DNSRecordType {
        const map = std.ComptimeStringMap(DNSRecordType, .{
            .{ "A", .A },
            .{ "AAAA", .AAAA },
            .{ "CNAME", .CNAME },
            .{ "TXT", .TXT },
            .{ "MX", .MX },
            .{ "SRV", .SRV },
        });
        return map.get(record_type) orelse .A;
    }
};

/// DNS record structure
pub const DNSRecord = struct {
    record_type: DNSRecordType,
    value: []const u8,
    ttl: u32 = 300,
    
    pub fn init(allocator: std.mem.Allocator, record_type: DNSRecordType, value: []const u8, ttl: u32) !DNSRecord {
        return DNSRecord{
            .record_type = record_type,
            .value = try allocator.dupe(u8, value),
            .ttl = ttl,
        };
    }
    
    pub fn deinit(self: *DNSRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

/// ZNS record format for native domains
pub const ZNSRecord = struct {
    domain: []const u8,
    owner_pubkey: [32]u8, // Ed25519 public key
    records: []DNSRecord,
    metadata_uri: ?[]const u8 = null,
    ttl: u32 = 300,
    timestamp: u64,
    signature: [64]u8, // Ed25519 signature
    
    pub fn init(
        allocator: std.mem.Allocator,
        domain: []const u8,
        owner_pubkey: [32]u8,
        records: []DNSRecord,
        ttl: u32,
    ) !ZNSRecord {
        return ZNSRecord{
            .domain = try allocator.dupe(u8, domain),
            .owner_pubkey = owner_pubkey,
            .records = records,
            .ttl = ttl,
            .timestamp = @intCast(std.time.timestamp()),
            .signature = std.mem.zeroes([64]u8), // Will be set during signing
        };
    }
    
    pub fn deinit(self: *ZNSRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        if (self.metadata_uri) |uri| {
            allocator.free(uri);
        }
        for (self.records) |*record| {
            record.deinit(allocator);
        }
        allocator.free(self.records);
    }
    
    /// Get signable data for Ed25519 signature
    pub fn getSignableData(self: *const ZNSRecord, allocator: std.mem.Allocator) ![]u8 {
        // Create JSON representation for signing (without signature field)
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        
        var json_data = std.ArrayList(u8).init(arena.allocator());
        try json_data.appendSlice(self.domain);
        try json_data.append(':');
        
        // Add timestamp
        var timestamp_buf: [20]u8 = undefined;
        const timestamp_str = try std.fmt.bufPrint(&timestamp_buf, "{d}", .{self.timestamp});
        try json_data.appendSlice(timestamp_str);
        
        // Add records
        for (self.records) |record| {
            try json_data.append(':');
            try json_data.appendSlice(record.value);
        }
        
        return allocator.dupe(u8, json_data.items);
    }
    
    /// Verify Ed25519 signature
    pub fn verify(self: *const ZNSRecord, allocator: std.mem.Allocator) !bool {
        const signable_data = try self.getSignableData(allocator);
        defer allocator.free(signable_data);
        
        // TODO: Use zcrypto for actual verification
        // const zcrypto = @import("zcrypto");
        // return zcrypto.asym.ed25519.verify(signable_data, self.owner_pubkey, self.signature);
        
        // Placeholder implementation
        return true;
    }
};

/// Error types for resolution
pub const ResolverError = error{
    DomainNotFound,
    InvalidDomain,
    NetworkError,
    AuthenticationError,
    RateLimited,
    InvalidSignature,
    UnsupportedDomain,
    OutOfMemory,
} || std.mem.Allocator.Error;