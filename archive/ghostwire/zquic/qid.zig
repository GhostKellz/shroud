//! QID (QUIC ID) and GID (Ghost ID) Implementation
//!
//! Provides unique identification for QUIC connections and Ghost Chain entities
//! with cryptographic verification and routing capabilities

const std = @import("std");
const zcrypto = @import("../../ghostcipher/zcrypto/root.zig");

/// QID (QUIC ID) - Unique identifier for QUIC connections
pub const QID = struct {
    /// Raw bytes of the QID (20 bytes total)
    bytes: [20]u8,
    
    /// QID version for future compatibility
    version: u8,
    
    /// Timestamp when QID was generated
    timestamp: u64,
    
    pub const CURRENT_VERSION = 1;
    pub const SIZE = 20;
    
    /// Generate new QID from connection parameters
    pub fn generate(local_addr: []const u8, remote_addr: []const u8, salt: [32]u8) QID {
        var hasher = std.crypto.hash.Blake3.init(.{});
        
        // Include version for future compatibility
        hasher.update(&[_]u8{CURRENT_VERSION});
        
        // Include addresses and salt
        hasher.update(local_addr);
        hasher.update(remote_addr);
        hasher.update(&salt);
        
        // Include current timestamp
        const timestamp = std.time.timestamp();
        hasher.update(std.mem.asBytes(&timestamp));
        
        var hash_result: [32]u8 = undefined;
        hasher.final(&hash_result);
        
        // Take first 20 bytes for QID
        var qid_bytes: [20]u8 = undefined;
        @memcpy(&qid_bytes, hash_result[0..20]);
        
        return QID{
            .bytes = qid_bytes,
            .version = CURRENT_VERSION,
            .timestamp = @intCast(timestamp),
        };
    }
    
    /// Generate deterministic QID from seed
    pub fn fromSeed(seed: [32]u8) QID {
        const hash = zcrypto.hash.blake3(seed);
        
        var qid_bytes: [20]u8 = undefined;
        @memcpy(&qid_bytes, hash[0..20]);
        
        return QID{
            .bytes = qid_bytes,
            .version = CURRENT_VERSION,
            .timestamp = 0, // Deterministic QIDs have no timestamp
        };
    }
    
    /// Parse QID from string representation
    pub fn fromString(str: []const u8) !QID {
        if (str.len != 40) { // 20 bytes * 2 hex chars
            return error.InvalidQIDFormat;
        }
        
        var qid_bytes: [20]u8 = undefined;
        _ = std.fmt.hexToBytes(&qid_bytes, str) catch return error.InvalidQIDFormat;
        
        return QID{
            .bytes = qid_bytes,
            .version = CURRENT_VERSION,
            .timestamp = 0,
        };
    }
    
    /// Convert QID to string representation
    pub fn toString(self: QID, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, 40);
        _ = std.fmt.bufPrint(result, "{}", .{std.fmt.fmtSliceHexLower(&self.bytes)}) catch unreachable;
        return result;
    }
    
    /// Check if QID is valid
    pub fn isValid(self: QID) bool {
        // Check version compatibility
        if (self.version > CURRENT_VERSION) return false;
        
        // Check for null QID
        for (self.bytes) |byte| {
            if (byte != 0) return true;
        }
        return false; // All zeros is invalid
    }
    
    /// Get routing prefix (first 4 bytes)
    pub fn getRoutingPrefix(self: QID) [4]u8 {
        return self.bytes[0..4].*;
    }
    
    /// Compare QIDs for equality
    pub fn eql(self: QID, other: QID) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

/// GID (Ghost ID) - Cryptographic identity for Ghost Chain entities
pub const GID = struct {
    /// Public key bytes (32 bytes for Ed25519)
    public_key: [32]u8,
    
    /// Chain ID for multi-chain support
    chain_id: u32,
    
    /// Entity type (wallet, node, service, etc.)
    entity_type: EntityType,
    
    /// Version for future compatibility
    version: u8,
    
    pub const CURRENT_VERSION = 1;
    pub const SIZE = 37; // 32 + 4 + 1 bytes
    
    pub const EntityType = enum(u8) {
        wallet = 0,
        validator = 1,
        service = 2,
        contract = 3,
        bridge = 4,
        oracle = 5,
    };
    
    /// Generate GID from public key
    pub fn fromPublicKey(public_key: [32]u8, chain_id: u32, entity_type: EntityType) GID {
        return GID{
            .public_key = public_key,
            .chain_id = chain_id,
            .entity_type = entity_type,
            .version = CURRENT_VERSION,
        };
    }
    
    /// Generate GID with new Ed25519 keypair
    pub fn generate(chain_id: u32, entity_type: EntityType) !struct {
        gid: GID,
        private_key: [64]u8,
    } {
        const keypair = try zcrypto.asym.ed25519.generateKeypair();
        
        const gid = GID.fromPublicKey(keypair.public_key, chain_id, entity_type);
        
        return .{
            .gid = gid,
            .private_key = keypair.private_key,
        };
    }
    
    /// Get GID as address string (bech32-like encoding)
    pub fn toAddress(self: GID, allocator: std.mem.Allocator) ![]u8 {
        // Create address from hash of GID components
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(&self.public_key);
        hasher.update(std.mem.asBytes(&self.chain_id));
        hasher.update(&[_]u8{@intFromEnum(self.entity_type)});
        hasher.update(&[_]u8{self.version});
        
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        // Use first 20 bytes for address
        const address_bytes = hash[0..20];
        
        // Add prefix based on entity type
        const prefix = switch (self.entity_type) {
            .wallet => "ghost",
            .validator => "gval",
            .service => "gsvc",
            .contract => "gcon",
            .bridge => "gbrg",
            .oracle => "gorc",
        };
        
        // Encode as hex with prefix
        var result = try allocator.alloc(u8, prefix.len + 40);
        @memcpy(result[0..prefix.len], prefix);
        _ = std.fmt.bufPrint(result[prefix.len..], "{}", .{std.fmt.fmtSliceHexLower(address_bytes)}) catch unreachable;
        
        return result;
    }
    
    /// Parse GID from address string
    pub fn fromAddress(address: []const u8) !GID {
        // Determine entity type from prefix
        const entity_type: EntityType = if (std.mem.startsWith(u8, address, "ghost"))
            .wallet
        else if (std.mem.startsWith(u8, address, "gval"))
            .validator
        else if (std.mem.startsWith(u8, address, "gsvc"))
            .service
        else if (std.mem.startsWith(u8, address, "gcon"))
            .contract
        else if (std.mem.startsWith(u8, address, "gbrg"))
            .bridge
        else if (std.mem.startsWith(u8, address, "gorc"))
            .oracle
        else
            return error.InvalidAddress;
        
        // Extract hex portion
        const hex_start = switch (entity_type) {
            .wallet => 5, // "ghost".len
            else => 4, // "gval", "gsvc", etc.
        };
        
        if (address.len != hex_start + 40) return error.InvalidAddress;
        
        var address_bytes: [20]u8 = undefined;
        _ = std.fmt.hexToBytes(&address_bytes, address[hex_start..]) catch return error.InvalidAddress;
        
        // For now, return a placeholder GID (in practice, would need reverse lookup)
        return GID{
            .public_key = [_]u8{0} ** 32,
            .chain_id = 0,
            .entity_type = entity_type,
            .version = CURRENT_VERSION,
        };
    }
    
    /// Sign message with GID's private key
    pub fn sign(self: GID, message: []const u8, private_key: [64]u8) ![64]u8 {
        // Verify the private key corresponds to this GID's public key
        const derived_public = try zcrypto.asym.ed25519.publicKeyFromPrivate(private_key);
        if (!std.mem.eql(u8, &derived_public, &self.public_key)) {
            return error.KeyMismatch;
        }
        
        return zcrypto.asym.ed25519.sign(message, private_key);
    }
    
    /// Verify signature against GID's public key
    pub fn verify(self: GID, message: []const u8, signature: [64]u8) bool {
        return zcrypto.asym.ed25519.verify(message, signature, self.public_key);
    }
    
    /// Check if GID is valid
    pub fn isValid(self: GID) bool {
        // Check version
        if (self.version > CURRENT_VERSION) return false;
        
        // Check for null public key
        for (self.public_key) |byte| {
            if (byte != 0) return true;
        }
        return false;
    }
};

/// QID-GID Association for routing and identity
pub const QIDGIDMapping = struct {
    qid: QID,
    gid: GID,
    created_at: u64,
    expires_at: ?u64,
    
    pub fn create(qid: QID, gid: GID, ttl_seconds: ?u64) QIDGIDMapping {
        const now = @intCast(u64, std.time.timestamp());
        return QIDGIDMapping{
            .qid = qid,
            .gid = gid,
            .created_at = now,
            .expires_at = if (ttl_seconds) |ttl| now + ttl else null,
        };
    }
    
    pub fn isExpired(self: QIDGIDMapping) bool {
        if (self.expires_at) |expires| {
            const now = @intCast(u64, std.time.timestamp());
            return now >= expires;
        }
        return false;
    }
};

/// QID/GID Router for connection management
pub const QIDRouter = struct {
    mappings: std.HashMap(QID, QIDGIDMapping, QIDContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    const QIDContext = struct {
        pub fn hash(self: @This(), qid: QID) u64 {
            _ = self;
            return std.hash_map.hashString(&qid.bytes);
        }
        
        pub fn eql(self: @This(), a: QID, b: QID) bool {
            _ = self;
            return a.eql(b);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) QIDRouter {
        return QIDRouter{
            .mappings = std.HashMap(QID, QIDGIDMapping, QIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *QIDRouter) void {
        self.mappings.deinit();
    }
    
    /// Register QID-GID mapping
    pub fn register(self: *QIDRouter, qid: QID, gid: GID, ttl_seconds: ?u64) !void {
        const mapping = QIDGIDMapping.create(qid, gid, ttl_seconds);
        try self.mappings.put(qid, mapping);
    }
    
    /// Lookup GID by QID
    pub fn lookupGID(self: *QIDRouter, qid: QID) ?GID {
        if (self.mappings.get(qid)) |mapping| {
            if (!mapping.isExpired()) {
                return mapping.gid;
            }
        }
        return null;
    }
    
    /// Cleanup expired mappings
    pub fn cleanup(self: *QIDRouter) !void {
        var expired_qids = std.ArrayList(QID).init(self.allocator);
        defer expired_qids.deinit();
        
        var iterator = self.mappings.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                try expired_qids.append(entry.key_ptr.*);
            }
        }
        
        for (expired_qids.items) |qid| {
            _ = self.mappings.remove(qid);
        }
    }
};

test "QID generation and operations" {
    const allocator = std.testing.allocator;
    
    // Test QID generation
    const qid = QID.generate("127.0.0.1:8080", "127.0.0.1:8081", [_]u8{1} ** 32);
    std.testing.expect(qid.isValid()) catch unreachable;
    
    // Test string conversion
    const qid_str = try qid.toString(allocator);
    defer allocator.free(qid_str);
    
    const parsed_qid = try QID.fromString(qid_str);
    std.testing.expect(qid.eql(parsed_qid)) catch unreachable;
}

test "GID generation and operations" {
    const allocator = std.testing.allocator;
    
    // Test GID generation
    const gid_result = try GID.generate(1, .wallet);
    const gid = gid_result.gid;
    const private_key = gid_result.private_key;
    
    std.testing.expect(gid.isValid()) catch unreachable;
    
    // Test address generation
    const address = try gid.toAddress(allocator);
    defer allocator.free(address);
    
    std.testing.expect(std.mem.startsWith(u8, address, "ghost")) catch unreachable;
    
    // Test signing and verification
    const message = "Hello, Ghost Chain!";
    const signature = try gid.sign(message, private_key);
    const valid = gid.verify(message, signature);
    
    std.testing.expect(valid) catch unreachable;
}

test "QID-GID routing" {
    const allocator = std.testing.allocator;
    
    var router = QIDRouter.init(allocator);
    defer router.deinit();
    
    // Create QID and GID
    const qid = QID.generate("test1", "test2", [_]u8{2} ** 32);
    const gid_result = try GID.generate(1, .service);
    
    // Register mapping
    try router.register(qid, gid_result.gid, 3600); // 1 hour TTL
    
    // Lookup
    const found_gid = router.lookupGID(qid);
    std.testing.expect(found_gid != null) catch unreachable;
    std.testing.expect(found_gid.?.public_key[0] == gid_result.gid.public_key[0]) catch unreachable;
}