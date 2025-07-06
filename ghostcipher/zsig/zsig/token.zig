//! Ghost Token System - JWT-compatible authentication tokens for GhostChain ecosystem
//! Provides secure, performant token creation/verification for ghostd, walletd, realid, etc.

const std = @import("std");
const backend = @import("backend.zig");
const key = @import("key.zig");
const sign = @import("sign.zig");

/// Token algorithms supported
pub const Algorithm = enum {
    ed25519,
    ml_dsa_65,
    hybrid_x25519_ml_kem,

    pub fn toString(self: Algorithm) []const u8 {
        return switch (self) {
            .ed25519 => "EdDSA", // EdDSA with Ed25519
            .ml_dsa_65 => "ML-DSA-65", // Post-quantum ML-DSA-65
            .hybrid_x25519_ml_kem => "HYBRID-X25519-ML-KEM", // Hybrid approach
        };
    }

    pub fn fromString(str: []const u8) ?Algorithm {
        // JWT-style algorithm names
        if (std.mem.eql(u8, str, "EdDSA")) return .ed25519;
        if (std.mem.eql(u8, str, "ES256")) return .ed25519; // JWT fallback
        if (std.mem.eql(u8, str, "ML-DSA-65")) return .ml_dsa_65;
        if (std.mem.eql(u8, str, "HYBRID-X25519-ML-KEM")) return .hybrid_x25519_ml_kem;
        
        // Plain algorithm names (for CLI convenience)
        if (std.mem.eql(u8, str, "ed25519")) return .ed25519;
        if (std.mem.eql(u8, str, "ml_dsa_65")) return .ml_dsa_65;
        if (std.mem.eql(u8, str, "ml-dsa-65")) return .ml_dsa_65;
        if (std.mem.eql(u8, str, "post-quantum")) return .ml_dsa_65;
        if (std.mem.eql(u8, str, "hybrid")) return .hybrid_x25519_ml_kem;
        if (std.mem.eql(u8, str, "hybrid_x25519_ml_kem")) return .hybrid_x25519_ml_kem;
        
        return null;
    }

    /// Convert token algorithm to backend algorithm
    pub fn toBackendAlgorithm(self: Algorithm) backend.Algorithm {
        return switch (self) {
            .ed25519 => .ed25519,
            .ml_dsa_65 => .ml_dsa_65,
            .hybrid_x25519_ml_kem => .hybrid_x25519_ml_kem,
        };
    }
};

/// Token types for different use cases
pub const TokenType = enum {
    auth,          // Authentication tokens
    session,       // Session management
    transaction,   // Transaction authorization
    consensus,     // Consensus participation
    identity,      // Identity proof
    delegation,    // Delegated authority
    
    pub fn toString(self: TokenType) []const u8 {
        return switch (self) {
            .auth => "AUTH",
            .session => "SESSION", 
            .transaction => "TX",
            .consensus => "CONSENSUS",
            .identity => "IDENTITY",
            .delegation => "DELEGATE",
        };
    }
    
    pub fn fromString(str: []const u8) ?TokenType {
        if (std.mem.eql(u8, str, "AUTH")) return .auth;
        if (std.mem.eql(u8, str, "SESSION")) return .session;
        if (std.mem.eql(u8, str, "TX")) return .transaction;
        if (std.mem.eql(u8, str, "CONSENSUS")) return .consensus;
        if (std.mem.eql(u8, str, "IDENTITY")) return .identity;
        if (std.mem.eql(u8, str, "DELEGATE")) return .delegation;
        return null;
    }
};

/// Token header containing metadata
pub const TokenHeader = struct {
    algorithm: Algorithm,
    token_type: TokenType,
    version: u8 = 1,
    key_id: ?[]const u8 = null,  // Optional key identifier
    
    pub fn encode(self: TokenHeader, allocator: std.mem.Allocator) ![]u8 {
        const header_json = std.json.stringifyAlloc(allocator, .{
            .alg = self.algorithm.toString(),
            .typ = self.token_type.toString(),
            .ver = self.version,
            .kid = self.key_id,
        }, .{}) catch return error.JsonEncodingError;
        defer allocator.free(header_json);
        
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded_len = encoder.calcSize(header_json.len);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, header_json);
        return result;
    }
    
    pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !TokenHeader {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(encoded);
        const decoded_json = try allocator.alloc(u8, decoded_len);
        defer allocator.free(decoded_json);
        try decoder.decode(decoded_json, encoded);
        
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, decoded_json, .{}) catch return error.JsonParsingError;
        defer parsed.deinit();
        
        const obj = parsed.value.object;
        
        return TokenHeader{
            .algorithm = Algorithm.fromString(obj.get("alg").?.string) orelse return error.UnsupportedAlgorithm,
            .token_type = TokenType.fromString(obj.get("typ").?.string) orelse return error.UnsupportedTokenType,
            .version = @intCast(obj.get("ver").?.integer),
            .key_id = if (obj.get("kid")) |kid| 
                if (kid == .string) try allocator.dupe(u8, kid.string) else null 
            else null,
        };
    }
};

/// Token payload with standard and custom claims
pub const TokenPayload = struct {
    // Standard claims
    issuer: ?[]const u8 = null,           // "iss" - token issuer
    subject: ?[]const u8 = null,          // "sub" - token subject  
    audience: ?[]const u8 = null,         // "aud" - intended audience
    expires_at: ?i64 = null,              // "exp" - expiration timestamp
    not_before: ?i64 = null,              // "nbf" - not valid before
    issued_at: ?i64 = null,               // "iat" - issued at timestamp
    jwt_id: ?[]const u8 = null,           // "jti" - unique token ID
    
    // GhostChain specific claims
    node_id: ?[]const u8 = null,          // Node identifier for ghostd
    wallet_id: ?[]const u8 = null,        // Wallet identifier for walletd
    identity_hash: ?[]const u8 = null,    // Identity hash for realid
    permissions: ?[]const u8 = null,      // Permissions/roles
    session_id: ?[]const u8 = null,       // Session identifier
    nonce: ?[]const u8 = null,            // Anti-replay nonce
    
    // Custom claims (JSON object)
    custom: ?std.json.Value = null,
    
    pub fn encode(self: TokenPayload, allocator: std.mem.Allocator) ![]u8 {
        var claims = std.json.ObjectMap.init(allocator);
        defer claims.deinit();
        
        // Add standard claims
        if (self.issuer) |iss| try claims.put("iss", std.json.Value{ .string = iss });
        if (self.subject) |sub| try claims.put("sub", std.json.Value{ .string = sub });
        if (self.audience) |aud| try claims.put("aud", std.json.Value{ .string = aud });
        if (self.expires_at) |exp| try claims.put("exp", std.json.Value{ .integer = exp });
        if (self.not_before) |nbf| try claims.put("nbf", std.json.Value{ .integer = nbf });
        if (self.issued_at) |iat| try claims.put("iat", std.json.Value{ .integer = iat });
        if (self.jwt_id) |jti| try claims.put("jti", std.json.Value{ .string = jti });
        
        // Add GhostChain claims
        if (self.node_id) |nid| try claims.put("ghost_node_id", std.json.Value{ .string = nid });
        if (self.wallet_id) |wid| try claims.put("ghost_wallet_id", std.json.Value{ .string = wid });
        if (self.identity_hash) |ih| try claims.put("ghost_identity_hash", std.json.Value{ .string = ih });
        if (self.permissions) |perms| try claims.put("ghost_permissions", std.json.Value{ .string = perms });
        if (self.session_id) |sid| try claims.put("ghost_session_id", std.json.Value{ .string = sid });
        if (self.nonce) |nonce| try claims.put("ghost_nonce", std.json.Value{ .string = nonce });
        
        // Add custom claims
        if (self.custom) |custom| {
            if (custom == .object) {
                var iter = custom.object.iterator();
                while (iter.next()) |entry| {
                    try claims.put(entry.key_ptr.*, entry.value_ptr.*);
                }
            }
        }
        
        const payload_json = std.json.stringifyAlloc(allocator, std.json.Value{ .object = claims }, .{}) catch return error.JsonEncodingError;
        defer allocator.free(payload_json);
        
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded_len = encoder.calcSize(payload_json.len);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, payload_json);
        return result;
    }
    
    pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !TokenPayload {
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(encoded);
        const decoded_json = try allocator.alloc(u8, decoded_len);
        defer allocator.free(decoded_json);
        try decoder.decode(decoded_json, encoded);
        
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, decoded_json, .{}) catch return error.JsonParsingError;
        defer parsed.deinit();
        
        const obj = parsed.value.object;
        
        return TokenPayload{
            .issuer = if (obj.get("iss")) |iss| try allocator.dupe(u8, iss.string) else null,
            .subject = if (obj.get("sub")) |sub| try allocator.dupe(u8, sub.string) else null,
            .audience = if (obj.get("aud")) |aud| try allocator.dupe(u8, aud.string) else null,
            .expires_at = if (obj.get("exp")) |exp| exp.integer else null,
            .not_before = if (obj.get("nbf")) |nbf| nbf.integer else null,
            .issued_at = if (obj.get("iat")) |iat| iat.integer else null,
            .jwt_id = if (obj.get("jti")) |jti| try allocator.dupe(u8, jti.string) else null,
            .node_id = if (obj.get("ghost_node_id")) |nid| try allocator.dupe(u8, nid.string) else null,
            .wallet_id = if (obj.get("ghost_wallet_id")) |wid| try allocator.dupe(u8, wid.string) else null,
            .identity_hash = if (obj.get("ghost_identity_hash")) |ih| try allocator.dupe(u8, ih.string) else null,
            .permissions = if (obj.get("ghost_permissions")) |perms| try allocator.dupe(u8, perms.string) else null,
            .session_id = if (obj.get("ghost_session_id")) |sid| try allocator.dupe(u8, sid.string) else null,
            .nonce = if (obj.get("ghost_nonce")) |nonce| try allocator.dupe(u8, nonce.string) else null,
            .custom = null, // TODO: Handle custom claims properly with current std.json API
        };
    }
    
    /// Check if token is expired
    pub fn isExpired(self: TokenPayload) bool {
        if (self.expires_at) |exp| {
            const now = std.time.timestamp();
            return now >= exp;
        }
        return false;
    }
    
    /// Check if token is valid yet (not before constraint)
    pub fn isValidYet(self: TokenPayload) bool {
        if (self.not_before) |nbf| {
            const now = std.time.timestamp();
            return now >= nbf;
        }
        return true;
    }
    
    /// Free memory from decoded payload strings
    pub fn deinitDecoded(self: TokenPayload, allocator: std.mem.Allocator) void {
        if (self.issuer) |iss| allocator.free(iss);
        if (self.subject) |sub| allocator.free(sub);
        if (self.audience) |aud| allocator.free(aud);
        if (self.jwt_id) |jti| allocator.free(jti);
        if (self.node_id) |nid| allocator.free(nid);
        if (self.wallet_id) |wid| allocator.free(wid);
        if (self.identity_hash) |ih| allocator.free(ih);
        if (self.permissions) |perms| allocator.free(perms);
        if (self.session_id) |sid| allocator.free(sid);
        if (self.nonce) |nonce| allocator.free(nonce);
    }
};

/// Complete Ghost token structure
pub const GhostToken = struct {
    header: TokenHeader,
    payload: TokenPayload,
    signature: []const u8,
    
    const Self = @This();
    
    /// Create a new Ghost token
    pub fn create(allocator: std.mem.Allocator, payload: TokenPayload, keypair: key.Keypair, algorithm: Algorithm) !Self {
        // Set current timestamp if not provided
        var mutable_payload = payload;
        if (mutable_payload.issued_at == null) {
            mutable_payload.issued_at = std.time.timestamp();
        }
        
        // Create header
        const header = TokenHeader{
            .algorithm = algorithm,
            .token_type = .auth, // Default type
        };
        
        // Encode header and payload
        const encoded_header = try header.encode(allocator);
        defer allocator.free(encoded_header);
        
        const encoded_payload = try mutable_payload.encode(allocator);
        defer allocator.free(encoded_payload);
        
        // Create signing input (header.payload)
        const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ encoded_header, encoded_payload });
        defer allocator.free(signing_input);
        
        // Sign the token
        const signature_bytes = try keypair.sign(signing_input);
        
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const sig_encoded_len = encoder.calcSize(signature_bytes.len);
        const encoded_signature = try allocator.alloc(u8, sig_encoded_len);
        _ = encoder.encode(encoded_signature, &signature_bytes);
        
        return Self{
            .header = header,
            .payload = mutable_payload,
            .signature = encoded_signature,
        };
    }
    
    /// Encode token as JWT-compatible string
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const encoded_header = try self.header.encode(allocator);
        defer allocator.free(encoded_header);
        
        const encoded_payload = try self.payload.encode(allocator);
        defer allocator.free(encoded_payload);
        
        return std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{ encoded_header, encoded_payload, self.signature });
    }
    
    /// Verify token signature and validity
    pub fn verify(allocator: std.mem.Allocator, token_string: []const u8, public_key: [32]u8) !TokenPayload {
        // Parse token parts
        var parts = std.mem.splitScalar(u8, token_string, '.');
        const encoded_header = parts.next() orelse return error.InvalidTokenFormat;
        const encoded_payload = parts.next() orelse return error.InvalidTokenFormat;
        const encoded_signature = parts.next() orelse return error.InvalidTokenFormat;
        
        if (parts.next() != null) return error.InvalidTokenFormat; // Too many parts
        
        // Decode header to get algorithm
        const header = try TokenHeader.decode(allocator, encoded_header);
        defer if (header.key_id) |kid| allocator.free(kid);
        
        // Verify signature
        const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ encoded_header, encoded_payload });
        defer allocator.free(signing_input);
        
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(encoded_signature);
        const signature_bytes = try allocator.alloc(u8, decoded_len);
        defer allocator.free(signature_bytes);
        try decoder.decode(signature_bytes, encoded_signature);
        
        if (signature_bytes.len != 64) return error.InvalidSignatureLength;
        
        const signature_array: [64]u8 = signature_bytes[0..64].*;
        const backend_alg = header.algorithm.toBackendAlgorithm();
        const is_valid = backend.verify(signing_input, signature_array, public_key, backend_alg);
        
        if (!is_valid) return error.InvalidSignature;
        
        // Decode and validate payload
        const payload = try TokenPayload.decode(allocator, encoded_payload);
        
        // Check temporal validity
        if (payload.isExpired()) return error.TokenExpired;
        if (!payload.isValidYet()) return error.TokenNotValidYet;
        
        return payload;
    }
    
    /// Refresh token with new expiration
    pub fn refresh(self: Self, allocator: std.mem.Allocator, new_expiry: i64, keypair: key.Keypair) !Self {
        var new_payload = self.payload;
        new_payload.expires_at = new_expiry;
        new_payload.issued_at = std.time.timestamp();
        
        return Self.create(allocator, new_payload, keypair, self.header.algorithm);
    }
    
    /// Clean up allocated memory
    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        // Free the signature which is allocated by the token itself
        allocator.free(self.signature);
        
        // Free any decoded payload strings (only if they were allocated during decode)
        self.payload.deinitDecoded(allocator);
    }
    
    /// Clean up memory from a freshly created token (not decoded)
    pub fn deinitCreated(self: Self, allocator: std.mem.Allocator) void {
        // Only free the signature for created tokens
        allocator.free(self.signature);
    }
    
    /// Decode a Ghost token from string format
    pub fn decode(allocator: std.mem.Allocator, token_string: []const u8) !Self {
        // Split the token by dots
        var parts = std.mem.splitScalar(u8, token_string, '.');
        const header_part = parts.next() orelse return error.InvalidTokenFormat;
        const payload_part = parts.next() orelse return error.InvalidTokenFormat;
        const signature_part = parts.next() orelse return error.InvalidTokenFormat;
        
        // Decode each part
        const header = try TokenHeader.decode(allocator, header_part);
        const payload = try TokenPayload.decode(allocator, payload_part);
        const signature = try allocator.dupe(u8, signature_part);
        
        return Self{
            .header = header,
            .payload = payload,
            .signature = signature,
        };
    }
};

/// JWT compatibility layer for standard JWT tokens
pub const JwtCompat = struct {
    /// Create standard JWT from Ghost token
    pub fn createJWT(allocator: std.mem.Allocator, claims: std.json.Value, keypair: key.Keypair) ![]u8 {
        const payload = TokenPayload{
            .custom = claims,
            .issued_at = std.time.timestamp(),
        };
        
        const token = try GhostToken.create(allocator, payload, keypair, .ed25519);
        defer token.deinit(allocator);
        
        return token.encode(allocator);
    }
    
    /// Verify standard JWT and return claims
    pub fn verifyJWT(allocator: std.mem.Allocator, jwt_string: []const u8, public_key: [32]u8) !std.json.Value {
        const payload = try GhostToken.verify(allocator, jwt_string, public_key);
        // Note: payload memory cleanup is handled by the caller
        
        return payload.custom orelse std.json.Value{ .object = std.json.ObjectMap.init(allocator) };
    }
    
    /// Convert Ghost token to standard JWT format
    pub fn convertGhostToJWT(allocator: std.mem.Allocator, ghost_token: GhostToken) ![]u8 {
        return ghost_token.encode(allocator);
    }
};

// Tests
test "Ghost token creation and verification" {
    const allocator = std.testing.allocator;
    
    // Generate test keypair
    const keypair = try backend.generateKeypair(allocator);
    
    // Create test payload
    const payload = TokenPayload{
        .issuer = "ghostd-node-1",
        .subject = "user123",
        .audience = "walletd",
        .expires_at = std.time.timestamp() + 3600, // 1 hour from now
        .node_id = "node_abc123",
        .permissions = "read,write,admin",
    };
    
    // Create token
    const token = try GhostToken.create(allocator, payload, keypair, .ed25519);
    defer token.deinit(allocator);
    
    // Encode token
    const token_string = try token.encode(allocator);
    defer allocator.free(token_string);
    
    // Verify token
    const verified_payload = try GhostToken.verify(allocator, token_string, keypair.publicKey());
    defer verified_payload.deinit(allocator);
    
    // Check claims
    try std.testing.expect(std.mem.eql(u8, verified_payload.issuer.?, "ghostd-node-1"));
    try std.testing.expect(std.mem.eql(u8, verified_payload.subject.?, "user123"));
    try std.testing.expect(std.mem.eql(u8, verified_payload.node_id.?, "node_abc123"));
}

test "Token expiration validation" {
    const allocator = std.testing.allocator;
    const keypair = try backend.generateKeypair(allocator);
    
    // Create expired token
    const expired_payload = TokenPayload{
        .subject = "test_user",
        .expires_at = std.time.timestamp() - 3600, // 1 hour ago
    };
    
    const token = try GhostToken.create(allocator, expired_payload, keypair, .ed25519);
    defer token.deinit(allocator);
    
    const token_string = try token.encode(allocator);
    defer allocator.free(token_string);
    
    // Should fail verification due to expiration
    const result = GhostToken.verify(allocator, token_string, keypair.publicKey());
    try std.testing.expectError(error.TokenExpired, result);
}

test "JWT compatibility" {
    const allocator = std.testing.allocator;
    const keypair = try backend.generateKeypair(allocator);
    
    // Create JWT-style claims
    var claims = std.json.ObjectMap.init(allocator);
    defer claims.deinit();
    
    try claims.put("user_id", std.json.Value{ .string = "12345" });
    try claims.put("role", std.json.Value{ .string = "admin" });
    
    const jwt_string = try JwtCompat.createJWT(allocator, std.json.Value{ .object = claims }, keypair);
    defer allocator.free(jwt_string);
    
    const verified_claims = try JwtCompat.verifyJWT(allocator, jwt_string, keypair.publicKey());
    defer verified_claims.deinit();
    
    try std.testing.expect(std.mem.eql(u8, verified_claims.object.get("user_id").?.string, "12345"));
}
