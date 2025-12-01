const std = @import("std");
const guardian = @import("guardian.zig");

pub const TokenError = error{
    InvalidToken,
    ExpiredToken,
    InvalidSignature,
    CryptoError,
    InvalidPrivateKey,
    SigningFailed,
    VerificationFailed,
    OutOfMemory,
    IdentityElement,
    WeakPublicKey,
    NonCanonical,
    KeyMismatch,
};

pub const KeyPair = struct {
    public_key: PublicKey,
    private_key: PrivateKey,
};

pub const PrivateKey = struct {
    bytes: [32]u8,  // Use 32 bytes for Ed25519 seed
};

pub const PublicKey = struct {
    bytes: [32]u8,
};

pub const Signature = struct {
    bytes: [64]u8,
};

pub const AccessToken = struct {
    user_id: []const u8,
    roles: std.ArrayList([]const u8),
    permissions: std.ArrayList(guardian.Permission),
    issued_at: u64,
    expires_at: u64,
    signature: Signature,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, user_id: []const u8, expires_in_seconds: u64) AccessToken {
        const now = @as(u64, @intCast((std.posix.clock_gettime(.REALTIME) catch unreachable).sec));
        return AccessToken{
            .user_id = user_id,
            .roles = std.ArrayList([]const u8){},
            .permissions = std.ArrayList(guardian.Permission){},
            .issued_at = now,
            .expires_at = now + expires_in_seconds,
            .signature = Signature{ .bytes = std.mem.zeroes([64]u8) },
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *AccessToken) void {
        self.roles.deinit(self.allocator);
        self.permissions.deinit(self.allocator);
    }
    
    pub fn addRole(self: *AccessToken, role: []const u8) !void {
        try self.roles.append(self.allocator, role);
    }
    
    pub fn addPermission(self: *AccessToken, permission: guardian.Permission) !void {
        try self.permissions.append(self.allocator, permission);
    }
    
    pub fn isExpired(self: *const AccessToken) bool {
        const now = @as(u64, @intCast((std.posix.clock_gettime(.REALTIME) catch unreachable).sec));
        return now > self.expires_at;
    }
    
    pub fn hasPermission(self: *const AccessToken, permission: guardian.Permission) bool {
        for (self.permissions.items) |perm| {
            if (perm == permission) return true;
        }
        return false;
    }
    
    pub fn sign(self: *AccessToken, private_key: PrivateKey) TokenError!void {
        // Create token payload for signing
        var payload = std.ArrayList(u8){};
        defer payload.deinit(self.allocator);
        
        try payload.appendSlice(self.allocator, self.user_id);
        var issued_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &issued_bytes, self.issued_at, .little);
        try payload.appendSlice(self.allocator, &issued_bytes);
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        try payload.appendSlice(self.allocator, &expires_bytes);
        
        // Add roles to payload
        for (self.roles.items) |role| {
            try payload.appendSlice(self.allocator, role);
        }
        
        // Use Ed25519 to sign
        const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(private_key.bytes) catch return TokenError.CryptoError;
        const signature = try keypair.sign(payload.items, null);
        self.signature.bytes = signature.toBytes();
    }
    
    pub fn verify(self: *const AccessToken, public_key: PublicKey) bool {
        // Recreate payload for verification
        var payload = std.ArrayList(u8){};
        defer payload.deinit(self.allocator);
        
        payload.appendSlice(self.allocator, self.user_id) catch return false;
        var issued_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &issued_bytes, self.issued_at, .little);
        payload.appendSlice(self.allocator, &issued_bytes) catch return false;
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        payload.appendSlice(self.allocator, &expires_bytes) catch return false;
        
        // Add roles to payload
        for (self.roles.items) |role| {
            payload.appendSlice(self.allocator, role) catch return false;
        }
        
        // Verify signature using Ed25519
        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.bytes) catch return false;
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(self.signature.bytes);
        
        sig.verify(payload.items, pub_key) catch return false;
        return true;
    }
};

/// Generate a new Ed25519 keypair from a passphrase
pub fn generateKeyPair(passphrase: []const u8) TokenError!KeyPair {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(passphrase);
    var seed: [32]u8 = undefined;
    hasher.final(&seed);
    
    // Generate Ed25519 keypair from seed
    const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return TokenError.CryptoError;
    
    return KeyPair{
        .public_key = PublicKey{ .bytes = keypair.public_key.bytes },
        .private_key = PrivateKey{ .bytes = seed },
    };
}

/// Generate an ephemeral keypair (random)
pub fn generateEphemeralKeyPair() TokenError!KeyPair {
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    
    const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return TokenError.CryptoError;
    
    return KeyPair{
        .public_key = PublicKey{ .bytes = keypair.public_key.bytes },
        .private_key = PrivateKey{ .bytes = seed },
    };
}

/// Sign arbitrary data
pub fn signData(data: []const u8, private_key: PrivateKey) TokenError!Signature {
    const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(private_key.bytes) catch return TokenError.CryptoError;
    const signature = try keypair.sign(data, null);
    return Signature{ .bytes = signature.toBytes() };
}

/// Verify signature against data and public key
pub fn verifyData(signature: Signature, data: []const u8, public_key: PublicKey) bool {
    const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.bytes) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature.bytes);
    
    sig.verify(data, pub_key) catch return false;
    return true;
}

pub fn version() []const u8 {
    return "0.1.0";
}