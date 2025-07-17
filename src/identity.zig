const std = @import("std");
const guardian = @import("guardian.zig");
const access_token = @import("access_token.zig");
const qid = @import("qid.zig");

// Constants for passphrase-based key derivation
const PBKDF2_ITERATIONS = 100000;
const SALT_PREFIX = "SHROUD-v1";

pub const IdentityError = error{
    InvalidIdentity,
    ResolutionFailed,
    AuthenticationFailed,
    TokenExpired,
    AccessDenied,
    InvalidDelegation,
    InvalidPassphrase,
    CryptoError,
    OutOfMemory,
    BufferTooSmall,
    NoSpaceLeft,
};

/// Options for identity generation
pub const IdentityGenerationOptions = struct {
    passphrase: ?[]const u8 = null,
    device_binding: bool = false,
    hsm_provider: ?HSMProvider = null,
};

/// HSM Provider configuration (Azure Key Vault support)
pub const HSMProvider = struct {
    provider_type: HSMType,
    config: HSMConfig,

    pub const HSMType = enum {
        azure_key_vault,
        // Future: hardware_security_module, aws_kms, etc.
    };

    pub const HSMConfig = union(HSMType) {
        azure_key_vault: AzureKeyVaultConfig,
    };

    pub const AzureKeyVaultConfig = struct {
        vault_url: []const u8,
        client_id: []const u8,
        tenant_id: []const u8,
        key_name: []const u8,
    };
};

/// Keypair for SHROUD identity
pub const IdentityKeyPair = struct {
    private_key: [64]u8, // Ed25519 private key
    public_key: [32]u8, // Ed25519 public key
    qid: qid.QID, // IPv6 QID derived from public key
};

pub const Identity = struct {
    id: []const u8,
    public_key: access_token.PublicKey,
    roles: std.ArrayList([]const u8),
    metadata: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    delegations: std.ArrayList(Delegation),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, id: []const u8, public_key: access_token.PublicKey) Identity {
        return Identity{
            .id = id,
            .public_key = public_key,
            .roles = std.ArrayList([]const u8).init(allocator),
            .metadata = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .delegations = std.ArrayList(Delegation).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Identity) void {
        self.roles.deinit();
        self.metadata.deinit();
        for (self.delegations.items) |*delegation| {
            delegation.deinit();
        }
        self.delegations.deinit();
    }

    pub fn addRole(self: *Identity, role: []const u8) !void {
        try self.roles.append(role);
    }

    pub fn hasRole(self: *const Identity, role: []const u8) bool {
        for (self.roles.items) |r| {
            if (std.mem.eql(u8, r, role)) return true;
        }
        return false;
    }

    pub fn setMetadata(self: *Identity, key: []const u8, value: []const u8) !void {
        try self.metadata.put(key, value);
    }

    pub fn getMetadata(self: *const Identity, key: []const u8) ?[]const u8 {
        return self.metadata.get(key);
    }

    pub fn addDelegation(self: *Identity, delegation: Delegation) !void {
        try self.delegations.append(delegation);
    }

    pub fn createAccessToken(self: *const Identity, expires_in_seconds: u64, private_key: access_token.PrivateKey) !access_token.AccessToken {
        var token = access_token.AccessToken.init(self.allocator, self.id, expires_in_seconds);

        // Add roles to token
        for (self.roles.items) |role| {
            try token.addRole(role);
        }

        // Sign the token
        try token.sign(private_key);

        return token;
    }

    /// Generate QID for this identity
    pub fn generateQID(self: *const Identity) qid.QID {
        return qid.QID.fromPublicKey(self.public_key.bytes[0..32]);
    }
};

/// Generate identity keypair from passphrase (RealID legacy pattern)
pub fn generateIdentityFromPassphrase(passphrase: []const u8) IdentityError!IdentityKeyPair {
    if (passphrase.len == 0) {
        return IdentityError.InvalidPassphrase;
    }

    // Create salt from passphrase and prefix using SHA-256
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(SALT_PREFIX);
    hasher.update(passphrase);
    const salt = hasher.finalResult();

    // Derive key material using PBKDF2-SHA256
    var key_material: [64]u8 = undefined;
    std.crypto.pwhash.pbkdf2(&key_material, passphrase, &salt, PBKDF2_ITERATIONS, std.crypto.auth.hmac.sha2.HmacSha256) catch {
        return IdentityError.CryptoError;
    };

    // Create Ed25519 keypair from seed
    const seed = key_material[0..32].*;
    const keypair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
        return IdentityError.CryptoError;
    };

    // Generate QID from public key
    const identity_qid = qid.QID.fromPublicKey(&keypair.public_key.bytes);

    return IdentityKeyPair{
        .private_key = keypair.secret_key.bytes,
        .public_key = keypair.public_key.bytes,
        .qid = identity_qid,
    };
}

/// Generate identity using options (passphrase, HSM, etc.)
pub fn generateIdentity(allocator: std.mem.Allocator, options: IdentityGenerationOptions) IdentityError!Identity {
    var keypair: IdentityKeyPair = undefined;

    if (options.passphrase) |passphrase| {
        // Generate from passphrase
        keypair = try generateIdentityFromPassphrase(passphrase);
    } else if (options.hsm_provider) |hsm| {
        // Generate using HSM
        keypair = try generateIdentityFromHSM(hsm);
    } else {
        // Generate random keypair
        keypair = try generateRandomIdentity();
    }

    // Create identity with generated public key
    const public_key = access_token.PublicKey{ .bytes = keypair.public_key };

    // Use QID as identity ID for now (can be enhanced later)
    var qid_buffer: [40]u8 = undefined;
    const qid_str = try keypair.qid.toString(&qid_buffer);
    const identity_id = try allocator.dupe(u8, qid_str);

    var identity = Identity.init(allocator, identity_id, public_key);

    // Add QID as metadata
    try identity.setMetadata("qid", qid_str);
    try identity.setMetadata("generation_method", if (options.passphrase != null) "passphrase" else "random");

    return identity;
}

/// Generate identity from HSM (Azure Key Vault support)
fn generateIdentityFromHSM(hsm: HSMProvider) IdentityError!IdentityKeyPair {
    switch (hsm.provider_type) {
        .azure_key_vault => {
            // TODO: Implement Azure Key Vault integration
            // For now, return error as placeholder
            return IdentityError.CryptoError;
        },
    }
}

/// Generate random identity keypair
fn generateRandomIdentity() IdentityError!IdentityKeyPair {
    const keypair = std.crypto.sign.Ed25519.KeyPair.generate();

    const identity_qid = qid.QID.fromPublicKey(&keypair.public_key.bytes);

    return IdentityKeyPair{
        .private_key = keypair.secret_key.bytes,
        .public_key = keypair.public_key.bytes,
        .qid = identity_qid,
    };
}

pub const Delegation = struct {
    delegator: []const u8,
    delegate: []const u8,
    permissions: std.ArrayList(guardian.Permission),
    resource_pattern: []const u8,
    expires_at: u64,
    signature: access_token.Signature,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, delegator: []const u8, delegate: []const u8, resource_pattern: []const u8, expires_in_seconds: u64) Delegation {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return Delegation{
            .delegator = delegator,
            .delegate = delegate,
            .permissions = std.ArrayList(guardian.Permission).init(allocator),
            .resource_pattern = resource_pattern,
            .expires_at = now + expires_in_seconds,
            .signature = access_token.Signature{ .bytes = std.mem.zeroes([64]u8) },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Delegation) void {
        self.permissions.deinit();
    }

    pub fn addPermission(self: *Delegation, permission: guardian.Permission) !void {
        try self.permissions.append(permission);
    }

    pub fn isExpired(self: *const Delegation) bool {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now > self.expires_at;
    }

    pub fn hasPermission(self: *const Delegation, permission: guardian.Permission) bool {
        for (self.permissions.items) |perm| {
            if (perm == permission) return true;
        }
        return false;
    }

    pub fn sign(self: *Delegation, private_key: access_token.PrivateKey) !void {
        // Create delegation payload for signing
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();

        try payload.appendSlice(self.delegator);
        try payload.appendSlice(self.delegate);
        try payload.appendSlice(self.resource_pattern);
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        try payload.appendSlice(&expires_bytes);

        // Add permissions to payload
        for (self.permissions.items) |perm| {
            try payload.appendSlice(perm.toString());
        }

        self.signature = try access_token.signData(payload.items, private_key);
    }

    pub fn verify(self: *const Delegation, public_key: access_token.PublicKey) bool {
        // Recreate payload for verification
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();

        payload.appendSlice(self.delegator) catch return false;
        payload.appendSlice(self.delegate) catch return false;
        payload.appendSlice(self.resource_pattern) catch return false;
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        payload.appendSlice(&expires_bytes) catch return false;

        // Add permissions to payload
        for (self.permissions.items) |perm| {
            payload.appendSlice(perm.toString()) catch return false;
        }

        return access_token.verifyData(self.signature, payload.items, public_key);
    }
};

pub const IdentityManager = struct {
    identities: std.HashMap([]const u8, Identity, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    guardian: guardian.Guardian,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) IdentityManager {
        return IdentityManager{
            .identities = std.HashMap([]const u8, Identity, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .guardian = guardian.Guardian.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *IdentityManager) void {
        var identity_iter = self.identities.iterator();
        while (identity_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.identities.deinit();
        self.guardian.deinit();
    }

    pub fn createIdentity(self: *IdentityManager, id: []const u8, public_key: access_token.PublicKey) !void {
        const identity = Identity.init(self.allocator, id, public_key);
        try self.identities.put(id, identity);
    }

    pub fn getIdentity(self: *IdentityManager, id: []const u8) ?*Identity {
        return self.identities.getPtr(id);
    }

    pub fn authenticate(self: *IdentityManager, token: *const access_token.AccessToken, public_key: access_token.PublicKey) IdentityError!*Identity {
        // Verify token signature
        if (!token.verify(public_key)) {
            return IdentityError.AuthenticationFailed;
        }

        // Check if token is expired
        if (token.isExpired()) {
            return IdentityError.TokenExpired;
        }

        // Get identity
        const identity = self.getIdentity(token.user_id) orelse {
            return IdentityError.InvalidIdentity;
        };

        return identity;
    }

    pub fn authorize(self: *IdentityManager, identity: *const Identity, resource: []const u8, permission: guardian.Permission) IdentityError!bool {
        // Create access context
        var context = guardian.AccessContext.init(self.allocator, identity.id, resource, permission);
        defer context.deinit();

        // Add identity roles to context
        for (identity.roles.items) |role| {
            try context.addRole(role);
        }

        // Check direct permissions
        const direct_access = self.guardian.canAccess(&context) catch false;
        if (direct_access) return true;

        // Check delegated permissions
        for (identity.delegations.items) |delegation| {
            if (delegation.isExpired()) continue;
            if (!delegation.hasPermission(permission)) continue;

            // Simple pattern matching for resource
            if (std.mem.eql(u8, delegation.resource_pattern, "*") or
                std.mem.eql(u8, delegation.resource_pattern, resource) or
                (std.mem.endsWith(u8, delegation.resource_pattern, "*") and
                    std.mem.startsWith(u8, resource, delegation.resource_pattern[0 .. delegation.resource_pattern.len - 1])))
            {
                return true;
            }
        }

        return false;
    }

    pub fn createDelegation(self: *IdentityManager, delegator_id: []const u8, delegate_id: []const u8, resource_pattern: []const u8, permissions: []const guardian.Permission, expires_in_seconds: u64, private_key: access_token.PrivateKey) !void {
        // Verify delegator exists
        if (self.getIdentity(delegator_id) == null) {
            return IdentityError.InvalidIdentity;
        }

        // Get delegate identity
        const delegate = self.getIdentity(delegate_id) orelse {
            return IdentityError.InvalidIdentity;
        };

        // Create delegation
        var delegation = Delegation.init(self.allocator, delegator_id, delegate_id, resource_pattern, expires_in_seconds);

        // Add permissions
        for (permissions) |perm| {
            try delegation.addPermission(perm);
        }

        // Sign delegation
        try delegation.sign(private_key);

        // Add to delegate's delegations
        try delegate.addDelegation(delegation);
    }
};

pub fn version() []const u8 {
    return "0.1.0";
}
