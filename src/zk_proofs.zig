//! Zero-Knowledge Proof System for SHROUD
//! Advanced privacy-preserving identity verification and selective disclosure

const std = @import("std");
const identity = @import("identity.zig");
const advanced_tokens = @import("advanced_tokens.zig");
const time_utils = @import("time_utils.zig");

/// Zero-Knowledge Proof types supported
pub const ZKProofType = enum {
    identity_verification,
    permission_validation,
    age_verification,
    attribute_proof,
    membership_proof,
};

/// Zero-Knowledge Proof structure
pub const ZKProof = struct {
    proof_type: ZKProofType,
    proof_data: []const u8,
    verification_key: []const u8,
    timestamp: i64,
    expires_at: ?i64,
    metadata: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, proof_type: ZKProofType) ZKProof {
        return ZKProof{
            .proof_type = proof_type,
            .proof_data = &[_]u8{},
            .verification_key = &[_]u8{},
            .timestamp = time_utils.milliTimestamp(),
            .expires_at = null,
            .metadata = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ZKProof) void {
        if (self.proof_data.len > 0) {
            self.allocator.free(self.proof_data);
        }
        if (self.verification_key.len > 0) {
            self.allocator.free(self.verification_key);
        }
        self.metadata.deinit();
    }

    pub fn setProofData(self: *ZKProof, data: []const u8) !void {
        if (self.proof_data.len > 0) {
            self.allocator.free(self.proof_data);
        }
        self.proof_data = try self.allocator.dupe(u8, data);
    }

    pub fn setVerificationKey(self: *ZKProof, key: []const u8) !void {
        if (self.verification_key.len > 0) {
            self.allocator.free(self.verification_key);
        }
        self.verification_key = try self.allocator.dupe(u8, key);
    }

    pub fn addMetadata(self: *ZKProof, key: []const u8, value: []const u8) !void {
        try self.metadata.put(key, value);
    }

    pub fn isExpired(self: *const ZKProof) bool {
        if (self.expires_at) |expiry| {
            return time_utils.milliTimestamp() > expiry;
        }
        return false;
    }
};

/// Selective disclosure request - choose which attributes to reveal
pub const SelectiveDisclosureRequest = struct {
    attributes_to_disclose: std.ArrayList([]const u8),
    proof_purpose: []const u8,
    verifier_did: []const u8,
    challenge: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, verifier_did: []const u8, purpose: []const u8) SelectiveDisclosureRequest {
        return SelectiveDisclosureRequest{
            .attributes_to_disclose = std.ArrayList([]const u8){},
            .proof_purpose = purpose,
            .verifier_did = verifier_did,
            .challenge = &[_]u8{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SelectiveDisclosureRequest) void {
        self.attributes_to_disclose.deinit(self.allocator);
        if (self.challenge.len > 0) {
            self.allocator.free(self.challenge);
        }
    }

    pub fn addAttribute(self: *SelectiveDisclosureRequest, attribute: []const u8) !void {
        try self.attributes_to_disclose.append(self.allocator, attribute);
    }

    pub fn setChallenge(self: *SelectiveDisclosureRequest, challenge: []const u8) !void {
        if (self.challenge.len > 0) {
            self.allocator.free(self.challenge);
        }
        self.challenge = try self.allocator.dupe(u8, challenge);
    }
};

/// Anonymous credential for privacy-preserving authentication
pub const AnonymousCredential = struct {
    credential_id: []const u8,
    issuer_did: []const u8,
    schema_id: []const u8,
    claims: std.HashMap([]const u8, ClaimValue, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    signature: []const u8,
    revocation_id: ?[]const u8,
    issued_at: i64,
    expires_at: ?i64,
    allocator: std.mem.Allocator,

    pub const ClaimValue = union(enum) {
        string: []const u8,
        number: i64,
        boolean: bool,
        binary: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, credential_id: []const u8, issuer_did: []const u8, schema_id: []const u8) AnonymousCredential {
        return AnonymousCredential{
            .credential_id = credential_id,
            .issuer_did = issuer_did,
            .schema_id = schema_id,
            .claims = std.HashMap([]const u8, ClaimValue, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .signature = &[_]u8{},
            .revocation_id = null,
            .issued_at = time_utils.milliTimestamp(),
            .expires_at = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AnonymousCredential) void {
        if (self.signature.len > 0) {
            self.allocator.free(self.signature);
        }
        var iterator = self.claims.iterator();
        while (iterator.next()) |entry| {
            switch (entry.value_ptr.*) {
                .binary => |data| self.allocator.free(data),
                else => {},
            }
        }
        self.claims.deinit();
    }

    pub fn addClaim(self: *AnonymousCredential, claim_name: []const u8, value: ClaimValue) !void {
        try self.claims.put(claim_name, value);
    }

    pub fn setSignature(self: *AnonymousCredential, signature: []const u8) !void {
        if (self.signature.len > 0) {
            self.allocator.free(self.signature);
        }
        self.signature = try self.allocator.dupe(u8, signature);
    }

    pub fn isExpired(self: *const AnonymousCredential) bool {
        if (self.expires_at) |expiry| {
            return time_utils.milliTimestamp() > expiry;
        }
        return false;
    }

    pub fn isRevoked(self: *const AnonymousCredential) bool {
        // Simplified revocation check - in production, check against revocation list
        _ = self;
        return false;
    }
};

/// Zero-Knowledge Proof System
pub const ZKProofSystem = struct {
    public_params: []const u8,
    trusted_setup: bool,
    curve_params: CurveParameters,
    allocator: std.mem.Allocator,

    pub const CurveParameters = struct {
        curve_name: []const u8,
        generator: [32]u8,
        order: [32]u8,
    };

    pub fn init(allocator: std.mem.Allocator) ZKProofSystem {
        return ZKProofSystem{
            .public_params = &[_]u8{},
            .trusted_setup = false,
            .curve_params = CurveParameters{
                .curve_name = "BLS12-381",
                .generator = [_]u8{1} ** 32,
                .order = [_]u8{0xFF} ** 32,
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ZKProofSystem) void {
        if (self.public_params.len > 0) {
            self.allocator.free(self.public_params);
        }
    }

    /// Generate a zero-knowledge proof for identity verification
    pub fn generateIdentityProof(self: *ZKProofSystem, identity_did: []const u8, challenge: []const u8) !ZKProof {
        _ = identity_did;
        _ = challenge;

        var proof = ZKProof.init(self.allocator, .identity_verification);

        // Simplified proof generation - in production, use proper ZK-SNARK/STARK
        const proof_bytes = "identity_proof_placeholder_data";
        try proof.setProofData(proof_bytes);

        const verification_key = "verification_key_placeholder";
        try proof.setVerificationKey(verification_key);

        try proof.addMetadata("curve", self.curve_params.curve_name);
        try proof.addMetadata("proof_system", "groth16");

        // Set expiration to 1 hour
        proof.expires_at = time_utils.milliTimestamp() + (60 * 60 * 1000);

        return proof;
    }

    /// Generate proof for permission validation without revealing full token
    pub fn generatePermissionProof(self: *ZKProofSystem, token: *const advanced_tokens.AdvancedAccessToken, required_permission: []const u8) !ZKProof {
        _ = token;
        _ = required_permission;

        var proof = ZKProof.init(self.allocator, .permission_validation);

        // Simplified permission proof - proves you have permission without revealing token
        const proof_bytes = "permission_proof_placeholder_data";
        try proof.setProofData(proof_bytes);

        const verification_key = "permission_verification_key";
        try proof.setVerificationKey(verification_key);

        try proof.addMetadata("permission_type", "hierarchical");
        try proof.addMetadata("proof_method", "bulletproof");

        proof.expires_at = time_utils.milliTimestamp() + (30 * 60 * 1000); // 30 minutes

        return proof;
    }

    /// Generate age verification proof without revealing exact age
    pub fn generateAgeProof(self: *ZKProofSystem, birth_timestamp: i64, minimum_age: u32) !ZKProof {
        var proof = ZKProof.init(self.allocator, .age_verification);

        const current_time = time_utils.milliTimestamp();
        const age_seconds = current_time - birth_timestamp;
        const age_years = @divTrunc(age_seconds, (365 * 24 * 60 * 60 * 1000));

        // Create proof that age >= minimum_age without revealing exact age
        if (age_years >= minimum_age) {
            const proof_bytes = "age_verification_proof_valid";
            try proof.setProofData(proof_bytes);

            const verification_key = "age_verification_key";
            try proof.setVerificationKey(verification_key);

            try proof.addMetadata("minimum_age_met", "true");
            try proof.addMetadata("proof_type", "range_proof");
        } else {
            return error.AgeRequirementNotMet;
        }

        proof.expires_at = time_utils.milliTimestamp() + (24 * 60 * 60 * 1000); // 24 hours

        return proof;
    }

    /// Verify a zero-knowledge proof
    pub fn verifyProof(self: *ZKProofSystem, proof: *const ZKProof, challenge: []const u8) bool {
        _ = self;
        _ = challenge;

        // Check if proof is expired
        if (proof.isExpired()) {
            return false;
        }

        // Check if we have valid proof data and verification key
        if (proof.proof_data.len == 0 or proof.verification_key.len == 0) {
            return false;
        }

        // Simplified verification - in production, use proper cryptographic verification
        switch (proof.proof_type) {
            .identity_verification => {
                return std.mem.eql(u8, proof.proof_data, "identity_proof_placeholder_data");
            },
            .permission_validation => {
                return std.mem.eql(u8, proof.proof_data, "permission_proof_placeholder_data");
            },
            .age_verification => {
                return std.mem.eql(u8, proof.proof_data, "age_verification_proof_valid");
            },
            .attribute_proof => {
                return proof.proof_data.len > 0;
            },
            .membership_proof => {
                return proof.proof_data.len > 0;
            },
        }
    }

    /// Create selective disclosure proof
    pub fn createSelectiveDisclosure(self: *ZKProofSystem, identity_claims: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage), request: *const SelectiveDisclosureRequest) !ZKProof {
        var proof = ZKProof.init(self.allocator, .attribute_proof);

        // Create proof that includes only requested attributes
        var disclosed_data = std.ArrayList(u8){};
        defer disclosed_data.deinit(self.allocator);

        for (request.attributes_to_disclose.items) |attribute| {
            if (identity_claims.get(attribute)) |value| {
                try disclosed_data.appendSlice(self.allocator, attribute);
                try disclosed_data.append(self.allocator, ':');
                try disclosed_data.appendSlice(self.allocator, value);
                try disclosed_data.append(self.allocator, ';');
            }
        }

        try proof.setProofData(disclosed_data.items);

        const verification_key = "selective_disclosure_key";
        try proof.setVerificationKey(verification_key);

        try proof.addMetadata("purpose", request.proof_purpose);
        try proof.addMetadata("verifier", request.verifier_did);

        // Use a fixed buffer instead of allocPrint to avoid memory leak
        var count_buf: [16]u8 = undefined;
        const count_str = try std.fmt.bufPrint(&count_buf, "{}", .{request.attributes_to_disclose.items.len});
        try proof.addMetadata("attribute_count", count_str);

        proof.expires_at = time_utils.milliTimestamp() + (60 * 60 * 1000); // 1 hour

        return proof;
    }

    /// Issue an anonymous credential
    pub fn issueAnonymousCredential(self: *ZKProofSystem, issuer_did: []const u8, schema_id: []const u8, claims: std.HashMap([]const u8, AnonymousCredential.ClaimValue, std.hash_map.StringContext, std.hash_map.default_max_load_percentage)) !AnonymousCredential {
        // Generate unique credential ID
        var credential_id_buf: [64]u8 = undefined;
        const credential_id = try std.fmt.bufPrint(&credential_id_buf, "anon_cred_{}", .{time_utils.milliTimestamp()});

        var credential = AnonymousCredential.init(self.allocator, credential_id, issuer_did, schema_id);

        // Copy claims
        var iterator = claims.iterator();
        while (iterator.next()) |entry| {
            try credential.addClaim(entry.key_ptr.*, entry.value_ptr.*);
        }

        // Generate signature (simplified - in production, use proper blind signature)
        const signature = "anonymous_credential_signature_placeholder";
        try credential.setSignature(signature);

        // Set expiration to 1 year
        credential.expires_at = time_utils.milliTimestamp() + (365 * 24 * 60 * 60 * 1000);

        return credential;
    }

    /// Verify an anonymous credential without revealing identity
    pub fn verifyAnonymousCredential(self: *ZKProofSystem, credential: *const AnonymousCredential, required_claims: []const []const u8) bool {
        _ = self;

        // Check if credential is expired or revoked
        if (credential.isExpired() or credential.isRevoked()) {
            return false;
        }

        // Check if credential has all required claims
        for (required_claims) |required_claim| {
            if (!credential.claims.contains(required_claim)) {
                return false;
            }
        }

        // Simplified signature verification
        return std.mem.eql(u8, credential.signature, "anonymous_credential_signature_placeholder");
    }
};

test "ZK proof generation and verification" {
    var zk_system = ZKProofSystem.init(std.testing.allocator);
    defer zk_system.deinit();

    // Generate identity proof
    var identity_proof = try zk_system.generateIdentityProof("did:shroud:alice", "challenge123");
    defer identity_proof.deinit();

    // Verify proof
    const is_valid = zk_system.verifyProof(&identity_proof, "challenge123");
    try std.testing.expect(is_valid);
    try std.testing.expect(identity_proof.proof_type == .identity_verification);
}

test "selective disclosure" {
    var zk_system = ZKProofSystem.init(std.testing.allocator);
    defer zk_system.deinit();

    // Create identity claims
    var claims = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(std.testing.allocator);
    defer claims.deinit();
    try claims.put("name", "Alice");
    try claims.put("age", "25");
    try claims.put("country", "USA");

    // Create selective disclosure request
    var request = SelectiveDisclosureRequest.init(std.testing.allocator, "did:shroud:verifier", "age_verification");
    defer request.deinit();
    try request.addAttribute("age");
    try request.addAttribute("country");

    // Generate selective disclosure proof
    var disclosure_proof = try zk_system.createSelectiveDisclosure(claims, &request);
    defer disclosure_proof.deinit();

    try std.testing.expect(disclosure_proof.proof_type == .attribute_proof);
    try std.testing.expect(disclosure_proof.proof_data.len > 0);
}

test "anonymous credentials" {
    var zk_system = ZKProofSystem.init(std.testing.allocator);
    defer zk_system.deinit();

    // Create claims for anonymous credential
    var claims = std.HashMap([]const u8, AnonymousCredential.ClaimValue, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(std.testing.allocator);
    defer claims.deinit();
    try claims.put("age_over_18", .{ .boolean = true });
    try claims.put("country", .{ .string = "USA" });

    // Issue anonymous credential
    var credential = try zk_system.issueAnonymousCredential("did:shroud:issuer", "age_verification_schema", claims);
    defer credential.deinit();

    // Verify credential
    const required_claims = [_][]const u8{"age_over_18"};
    const is_valid = zk_system.verifyAnonymousCredential(&credential, &required_claims);
    try std.testing.expect(is_valid);
}

test "age verification proof" {
    var zk_system = ZKProofSystem.init(std.testing.allocator);
    defer zk_system.deinit();

    // Birth timestamp for someone born 25 years ago
    const birth_timestamp = time_utils.milliTimestamp() - (25 * 365 * 24 * 60 * 60 * 1000);

    // Generate age proof for 18+ verification
    var age_proof = try zk_system.generateAgeProof(birth_timestamp, 18);
    defer age_proof.deinit();

    // Verify proof
    const is_valid = zk_system.verifyProof(&age_proof, "age_challenge");
    try std.testing.expect(is_valid);
    try std.testing.expect(age_proof.proof_type == .age_verification);
}
