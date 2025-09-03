const std = @import("std");
const identity = @import("identity.zig");
const access_token = @import("access_token.zig");
const guardian = @import("guardian.zig");
const zk_proof = @import("zk_proof.zig");

pub const CrossChainError = error{
    ChainNotSupported,
    ResolutionFailed,
    InvalidDID,
    NetworkError,
    InvalidProof,
    ChainMismatch,
    OutOfMemory,
    TimeoutError,
};

pub const ChainType = enum {
    ethereum,
    polygon,
    solana,
    ghostchain,
    keystone,
    bitcoin,
    cosmos,
    polkadot,
    
    pub fn toString(self: ChainType) []const u8 {
        return switch (self) {
            .ethereum => "ethereum",
            .polygon => "polygon",
            .solana => "solana",
            .ghostchain => "ghostchain",
            .keystone => "keystone",
            .bitcoin => "bitcoin",
            .cosmos => "cosmos",
            .polkadot => "polkadot",
        };
    }
    
    pub fn fromString(chain_str: []const u8) ?ChainType {
        if (std.mem.eql(u8, chain_str, "ethereum")) return .ethereum;
        if (std.mem.eql(u8, chain_str, "polygon")) return .polygon;
        if (std.mem.eql(u8, chain_str, "solana")) return .solana;
        if (std.mem.eql(u8, chain_str, "ghostchain")) return .ghostchain;
        if (std.mem.eql(u8, chain_str, "keystone")) return .keystone;
        if (std.mem.eql(u8, chain_str, "bitcoin")) return .bitcoin;
        if (std.mem.eql(u8, chain_str, "cosmos")) return .cosmos;
        if (std.mem.eql(u8, chain_str, "polkadot")) return .polkadot;
        return null;
    }
};

pub const DID = struct {
    method: []const u8,
    chain: ChainType,
    identifier: []const u8,
    
    pub fn parse(did_string: []const u8) CrossChainError!DID {
        // Parse DID format: did:method:chain:identifier
        var parts = std.mem.split(u8, did_string, ":");
        
        if (!std.mem.eql(u8, parts.next() orelse return CrossChainError.InvalidDID, "did")) {
            return CrossChainError.InvalidDID;
        }
        
        const method = parts.next() orelse return CrossChainError.InvalidDID;
        const chain_str = parts.next() orelse return CrossChainError.InvalidDID;
        const identifier = parts.next() orelse return CrossChainError.InvalidDID;
        
        const chain = ChainType.fromString(chain_str) orelse return CrossChainError.InvalidDID;
        
        return DID{
            .method = method,
            .chain = chain,
            .identifier = identifier,
        };
    }
    
    pub fn toString(self: *const DID, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "did:{s}:{s}:{s}", .{ self.method, self.chain.toString(), self.identifier });
    }
};

pub const CrossChainIdentity = struct {
    primary_did: DID,
    anchored_chains: std.HashMap(ChainType, ChainAnchor, std.hash_map.AutoContext(ChainType), std.hash_map.default_max_load_percentage),
    verifiable_credentials: std.ArrayList(VerifiableCredential),
    cross_chain_proofs: std.ArrayList(CrossChainProof),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, primary_did: DID) CrossChainIdentity {
        return CrossChainIdentity{
            .primary_did = primary_did,
            .anchored_chains = std.HashMap(ChainType, ChainAnchor, std.hash_map.AutoContext(ChainType), std.hash_map.default_max_load_percentage).init(allocator),
            .verifiable_credentials = std.ArrayList(VerifiableCredential){},
            .cross_chain_proofs = std.ArrayList(CrossChainProof){},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *CrossChainIdentity) void {
        var anchor_iter = self.anchored_chains.iterator();
        while (anchor_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.anchored_chains.deinit();
        
        for (self.verifiable_credentials.items) |*cred| {
            cred.deinit();
        }
        self.verifiable_credentials.deinit(self.allocator);
        
        for (self.cross_chain_proofs.items) |*proof| {
            proof.deinit();
        }
        self.cross_chain_proofs.deinit(self.allocator);
    }
    
    pub fn anchorToChain(self: *CrossChainIdentity, chain: ChainType, address: []const u8, proof: []const u8) !void {
        const anchor = ChainAnchor.init(self.allocator, chain, address, proof);
        try self.anchored_chains.put(chain, anchor);
    }
    
    pub fn addVerifiableCredential(self: *CrossChainIdentity, credential: VerifiableCredential) !void {
        try self.verifiable_credentials.append(self.allocator, credential);
    }
    
    pub fn createCrossChainProof(self: *CrossChainIdentity, target_chain: ChainType, proof_system: *zk_proof.ZkProofSystem) !CrossChainProof {
        // Create witness for cross-chain identity proof
        const primary_did_str = try self.primary_did.toString(self.allocator);
        defer self.allocator.free(primary_did_str);
        
        var witness = zk_proof.ZkWitness.init(self.allocator, primary_did_str);
        defer witness.deinit();
        
        // Add chain anchors as private inputs
        var anchor_iter = self.anchored_chains.iterator();
        while (anchor_iter.next()) |entry| {
            try witness.addPrivateInput(entry.value_ptr.address);
            try witness.addPrivateInput(entry.value_ptr.proof);
        }
        
        var public_inputs = zk_proof.ZkPublicInputs.init(.identity_verification);
        
        // Generate cross-chain proof
        const zk_proof_data = try proof_system.generateProof(.identity_verification, &witness, &public_inputs);
        
        return CrossChainProof{
            .source_chain = self.primary_did.chain,
            .target_chain = target_chain,
            .proof = zk_proof_data,
            .allocator = self.allocator,
        };
    }
    
    pub fn verifyOnChain(self: *const CrossChainIdentity, chain: ChainType) bool {
        return self.anchored_chains.contains(chain);
    }
};

pub const ChainAnchor = struct {
    chain: ChainType,
    address: []const u8,
    proof: []const u8,
    timestamp: u64,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, chain: ChainType, address: []const u8, proof: []const u8) ChainAnchor {
        return ChainAnchor{
            .chain = chain,
            .address = address,
            .proof = proof,
            .timestamp = @intCast(std.time.timestamp()),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ChainAnchor) void {
        _ = self;
        // Note: address and proof are typically string literals or managed elsewhere
    }
    
    pub fn isValid(self: *const ChainAnchor) bool {
        // Simple validation - check if address and proof are non-empty
        return self.address.len > 0 and self.proof.len > 0;
    }
};

pub const VerifiableCredential = struct {
    id: []const u8,
    issuer: DID,
    subject: DID,
    credential_type: []const u8,
    claims: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    issued_at: u64,
    expires_at: u64,
    proof: access_token.Signature,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, id: []const u8, issuer: DID, subject: DID, credential_type: []const u8, expires_in_seconds: u64) VerifiableCredential {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return VerifiableCredential{
            .id = id,
            .issuer = issuer,
            .subject = subject,
            .credential_type = credential_type,
            .claims = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .issued_at = now,
            .expires_at = now + expires_in_seconds,
            .proof = access_token.Signature{ .bytes = std.mem.zeroes([64]u8) },
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *VerifiableCredential) void {
        self.claims.deinit();
    }
    
    pub fn addClaim(self: *VerifiableCredential, key: []const u8, value: []const u8) !void {
        try self.claims.put(key, value);
    }
    
    pub fn isExpired(self: *const VerifiableCredential) bool {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now > self.expires_at;
    }
    
    pub fn sign(self: *VerifiableCredential, private_key: access_token.PrivateKey) !void {
        var payload = std.ArrayList(u8){};
        defer payload.deinit(self.allocator);
        
        try payload.appendSlice(self.allocator, self.id);
        
        const issuer_str = try self.issuer.toString(self.allocator);
        defer self.allocator.free(issuer_str);
        try payload.appendSlice(self.allocator, issuer_str);
        
        const subject_str = try self.subject.toString(self.allocator);
        defer self.allocator.free(subject_str);
        try payload.appendSlice(self.allocator, subject_str);
        
        try payload.appendSlice(self.allocator, self.credential_type);
        
        // Add claims
        var claim_iter = self.claims.iterator();
        while (claim_iter.next()) |entry| {
            try payload.appendSlice(self.allocator, entry.key_ptr.*);
            try payload.appendSlice(self.allocator, entry.value_ptr.*);
        }
        
        var issued_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &issued_bytes, self.issued_at, .little);
        try payload.appendSlice(self.allocator, &issued_bytes);
        
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        try payload.appendSlice(self.allocator, &expires_bytes);
        
        self.proof = try access_token.signData(payload.items, private_key);
    }
    
    pub fn verify(self: *const VerifiableCredential, public_key: access_token.PublicKey) bool {
        if (self.isExpired()) return false;
        
        var payload = std.ArrayList(u8){};
        defer payload.deinit(self.allocator);
        
        payload.appendSlice(self.allocator, self.id) catch return false;
        
        const issuer_str = self.issuer.toString(self.allocator) catch return false;
        defer self.allocator.free(issuer_str);
        payload.appendSlice(self.allocator, issuer_str) catch return false;
        
        const subject_str = self.subject.toString(self.allocator) catch return false;
        defer self.allocator.free(subject_str);
        payload.appendSlice(self.allocator, subject_str) catch return false;
        
        payload.appendSlice(self.allocator, self.credential_type) catch return false;
        
        // Add claims
        var claim_iter = self.claims.iterator();
        while (claim_iter.next()) |entry| {
            payload.appendSlice(self.allocator, entry.key_ptr.*) catch return false;
            payload.appendSlice(self.allocator, entry.value_ptr.*) catch return false;
        }
        
        var issued_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &issued_bytes, self.issued_at, .little);
        payload.appendSlice(self.allocator, &issued_bytes) catch return false;
        
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        payload.appendSlice(self.allocator, &expires_bytes) catch return false;
        
        return access_token.verifyData(self.proof, payload.items, public_key);
    }
};

pub const CrossChainProof = struct {
    source_chain: ChainType,
    target_chain: ChainType,
    proof: zk_proof.ZkProof,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *CrossChainProof) void {
        self.proof.deinit();
    }
    
    pub fn verify(self: *const CrossChainProof, proof_system: *zk_proof.ZkProofSystem) !bool {
        return proof_system.verifyProof(&self.proof);
    }
};

pub const CrossChainResolver = struct {
    supported_chains: std.HashMap(ChainType, ChainConfig, std.hash_map.AutoContext(ChainType), std.hash_map.default_max_load_percentage),
    identity_cache: std.HashMap([]const u8, CrossChainIdentity, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) CrossChainResolver {
        return CrossChainResolver{
            .supported_chains = std.HashMap(ChainType, ChainConfig, std.hash_map.AutoContext(ChainType), std.hash_map.default_max_load_percentage).init(allocator),
            .identity_cache = std.HashMap([]const u8, CrossChainIdentity, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *CrossChainResolver) void {
        var config_iter = self.supported_chains.iterator();
        while (config_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.supported_chains.deinit();
        
        var identity_iter = self.identity_cache.iterator();
        while (identity_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.identity_cache.deinit();
    }
    
    pub fn addChainSupport(self: *CrossChainResolver, chain: ChainType, config: ChainConfig) !void {
        try self.supported_chains.put(chain, config);
    }
    
    pub fn resolveDID(self: *CrossChainResolver, did_string: []const u8) CrossChainError!*CrossChainIdentity {
        // Check cache first
        if (self.identity_cache.getPtr(did_string)) |cached| {
            return cached;
        }
        
        // Parse DID
        const did = try DID.parse(did_string);
        
        // Check if chain is supported
        const chain_config = self.supported_chains.get(did.chain) orelse return CrossChainError.ChainNotSupported;
        
        // Create cross-chain identity
        var cross_chain_identity = CrossChainIdentity.init(self.allocator, did);
        
        // Simulate resolution from blockchain
        try self.resolveFromChain(&cross_chain_identity, &chain_config);
        
        // Cache the result
        try self.identity_cache.put(did_string, cross_chain_identity);
        
        return self.identity_cache.getPtr(did_string).?;
    }
    
    pub fn createCrossChainIdentity(self: *CrossChainResolver, primary_chain: ChainType, identifier: []const u8) CrossChainError!CrossChainIdentity {
        const primary_did = DID{
            .method = "shroud",
            .chain = primary_chain,
            .identifier = identifier,
        };
        
        return CrossChainIdentity.init(self.allocator, primary_did);
    }
    
    fn resolveFromChain(self: *CrossChainResolver, cross_chain_identity: *CrossChainIdentity, config: *const ChainConfig) CrossChainError!void {
        _ = config;
        // Simulate blockchain resolution
        switch (cross_chain_identity.primary_did.chain) {
            .ethereum, .polygon => {
                // Resolve from EVM-compatible chains
                try cross_chain_identity.anchorToChain(cross_chain_identity.primary_did.chain, cross_chain_identity.primary_did.identifier, "eth_signature_proof");
            },
            .solana => {
                // Resolve from Solana
                try cross_chain_identity.anchorToChain(.solana, cross_chain_identity.primary_did.identifier, "solana_signature_proof");
            },
            .ghostchain, .keystone => {
                // Resolve from Ghostchain ecosystem
                try cross_chain_identity.anchorToChain(cross_chain_identity.primary_did.chain, cross_chain_identity.primary_did.identifier, "ghost_signature_proof");
            },
            else => {
                // Generic resolution
                try cross_chain_identity.anchorToChain(cross_chain_identity.primary_did.chain, cross_chain_identity.primary_did.identifier, "generic_proof");
            },
        }
        
        // Add default verifiable credential
        const default_cred = VerifiableCredential.init(
            self.allocator,
            "default_identity_cred",
            cross_chain_identity.primary_did,
            cross_chain_identity.primary_did,
            "IdentityCredential",
            86400 * 365, // 1 year
        );
        try cross_chain_identity.addVerifiableCredential(default_cred);
    }
};

pub const ChainConfig = struct {
    rpc_endpoint: []const u8,
    contract_address: ?[]const u8,
    network_id: u64,
    supported_did_methods: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, rpc_endpoint: []const u8, network_id: u64) ChainConfig {
        return ChainConfig{
            .rpc_endpoint = rpc_endpoint,
            .contract_address = null,
            .network_id = network_id,
            .supported_did_methods = std.ArrayList([]const u8){},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ChainConfig) void {
        self.supported_did_methods.deinit(self.allocator);
    }
    
    pub fn addDIDMethod(self: *ChainConfig, method: []const u8) !void {
        try self.supported_did_methods.append(self.allocator, method);
    }
    
    pub fn setContractAddress(self: *ChainConfig, address: []const u8) void {
        self.contract_address = address;
    }
};

pub fn createDefaultChainConfigs(allocator: std.mem.Allocator, resolver: *CrossChainResolver) !void {
    // Ethereum mainnet
    var eth_config = ChainConfig.init(allocator, "https://mainnet.infura.io/v3/", 1);
    try eth_config.addDIDMethod("ethr");
    try eth_config.addDIDMethod("shroud");
    try resolver.addChainSupport(.ethereum, eth_config);
    
    // Polygon
    var polygon_config = ChainConfig.init(allocator, "https://polygon-rpc.com", 137);
    try polygon_config.addDIDMethod("polygon");
    try polygon_config.addDIDMethod("shroud");
    try resolver.addChainSupport(.polygon, polygon_config);
    
    // Ghostchain
    var ghost_config = ChainConfig.init(allocator, "https://rpc.ghostchain.network", 9999);
    try ghost_config.addDIDMethod("ghost");
    try ghost_config.addDIDMethod("shroud");
    ghost_config.setContractAddress("0x1234567890123456789012345678901234567890");
    try resolver.addChainSupport(.ghostchain, ghost_config);
    
    // Keystone
    var keystone_config = ChainConfig.init(allocator, "https://rpc.keystone.network", 10000);
    try keystone_config.addDIDMethod("keystone");
    try keystone_config.addDIDMethod("shroud");
    try resolver.addChainSupport(.keystone, keystone_config);
}

pub fn version() []const u8 {
    return "0.1.0";
}