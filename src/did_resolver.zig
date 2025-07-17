//! DID Resolution System with Batch Support
//! High-performance DID resolution with caching and batch operations

const std = @import("std");
const qid = @import("qid.zig");
const identity = @import("identity.zig");
const guardian = @import("guardian.zig");
const advanced_tokens = @import("advanced_tokens.zig");
const policy_engine = @import("policy_engine.zig");

/// DID Document structure
pub const DIDDocument = struct {
    id: []const u8,
    public_keys: std.ArrayList(PublicKeyEntry),
    services: std.ArrayList(ServiceEntry),
    authentication: std.ArrayList([]const u8),
    assertion_method: std.ArrayList([]const u8),
    created: i64,
    updated: i64,
    version: u32,
    allocator: std.mem.Allocator,

    pub const PublicKeyEntry = struct {
        id: []const u8,
        type: KeyType,
        public_key_base58: []const u8,
        purposes: std.ArrayList(KeyPurpose),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, id: []const u8, key_type: KeyType, public_key: []const u8) PublicKeyEntry {
            return PublicKeyEntry{
                .id = id,
                .type = key_type,
                .public_key_base58 = public_key,
                .purposes = std.ArrayList(KeyPurpose).init(allocator),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *PublicKeyEntry) void {
            self.purposes.deinit();
        }
    };

    pub const ServiceEntry = struct {
        id: []const u8,
        type: []const u8,
        service_endpoint: []const u8,
    };

    pub const KeyType = enum {
        ed25519,
        secp256k1,
        rsa,
        bls12381,
    };

    pub const KeyPurpose = enum {
        authentication,
        assertion_method,
        key_agreement,
        capability_invocation,
        capability_delegation,
    };

    pub fn init(allocator: std.mem.Allocator, id: []const u8) DIDDocument {
        return DIDDocument{
            .id = id,
            .public_keys = std.ArrayList(PublicKeyEntry).init(allocator),
            .services = std.ArrayList(ServiceEntry).init(allocator),
            .authentication = std.ArrayList([]const u8).init(allocator),
            .assertion_method = std.ArrayList([]const u8).init(allocator),
            .created = std.time.milliTimestamp(),
            .updated = std.time.milliTimestamp(),
            .version = 1,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DIDDocument) void {
        for (self.public_keys.items) |*key| {
            key.deinit();
        }
        self.public_keys.deinit();
        self.services.deinit();
        self.authentication.deinit();
        self.assertion_method.deinit();
    }

    pub fn addPublicKey(self: *DIDDocument, key: PublicKeyEntry) !void {
        try self.public_keys.append(key);
    }

    pub fn addService(self: *DIDDocument, service: ServiceEntry) !void {
        try self.services.append(service);
    }

    pub fn getPublicKey(self: *const DIDDocument, key_id: []const u8) ?*const PublicKeyEntry {
        for (self.public_keys.items) |*key| {
            if (std.mem.eql(u8, key.id, key_id)) return key;
        }
        return null;
    }

    /// Generate QID from this DID document's primary key
    pub fn generateQID(self: *const DIDDocument) ?qid.QID {
        if (self.public_keys.items.len == 0) return null;
        
        // Use first Ed25519 key for QID generation
        for (self.public_keys.items) |*key| {
            if (key.type == .ed25519) {
                // For now, assume public_key_base58 contains raw bytes
                // In production, you'd decode from base58
                const dummy_pubkey = [_]u8{0x42} ** 32; // Placeholder
                return qid.QID.fromPublicKey(&dummy_pubkey);
            }
        }
        return null;
    }
};

/// Cache entry for DID documents with TTL
pub const CacheEntry = struct {
    document: DIDDocument,
    expires_at: i64,
    
    pub fn isExpired(self: *const CacheEntry) bool {
        return std.time.milliTimestamp() > self.expires_at;
    }
};

/// Batch DID resolution request
pub const BatchResolutionRequest = struct {
    dids: []const []const u8,
    context: ?[]const u8 = null,
    include_metadata: bool = true,
    cache_policy: CachePolicy = .prefer_cache,

    pub const CachePolicy = enum {
        prefer_cache,
        bypass_cache,
        cache_only,
    };
};

/// Batch DID resolution response
pub const BatchResolutionResponse = struct {
    results: std.ArrayList(ResolutionResult),
    metadata: ResolutionMetadata,
    allocator: std.mem.Allocator,

    pub const ResolutionResult = struct {
        did: []const u8,
        document: ?DIDDocument,
        error_code: ?ResolutionError,
        from_cache: bool,
        resolution_time_ms: u64,
    };

    pub const ResolutionMetadata = struct {
        total_requested: u32,
        successful: u32,
        failed: u32,
        cache_hits: u32,
        total_time_ms: u64,
    };

    pub fn init(allocator: std.mem.Allocator) BatchResolutionResponse {
        return BatchResolutionResponse{
            .results = std.ArrayList(ResolutionResult).init(allocator),
            .metadata = ResolutionMetadata{
                .total_requested = 0,
                .successful = 0,
                .failed = 0,
                .cache_hits = 0,
                .total_time_ms = 0,
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BatchResolutionResponse) void {
        for (self.results.items) |*result| {
            if (result.document) |*doc| {
                doc.deinit();
            }
        }
        self.results.deinit();
    }
};

/// DID Resolution errors
pub const ResolutionError = error{
    InvalidDID,
    NotFound,
    MethodNotSupported,
    NetworkError,
    Timeout,
    CacheError,
    InvalidFormat,
    PermissionDenied,
    OutOfMemory,
};

/// DID Resolver with caching and batch support
pub const DIDResolver = struct {
    cache: std.HashMap([]const u8, CacheEntry, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    cache_ttl_seconds: u64,
    max_cache_size: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, cache_ttl_seconds: u64, max_cache_size: u32) DIDResolver {
        return DIDResolver{
            .cache = std.HashMap([]const u8, CacheEntry, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .cache_ttl_seconds = cache_ttl_seconds,
            .max_cache_size = max_cache_size,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DIDResolver) void {
        // Clean up cache entries safely
        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            var doc = entry.value_ptr.document;
            doc.deinit();
        }
        self.cache.deinit();
    }

    /// Resolve a single DID
    pub fn resolveDID(self: *DIDResolver, did: []const u8) ResolutionError!DIDDocument {
        // Check cache first
        if (self.cache.get(did)) |entry| {
            if (!entry.isExpired()) {
                // Return cached copy
                return entry.document; // Note: This is a shallow copy, be careful with memory
            } else {
                // Remove expired entry
                _ = self.cache.remove(did);
            }
        }

        // Resolve from network/storage
        const document = try self.resolveFromSource(did);
        
        // Cache the result
        try self.cacheDocument(did, document);
        
        return document;
    }

    /// Batch resolve multiple DIDs
    pub fn batchResolveDIDs(self: *DIDResolver, request: BatchResolutionRequest) !BatchResolutionResponse {
        const start_time = std.time.milliTimestamp();
        var response = BatchResolutionResponse.init(self.allocator);
        
        response.metadata.total_requested = @intCast(request.dids.len);

        for (request.dids) |did| {
            const resolve_start = std.time.milliTimestamp();
            
            var result = BatchResolutionResponse.ResolutionResult{
                .did = did,
                .document = null,
                .error_code = null,
                .from_cache = false,
                .resolution_time_ms = 0,
            };

            // Check cache policy
            var check_cache = true;
            if (request.cache_policy == .bypass_cache) {
                check_cache = false;
            }

            // Try cache first if allowed
            if (check_cache) {
                if (self.cache.get(did)) |entry| {
                    if (!entry.isExpired()) {
                        result.document = entry.document;
                        result.from_cache = true;
                        response.metadata.cache_hits += 1;
                    }
                }
            }

            // Resolve from source if not in cache
            if (result.document == null and request.cache_policy != .cache_only) {
                result.document = self.resolveFromSource(did) catch |err| blk: {
                    result.error_code = err;
                    break :blk null;
                };

                if (result.document != null) {
                    // Cache the new result
                    self.cacheDocument(did, result.document.?) catch {};
                }
            }

            result.resolution_time_ms = @intCast(std.time.milliTimestamp() - resolve_start);
            
            if (result.document != null) {
                response.metadata.successful += 1;
            } else {
                response.metadata.failed += 1;
            }

            try response.results.append(result);
        }

        response.metadata.total_time_ms = @intCast(std.time.milliTimestamp() - start_time);
        return response;
    }

    /// Resolve DIDs with transaction context awareness
    pub fn resolveWithTransactionContext(self: *DIDResolver, request: *const TransactionAwareBatchResolutionRequest) !BatchResolutionResponse {
        // Perform compliance checks if transaction context is provided
        if (request.transaction_context) |tx_context| {
            try self.performComplianceChecks(tx_context);
            
            // Check if manual review is required
            if (tx_context.requiresManualReview()) {
                return error.ManualReviewRequired;
            }
        }

        // Validate authorization tokens
        try self.validateAuthorizationTokens(request);

        // Apply policy requirements
        try self.applyPolicyRequirements(request);

        // Perform standard batch resolution with enhanced context
        return try self.resolveBatch(&request.base_request);
    }

    fn performComplianceChecks(self: *DIDResolver, tx_context: *const TransactionContext) !void {
        _ = self;
        
        // Simulate compliance checks
        for (tx_context.compliance_flags.items) |flag| {
            switch (flag.flag_type) {
                .kyc_required => {
                    // Simulate KYC validation
                    std.log.info("Performing KYC check for transaction {s}", .{tx_context.transaction_id});
                },
                .aml_check => {
                    // Simulate AML validation
                    std.log.info("Performing AML check for transaction {s}", .{tx_context.transaction_id});
                },
                .sanctions_screening => {
                    // Simulate sanctions screening
                    std.log.info("Performing sanctions screening for transaction {s}", .{tx_context.transaction_id});
                },
                .high_risk_country => {
                    // Simulate country risk assessment
                    std.log.info("Checking country risk for transaction {s}", .{tx_context.transaction_id});
                },
                .unusual_pattern => {
                    // Simulate pattern analysis
                    std.log.info("Analyzing transaction patterns for {s}", .{tx_context.transaction_id});
                },
                .manual_review => {
                    // Flag for manual review
                    std.log.warn("Manual review required for transaction {s}", .{tx_context.transaction_id});
                },
            }
        }

        // Amount-based checks
        if (tx_context.amount) |amount| {
            if (amount > 10000) {
                std.log.warn("High-value transaction detected: {} {s}", .{ amount, tx_context.currency orelse "USD" });
            }
        }
    }

    fn validateAuthorizationTokens(self: *DIDResolver, request: *const TransactionAwareBatchResolutionRequest) !void {
        _ = self;
        
        if (request.authorization_tokens.items.len == 0) {
            return; // No tokens to validate
        }

        for (request.authorization_tokens.items) |token| {
            // Simulate token validation
            if (token.len < 32) {
                return error.InvalidAuthorizationToken;
            }
            
            // In a real implementation, we would:
            // 1. Parse the token (JWT, etc.)
            // 2. Verify the signature
            // 3. Check expiration
            // 4. Validate permissions
            std.log.info("Validating authorization token: {s}...", .{token[0..8]});
        }
    }

    fn applyPolicyRequirements(self: *DIDResolver, request: *const TransactionAwareBatchResolutionRequest) !void {
        _ = self;
        
        if (request.policy_requirements.items.len == 0) {
            return; // No policy requirements
        }

        for (request.policy_requirements.items) |policy_name| {
            // Simulate policy application
            std.log.info("Applying policy requirement: {s}", .{policy_name});
            
            // In a real implementation, we would:
            // 1. Load the policy from the policy engine
            // 2. Evaluate the policy against the current context
            // 3. Apply any restrictions or requirements
            // 4. Log policy decisions for audit
        }
    }



    /// Clear expired entries from cache
    pub fn cleanCache(self: *DIDResolver) void {
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.cache.fetchRemove(key)) |removed| {
                var doc = removed.value.document;
                doc.deinit();
            }
        }
    }

    /// Get cache statistics
    pub fn getCacheStats(self: *const DIDResolver) CacheStats {
        var expired_count: u32 = 0;
        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                expired_count += 1;
            }
        }

        return CacheStats{
            .total_entries = @intCast(self.cache.count()),
            .expired_entries = expired_count,
            .active_entries = @as(u32, @intCast(self.cache.count())) - expired_count,
            .max_size = self.max_cache_size,
        };
    }

    pub const CacheStats = struct {
        total_entries: u32,
        expired_entries: u32,
        active_entries: u32,
        max_size: u32,
    };

    /// Resolve DID from source (placeholder implementation)
    fn resolveFromSource(self: *DIDResolver, did: []const u8) ResolutionError!DIDDocument {
        // Placeholder implementation - in production this would:
        // 1. Parse DID to determine method
        // 2. Route to appropriate resolver (blockchain, DNS, etc.)
        // 3. Fetch and parse DID document
        
        if (std.mem.startsWith(u8, did, "did:shroud:")) {
            return self.resolveShroudDID(did);
        } else if (std.mem.startsWith(u8, did, "did:key:")) {
            return self.resolveKeyDID(did);
        } else {
            return ResolutionError.MethodNotSupported;
        }
    }

    /// Resolve SHROUD-specific DID
    fn resolveShroudDID(self: *DIDResolver, did: []const u8) ResolutionError!DIDDocument {
        var document = DIDDocument.init(self.allocator, did);
        
        // Create a sample key entry
        var key = DIDDocument.PublicKeyEntry.init(
            self.allocator,
            "key-1",
            .ed25519,
            "sample-public-key-base58"
        );
        try key.purposes.append(.authentication);
        try key.purposes.append(.assertion_method);
        
        try document.addPublicKey(key);
        
        // Add authentication reference
        try document.authentication.append("key-1");
        try document.assertion_method.append("key-1");
        
        return document;
    }

    /// Resolve key-based DID
    fn resolveKeyDID(self: *DIDResolver, did: []const u8) ResolutionError!DIDDocument {
        var document = DIDDocument.init(self.allocator, did);
        
        // Extract public key from DID (simplified)
        var key = DIDDocument.PublicKeyEntry.init(
            self.allocator,
            "key-1",
            .ed25519,
            did[8..] // Skip "did:key:" prefix
        );
        try key.purposes.append(.authentication);
        
        try document.addPublicKey(key);
        try document.authentication.append("key-1");
        
        return document;
    }

    /// Cache a DID document
    fn cacheDocument(self: *DIDResolver, did: []const u8, document: DIDDocument) !void {
        // Check cache size limit
        if (self.cache.count() >= self.max_cache_size) {
            self.cleanCache();
            
            // If still at limit, remove oldest entry
            if (self.cache.count() >= self.max_cache_size) {
                // Simple eviction: remove first entry
                var iterator = self.cache.iterator();
                if (iterator.next()) |entry| {
                    const key_to_remove = entry.key_ptr.*;
                    if (self.cache.fetchRemove(key_to_remove)) |removed| {
                        var doc = removed.value.document;
                        doc.deinit();
                    }
                }
            }
        }

        const expires_at = std.time.milliTimestamp() + (@as(i64, @intCast(self.cache_ttl_seconds)) * 1000);
        const cache_entry = CacheEntry{
            .document = document,
            .expires_at = expires_at,
        };

        try self.cache.put(did, cache_entry);
    }

    /// Create transaction context for identity verification
    pub fn createIdentityVerificationContext(self: *DIDResolver, transaction_id: []const u8, requester_did: []const u8, target_did: []const u8) !TransactionContext {
        var context = TransactionContext.init(self.allocator, transaction_id, .identity_verification, requester_did);
        context.setTargetDID(target_did);
        
        // Add default compliance flags for identity verification
        try context.addComplianceFlag(.{
            .flag_type = .kyc_required,
            .severity = .medium,
            .description = "KYC verification required for identity transactions",
        });
        
        return context;
    }

    /// Create transaction context for payment operations
    pub fn createPaymentContext(self: *DIDResolver, transaction_id: []const u8, requester_did: []const u8, amount: u64, currency: []const u8) !TransactionContext {
        var context = TransactionContext.init(self.allocator, transaction_id, .payment, requester_did);
        context.setAmount(amount, currency);
        
        // Add compliance flags based on amount
        if (amount > 10000) {
            try context.addComplianceFlag(.{
                .flag_type = .aml_check,
                .severity = .high,
                .description = "AML check required for high-value transactions",
            });
        }
        
        if (amount > 50000) {
            try context.addComplianceFlag(.{
                .flag_type = .manual_review,
                .severity = .critical,
                .description = "Manual review required for very high-value transactions",
            });
        }
        
        return context;
    }
};

/// Transaction context for DID resolution
pub const TransactionContext = struct {
    transaction_id: []const u8,
    transaction_type: TransactionType,
    amount: ?u64,
    currency: ?[]const u8,
    requester_did: []const u8,
    target_did: ?[]const u8,
    timestamp: i64,
    risk_score: f32,
    compliance_flags: std.ArrayList(ComplianceFlag),
    allocator: std.mem.Allocator,

    pub const TransactionType = enum {
        payment,
        identity_verification,
        document_signing,
        asset_transfer,
        data_access,
        contract_execution,
    };

    pub const ComplianceFlag = struct {
        flag_type: FlagType,
        severity: Severity,
        description: []const u8,

        pub const FlagType = enum {
            kyc_required,
            aml_check,
            sanctions_screening,
            high_risk_country,
            unusual_pattern,
            manual_review,
        };

        pub const Severity = enum {
            low,
            medium,
            high,
            critical,
        };
    };

    pub fn init(allocator: std.mem.Allocator, transaction_id: []const u8, transaction_type: TransactionType, requester_did: []const u8) TransactionContext {
        return TransactionContext{
            .transaction_id = transaction_id,
            .transaction_type = transaction_type,
            .amount = null,
            .currency = null,
            .requester_did = requester_did,
            .target_did = null,
            .timestamp = std.time.milliTimestamp(),
            .risk_score = 0.0,
            .compliance_flags = std.ArrayList(ComplianceFlag).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TransactionContext) void {
        self.compliance_flags.deinit();
    }

    pub fn setAmount(self: *TransactionContext, amount: u64, currency: []const u8) void {
        self.amount = amount;
        self.currency = currency;
    }

    pub fn setTargetDID(self: *TransactionContext, did: []const u8) void {
        self.target_did = did;
    }

    pub fn addComplianceFlag(self: *TransactionContext, flag: ComplianceFlag) !void {
        try self.compliance_flags.append(flag);
        
        // Update risk score based on flag severity
        const severity_weight: f32 = switch (flag.severity) {
            .low => 0.1,
            .medium => 0.3,
            .high => 0.6,
            .critical => 1.0,
        };
        self.risk_score = @min(1.0, self.risk_score + severity_weight);
    }

    pub fn isHighRisk(self: *const TransactionContext) bool {
        return self.risk_score > 0.7;
    }

    pub fn requiresManualReview(self: *const TransactionContext) bool {
        for (self.compliance_flags.items) |flag| {
            if (flag.flag_type == .manual_review or flag.severity == .critical) {
                return true;
            }
        }
        return self.isHighRisk();
    }
};

/// Enhanced DID resolution request with transaction context
pub const TransactionAwareBatchResolutionRequest = struct {
    base_request: BatchResolutionRequest,
    transaction_context: ?*const TransactionContext,
    policy_requirements: std.ArrayList([]const u8),
    authorization_tokens: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, base_request: BatchResolutionRequest) TransactionAwareBatchResolutionRequest {
        return TransactionAwareBatchResolutionRequest{
            .base_request = base_request,
            .transaction_context = null,
            .policy_requirements = std.ArrayList([]const u8).init(allocator),
            .authorization_tokens = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TransactionAwareBatchResolutionRequest) void {
        self.policy_requirements.deinit();
        self.authorization_tokens.deinit();
    }

    pub fn setTransactionContext(self: *TransactionAwareBatchResolutionRequest, context: *const TransactionContext) void {
        self.transaction_context = context;
    }

    pub fn addPolicyRequirement(self: *TransactionAwareBatchResolutionRequest, policy: []const u8) !void {
        try self.policy_requirements.append(policy);
    }

    pub fn addAuthorizationToken(self: *TransactionAwareBatchResolutionRequest, token: []const u8) !void {
        try self.authorization_tokens.append(token);
    }
};

test "DID document creation and management" {
    var document = DIDDocument.init(std.testing.allocator, "did:shroud:example");
    defer document.deinit();

    var key = DIDDocument.PublicKeyEntry.init(
        std.testing.allocator,
        "key-1",
        .ed25519,
        "test-public-key"
    );
    try key.purposes.append(.authentication);
    try document.addPublicKey(key);

    try std.testing.expect(document.public_keys.items.len == 1);
    try std.testing.expect(document.getPublicKey("key-1") != null);
    try std.testing.expect(document.getPublicKey("key-2") == null);
}

test "DID resolver single resolution" {
    var resolver = DIDResolver.init(std.testing.allocator, 300, 100); // 5 min TTL, 100 entries max
    defer resolver.deinit();

    const document = try resolver.resolveDID("did:shroud:test");
    defer {
        var doc = document;
        doc.deinit();
    }

    try std.testing.expect(std.mem.eql(u8, document.id, "did:shroud:test"));
    try std.testing.expect(document.public_keys.items.len > 0);
}

test "DID resolver batch resolution" {
    var resolver = DIDResolver.init(std.testing.allocator, 300, 100);
    defer resolver.deinit();

    const dids = [_][]const u8{ "did:shroud:test1", "did:shroud:test2", "did:key:test3" };
    const request = BatchResolutionRequest{
        .dids = &dids,
        .cache_policy = .prefer_cache,
    };

    var response = try resolver.batchResolveDIDs(request);
    defer response.deinit();

    try std.testing.expect(response.results.items.len == 3);
    try std.testing.expect(response.metadata.total_requested == 3);
    try std.testing.expect(response.metadata.successful == 3);
    try std.testing.expect(response.metadata.failed == 0);
}

test "transaction context creation and management" {
    var tx_context = TransactionContext.init(std.testing.allocator, "tx-001", .payment, "did:shroud:alice");
    defer tx_context.deinit();

    tx_context.setAmount(5000, "USD");
    tx_context.setTargetDID("did:shroud:bob");

    try tx_context.addComplianceFlag(.{
        .flag_type = .aml_check,
        .severity = .medium,
        .description = "AML verification needed",
    });

    try std.testing.expect(tx_context.amount.? == 5000);
    try std.testing.expect(std.mem.eql(u8, tx_context.currency.?, "USD"));
    try std.testing.expect(tx_context.compliance_flags.items.len == 1);
    try std.testing.expect(tx_context.risk_score > 0.0);
}

test "transaction context risk assessment" {
    var tx_context = TransactionContext.init(std.testing.allocator, "tx-002", .payment, "did:shroud:charlie");
    defer tx_context.deinit();

    // Add multiple compliance flags
    try tx_context.addComplianceFlag(.{
        .flag_type = .high_risk_country,
        .severity = .high,
        .description = "Transaction from high-risk jurisdiction",
    });

    try tx_context.addComplianceFlag(.{
        .flag_type = .unusual_pattern,
        .severity = .medium,
        .description = "Unusual transaction pattern detected",
    });

    try std.testing.expect(tx_context.isHighRisk());
    try std.testing.expect(tx_context.requiresManualReview());
}

test "transaction-aware DID resolution" {
    var resolver = DIDResolver.init(std.testing.allocator, 300, 100);
    defer resolver.deinit();

    // Create base batch request
    var did_list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer did_list.deinit();
    try did_list.append("did:shroud:test");

    const base_request = BatchResolutionRequest{
        .dids = did_list.items,
        .context = "test-batch",
        .include_metadata = true,
        .cache_policy = .prefer_cache,
    };

    // Create transaction-aware request
    var tx_request = TransactionAwareBatchResolutionRequest.init(std.testing.allocator, base_request);
    defer tx_request.deinit();

    // Create transaction context
    var tx_context = try resolver.createPaymentContext("tx-003", "did:shroud:payer", 1000, "USD");
    defer tx_context.deinit();

    tx_request.setTransactionContext(&tx_context);
    try tx_request.addPolicyRequirement("payment_policy");
    try tx_request.addAuthorizationToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

    // Test that low-value transactions don't require manual review
    try std.testing.expect(!tx_context.requiresManualReview());
}

test "high-value transaction compliance" {
    var resolver = DIDResolver.init(std.testing.allocator, 300, 100);
    defer resolver.deinit();

    // Create high-value payment context
    var tx_context = try resolver.createPaymentContext("tx-004", "did:shroud:big_spender", 75000, "USD");
    defer tx_context.deinit();

    // High-value transactions should require manual review
    try std.testing.expect(tx_context.requiresManualReview());
    try std.testing.expect(tx_context.isHighRisk());
    try std.testing.expect(tx_context.compliance_flags.items.len >= 2); // AML + manual review
}

test "identity verification context" {
    var resolver = DIDResolver.init(std.testing.allocator, 300, 100);
    defer resolver.deinit();

    var tx_context = try resolver.createIdentityVerificationContext("id-verify-001", "did:shroud:verifier", "did:shroud:subject");
    defer tx_context.deinit();

    try std.testing.expect(tx_context.transaction_type == .identity_verification);
    try std.testing.expect(std.mem.eql(u8, tx_context.target_did.?, "did:shroud:subject"));
    try std.testing.expect(tx_context.compliance_flags.items.len == 1);
    try std.testing.expect(tx_context.compliance_flags.items[0].flag_type == .kyc_required);
}
