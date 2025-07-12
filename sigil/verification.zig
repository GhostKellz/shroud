//! Identity Verification Levels System
//! Provides progressive verification for enhanced trust and access

const std = @import("std");
const zcrypto = @import("ghostcipher").zcrypto;
const types = @import("types.zig");
const qid = @import("qid.zig");

const GID = qid.GID;

/// Progressive verification levels for identities
pub const VerificationLevel = enum(u8) {
    unverified = 0,     // Just created, no verification
    self_attested = 1,  // User provided basic info
    device_bound = 2,   // Tied to hardware device
    biometric = 3,      // Biometric verification
    social_proof = 4,   // Web2 accounts linked
    on_chain = 5,       // Blockchain verified
    trusted_party = 6,  // KYC/trusted institution
    government = 7,     // Government-issued ID verified
    
    pub fn toString(self: VerificationLevel) []const u8 {
        return switch (self) {
            .unverified => "Unverified",
            .self_attested => "Self-Attested", 
            .device_bound => "Device-Bound",
            .biometric => "Biometric",
            .social_proof => "Social Proof",
            .on_chain => "On-Chain",
            .trusted_party => "KYC Verified",
            .government => "Government ID",
        };
    }
    
    pub fn getScore(self: VerificationLevel) u8 {
        return @intFromEnum(self) * 10; // 0-70 points
    }
    
    pub fn canAccess(self: VerificationLevel, required_level: VerificationLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(required_level);
    }
};

/// Verification requirements for different operations
pub const VerificationRequirement = struct {
    min_level: VerificationLevel,
    additional_checks: []const VerificationCheck,
    grace_period_hours: ?u32, // Allow lower verification temporarily
    
    pub const VerificationCheck = enum {
        device_consistency,    // Same device as registration
        location_consistency,  // Reasonable location
        time_since_verification, // Recent verification
        social_vouching,       // Someone vouched for them
        transaction_history,   // Clean history
    };
};

/// Evidence for verification claims
pub const VerificationEvidence = struct {
    evidence_type: EvidenceType,
    data_hash: [32]u8,      // Hash of evidence data
    verifier_gid: ?GID,     // Who verified this
    timestamp: u64,
    expiry: ?u64,
    confidence_score: u8,   // 0-100
    signature: [64]u8,      // Verifier signature
    
    pub const EvidenceType = enum {
        government_id,
        passport,
        drivers_license,
        utility_bill,
        bank_statement,
        biometric_scan,
        device_attestation,
        social_account,
        blockchain_transaction,
        third_party_kyc,
        peer_attestation,
        institutional_verification,
    };
    
    pub fn verify(self: VerificationEvidence, verifier_public_key: [32]u8) bool {
        // Verify the signature on the evidence
        var message_data: [1024]u8 = undefined;
        const message = std.fmt.bufPrint(&message_data, "evidence:{s}:{}:{}:{}", .{
            @tagName(self.evidence_type),
            std.fmt.fmtSliceHexLower(&self.data_hash),
            self.timestamp,
            self.confidence_score
        }) catch return false;
        
        return zcrypto.asym.ed25519.verify(message, self.signature, verifier_public_key);
    }
    
    pub fn isExpired(self: VerificationEvidence) bool {
        if (self.expiry) |expiry| {
            return std.time.timestamp() > expiry;
        }
        return false;
    }
};

/// Complete verification record for an identity
pub const VerificationRecord = struct {
    gid: GID,
    current_level: VerificationLevel,
    evidence: std.ArrayList(VerificationEvidence),
    verification_history: std.ArrayList(VerificationEvent),
    last_updated: u64,
    flags: VerificationFlags,
    allocator: std.mem.Allocator,
    
    pub const VerificationFlags = packed struct {
        pending_verification: bool = false,
        verification_disputed: bool = false,
        manual_review_required: bool = false,
        high_risk: bool = false,
        frozen: bool = false,
        _reserved: u3 = 0,
    };
    
    pub const VerificationEvent = struct {
        event_type: EventType,
        old_level: VerificationLevel,
        new_level: VerificationLevel,
        evidence_id: ?usize, // Index into evidence array
        timestamp: u64,
        verifier_gid: ?GID,
        notes: ?[]const u8,
        
        pub const EventType = enum {
            initial_verification,
            level_upgrade,
            level_downgrade,
            evidence_added,
            evidence_disputed,
            manual_review,
            fraud_detected,
            verification_expired,
        };
    };
    
    pub fn init(allocator: std.mem.Allocator, gid: GID) VerificationRecord {
        return VerificationRecord{
            .gid = gid,
            .current_level = .unverified,
            .evidence = std.ArrayList(VerificationEvidence).init(allocator),
            .verification_history = std.ArrayList(VerificationEvent).init(allocator),
            .last_updated = @intCast(std.time.timestamp()),
            .flags = VerificationFlags{},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *VerificationRecord) void {
        self.evidence.deinit();
        self.verification_history.deinit();
    }
    
    /// Add new verification evidence
    pub fn addEvidence(self: *VerificationRecord, evidence: VerificationEvidence) !void {
        try self.evidence.append(evidence);
        
        // Recalculate verification level based on evidence
        const new_level = self.calculateVerificationLevel();
        if (new_level != self.current_level) {
            try self.updateLevel(new_level, .evidence_added, evidence.verifier_gid);
        }
        
        self.last_updated = @intCast(std.time.timestamp());
    }
    
    /// Update verification level with audit trail
    pub fn updateLevel(self: *VerificationRecord, new_level: VerificationLevel, event_type: VerificationEvent.EventType, verifier_gid: ?GID) !void {
        const old_level = self.current_level;
        
        const event = VerificationEvent{
            .event_type = event_type,
            .old_level = old_level,
            .new_level = new_level,
            .evidence_id = if (self.evidence.items.len > 0) self.evidence.items.len - 1 else null,
            .timestamp = @intCast(std.time.timestamp()),
            .verifier_gid = verifier_gid,
            .notes = null,
        };
        
        try self.verification_history.append(event);
        self.current_level = new_level;
        self.last_updated = @intCast(std.time.timestamp());
    }
    
    /// Calculate verification level based on available evidence
    fn calculateVerificationLevel(self: *VerificationRecord) VerificationLevel {
        var max_level: VerificationLevel = .unverified;
        var evidence_score: u32 = 0;
        
        for (self.evidence.items) |evidence| {
            if (evidence.isExpired()) continue;
            
            evidence_score += evidence.confidence_score;
            
            const evidence_level: VerificationLevel = switch (evidence.evidence_type) {
                .government_id, .passport => .government,
                .drivers_license => .trusted_party,
                .third_party_kyc, .institutional_verification => .trusted_party,
                .blockchain_transaction => .on_chain,
                .social_account => .social_proof,
                .biometric_scan => .biometric,
                .device_attestation => .device_bound,
                else => .self_attested,
            };
            
            if (@intFromEnum(evidence_level) > @intFromEnum(max_level)) {
                max_level = evidence_level;
            }
        }
        
        // Require minimum evidence score for higher levels
        const required_scores = [_]u32{ 0, 50, 150, 250, 350, 450, 600, 800 };
        const level_index = @intFromEnum(max_level);
        
        if (evidence_score < required_scores[level_index]) {
            // Downgrade if insufficient evidence
            for (required_scores, 0..) |required, i| {
                if (evidence_score >= required) {
                    max_level = @enumFromInt(i);
                } else {
                    break;
                }
            }
        }
        
        return max_level;
    }
    
    /// Check if identity meets requirements for operation
    pub fn meetsRequirements(self: *VerificationRecord, requirements: VerificationRequirement) bool {
        // Check basic level requirement
        if (!self.current_level.canAccess(requirements.min_level)) {
            // Check grace period
            if (requirements.grace_period_hours) |grace_hours| {
                const grace_cutoff = @as(u64, @intCast(std.time.timestamp())) - (grace_hours * 3600);
                if (self.last_updated < grace_cutoff) {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        // Check additional requirements
        for (requirements.additional_checks) |check| {
            if (!self.checkAdditionalRequirement(check)) {
                return false;
            }
        }
        
        // Check for blocking flags
        if (self.flags.frozen or self.flags.high_risk) {
            return false;
        }
        
        return true;
    }
    
    fn checkAdditionalRequirement(self: *VerificationRecord, check: VerificationRequirement.VerificationCheck) bool {
        return switch (check) {
            .device_consistency => self.checkDeviceConsistency(),
            .location_consistency => self.checkLocationConsistency(),
            .time_since_verification => self.checkVerificationRecency(),
            .social_vouching => self.checkSocialVouching(),
            .transaction_history => self.checkTransactionHistory(),
        };
    }
    
    fn checkDeviceConsistency(self: *VerificationRecord) bool {
        // Check if verification done on consistent devices
        _ = self;
        return true; // Simplified for now
    }
    
    fn checkLocationConsistency(self: *VerificationRecord) bool {
        // Check for reasonable location patterns
        _ = self;
        return true; // Simplified for now
    }
    
    fn checkVerificationRecency(self: *VerificationRecord) bool {
        const week_ago = @as(u64, @intCast(std.time.timestamp())) - (7 * 24 * 3600);
        return self.last_updated > week_ago;
    }
    
    fn checkSocialVouching(self: *VerificationRecord) bool {
        // Check for peer attestations
        _ = self;
        return true; // Will integrate with attestations module
    }
    
    fn checkTransactionHistory(self: *VerificationRecord) bool {
        // Check for clean transaction history
        _ = self;
        return true; // Will integrate with reputation module
    }
    
    /// Get verification summary for display
    pub fn getSummary(self: *VerificationRecord, allocator: std.mem.Allocator) !VerificationSummary {
        var active_evidence = std.ArrayList(VerificationEvidence.EvidenceType).init(allocator);
        
        for (self.evidence.items) |evidence| {
            if (!evidence.isExpired()) {
                try active_evidence.append(evidence.evidence_type);
            }
        }
        
        return VerificationSummary{
            .level = self.current_level,
            .score = self.current_level.getScore(),
            .evidence_count = self.evidence.items.len,
            .active_evidence = try active_evidence.toOwnedSlice(),
            .last_updated = self.last_updated,
            .flags = self.flags,
        };
    }
};

pub const VerificationSummary = struct {
    level: VerificationLevel,
    score: u8,
    evidence_count: usize,
    active_evidence: []VerificationEvidence.EvidenceType,
    last_updated: u64,
    flags: VerificationRecord.VerificationFlags,
    
    pub fn deinit(self: VerificationSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.active_evidence);
    }
};

/// Verification service for managing identity verification
pub const VerificationService = struct {
    records: std.HashMap(GID, VerificationRecord, GIDContext, std.hash_map.default_max_load_percentage),
    trusted_verifiers: std.HashMap(GID, TrustedVerifier, GIDContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    const GIDContext = struct {
        pub fn hash(self: @This(), gid: GID) u64 {
            _ = self;
            return std.hash_map.hashString(&gid.public_key);
        }
        
        pub fn eql(self: @This(), a: GID, b: GID) bool {
            _ = self;
            return std.mem.eql(u8, &a.public_key, &b.public_key);
        }
    };
    
    pub const TrustedVerifier = struct {
        gid: GID,
        name: []const u8,
        verification_types: []VerificationEvidence.EvidenceType,
        trust_score: u8,
        active: bool,
    };
    
    pub fn init(allocator: std.mem.Allocator) VerificationService {
        return VerificationService{
            .records = std.HashMap(GID, VerificationRecord, GIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .trusted_verifiers = std.HashMap(GID, TrustedVerifier, GIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *VerificationService) void {
        var record_iter = self.records.iterator();
        while (record_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.records.deinit();
        self.trusted_verifiers.deinit();
    }
    
    /// Get or create verification record for identity
    pub fn getRecord(self: *VerificationService, gid: GID) !*VerificationRecord {
        if (self.records.getPtr(gid)) |record| {
            return record;
        }
        
        const new_record = VerificationRecord.init(self.allocator, gid);
        try self.records.put(gid, new_record);
        return self.records.getPtr(gid).?;
    }
    
    /// Submit verification evidence
    pub fn submitEvidence(self: *VerificationService, gid: GID, evidence: VerificationEvidence) !void {
        const record = try self.getRecord(gid);
        try record.addEvidence(evidence);
    }
    
    /// Register trusted verifier
    pub fn registerVerifier(self: *VerificationService, verifier: TrustedVerifier) !void {
        try self.trusted_verifiers.put(verifier.gid, verifier);
    }
    
    /// Check if verifier is trusted for evidence type
    pub fn isVerifierTrusted(self: *VerificationService, verifier_gid: GID, evidence_type: VerificationEvidence.EvidenceType) bool {
        if (self.trusted_verifiers.get(verifier_gid)) |verifier| {
            if (!verifier.active) return false;
            
            for (verifier.verification_types) |vtype| {
                if (vtype == evidence_type) return true;
            }
        }
        return false;
    }
};

test "verification levels" {
    const allocator = std.testing.allocator;
    
    // Test level comparison
    std.testing.expect(VerificationLevel.government.canAccess(.social_proof)) catch unreachable;
    std.testing.expect(!VerificationLevel.self_attested.canAccess(.biometric)) catch unreachable;
    
    // Test verification record
    const gid = GID{
        .public_key = [_]u8{1} ** 32,
        .chain_id = 1,
        .entity_type = .wallet,
        .version = 1,
    };
    
    var record = VerificationRecord.init(allocator, gid);
    defer record.deinit();
    
    std.testing.expect(record.current_level == .unverified) catch unreachable;
    
    // Test verification service
    var service = VerificationService.init(allocator);
    defer service.deinit();
    
    const test_record = try service.getRecord(gid);
    std.testing.expect(test_record.current_level == .unverified) catch unreachable;
}