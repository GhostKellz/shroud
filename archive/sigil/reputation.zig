//! Identity Reputation Scoring System
//! Dynamic reputation calculation and management for Ghost Chain identities

const std = @import("std");
const qid = @import("qid.zig");
const verification = @import("verification.zig");

const GID = qid.GID;
const VerificationLevel = verification.VerificationLevel;

/// Core reputation factors that influence scoring
pub const ReputationFactor = enum {
    transaction_history,    // Clean transaction record
    verification_level,     // Identity verification status
    network_activity,       // Positive network participation
    peer_endorsements,      // Vouching from other users
    protocol_compliance,    // Following network rules
    stake_commitment,       // Amount of tokens staked
    time_in_network,       // Account age and consistent activity
    dispute_resolution,     // How disputes were handled
    governance_participation, // Voting and proposal activity
};

/// Reputation scoring components with weights
pub const ReputationScore = struct {
    /// Core score (0-1000)
    base_score: u16 = 500,
    
    /// Factor-based scores (0-100 each)
    transaction_score: u8 = 50,
    verification_score: u8 = 0,
    activity_score: u8 = 50,
    endorsement_score: u8 = 0,
    compliance_score: u8 = 100,
    stake_score: u8 = 0,
    longevity_score: u8 = 0,
    governance_score: u8 = 0,
    
    /// Modifiers
    penalties: u16 = 0,        // Deductions for negative behavior
    bonuses: u16 = 0,          // Rewards for exceptional behavior
    
    /// Metadata
    last_calculated: u64,
    calculation_count: u32 = 1,
    
    /// Calculate final weighted reputation score
    pub fn getFinalScore(self: ReputationScore) u16 {
        const factor_weights = [_]u8{ 25, 20, 15, 15, 10, 10, 3, 2 }; // Sum = 100
        const factor_scores = [_]u8{
            self.transaction_score,
            self.verification_score,
            self.activity_score,
            self.endorsement_score,
            self.compliance_score,
            self.stake_score,
            self.longevity_score,
            self.governance_score,
        };
        
        var weighted_sum: u32 = 0;
        for (factor_scores, factor_weights) |score, weight| {
            weighted_sum += @as(u32, score) * @as(u32, weight);
        }
        
        // Scale from 0-10000 to 0-1000
        var final_score = @as(u16, @intCast(weighted_sum / 10));
        
        // Apply penalties and bonuses
        if (self.penalties > final_score) {
            final_score = 0;
        } else {
            final_score -= self.penalties;
        }
        
        final_score = @min(1000, final_score + self.bonuses);
        
        return final_score;
    }
    
    /// Get reputation tier based on score
    pub fn getTier(self: ReputationScore) ReputationTier {
        const score = self.getFinalScore();
        return ReputationTier.fromScore(score);
    }
    
    /// Check if score is above threshold
    pub fn meetsThreshold(self: ReputationScore, threshold: u16) bool {
        return self.getFinalScore() >= threshold;
    }
};

/// Reputation tiers for easy categorization
pub const ReputationTier = enum(u8) {
    untrusted = 0,      // 0-199: New or problematic
    emerging = 1,       // 200-399: Building reputation
    established = 2,    // 400-599: Solid reputation
    trusted = 3,        // 600-799: High reputation
    exemplary = 4,      // 800-899: Exceptional reputation
    legendary = 5,      // 900-1000: Top tier
    
    pub fn fromScore(score: u16) ReputationTier {
        return switch (score) {
            0...199 => .untrusted,
            200...399 => .emerging,
            400...599 => .established,
            600...799 => .trusted,
            800...899 => .exemplary,
            900...1000 => .legendary,
            else => .untrusted,
        };
    }
    
    pub fn toString(self: ReputationTier) []const u8 {
        return switch (self) {
            .untrusted => "Untrusted",
            .emerging => "Emerging",
            .established => "Established", 
            .trusted => "Trusted",
            .exemplary => "Exemplary",
            .legendary => "Legendary",
        };
    }
    
    pub fn getMinScore(self: ReputationTier) u16 {
        return switch (self) {
            .untrusted => 0,
            .emerging => 200,
            .established => 400,
            .trusted => 600,
            .exemplary => 800,
            .legendary => 900,
        };
    }
    
    /// Get privileges for this tier
    pub fn getPrivileges(self: ReputationTier) TierPrivileges {
        return switch (self) {
            .untrusted => TierPrivileges{
                .can_vote = false,
                .can_propose = false,
                .max_transaction_amount = 1000,
                .requires_escrow = true,
            },
            .emerging => TierPrivileges{
                .can_vote = false,
                .can_propose = false,
                .max_transaction_amount = 10000,
                .requires_escrow = true,
            },
            .established => TierPrivileges{
                .can_vote = true,
                .can_propose = false,
                .max_transaction_amount = 100000,
                .requires_escrow = false,
            },
            .trusted => TierPrivileges{
                .can_vote = true,
                .can_propose = true,
                .max_transaction_amount = 1000000,
                .requires_escrow = false,
            },
            .exemplary => TierPrivileges{
                .can_vote = true,
                .can_propose = true,
                .max_transaction_amount = 10000000,
                .requires_escrow = false,
            },
            .legendary => TierPrivileges{
                .can_vote = true,
                .can_propose = true,
                .max_transaction_amount = std.math.maxInt(u64),
                .requires_escrow = false,
            },
        };
    }
};

pub const TierPrivileges = struct {
    can_vote: bool,
    can_propose: bool,
    max_transaction_amount: u64,
    requires_escrow: bool,
};

/// Historical reputation events for audit trail
pub const ReputationEvent = struct {
    event_type: EventType,
    factor: ReputationFactor,
    score_change: i16,      // Can be negative
    description: []const u8,
    timestamp: u64,
    related_gid: ?GID = null, // For peer interactions
    transaction_hash: ?[32]u8 = null,
    
    pub const EventType = enum {
        score_increase,
        score_decrease,
        penalty_applied,
        bonus_awarded,
        tier_change,
        manual_adjustment,
        system_recalculation,
    };
};

/// Complete reputation record for an identity
pub const ReputationRecord = struct {
    gid: GID,
    current_score: ReputationScore,
    historical_scores: std.ArrayList(ReputationScore),
    events: std.ArrayList(ReputationEvent),
    
    /// Interaction tracking
    successful_transactions: u32 = 0,
    failed_transactions: u32 = 0,
    disputed_transactions: u32 = 0,
    resolved_disputes: u32 = 0,
    
    /// Network participation
    votes_cast: u32 = 0,
    proposals_made: u32 = 0,
    governance_participation_rate: u8 = 0, // 0-100%
    
    /// Endorsements
    endorsements_received: u32 = 0,
    endorsements_given: u32 = 0,
    
    /// Time-based factors
    account_created: u64,
    last_active: u64,
    consecutive_active_days: u32 = 0,
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, gid: GID) ReputationRecord {
        const now = @as(u64, @intCast(std.time.timestamp()));
        
        return ReputationRecord{
            .gid = gid,
            .current_score = ReputationScore{
                .last_calculated = now,
            },
            .historical_scores = std.ArrayList(ReputationScore).init(allocator),
            .events = std.ArrayList(ReputationEvent).init(allocator),
            .account_created = now,
            .last_active = now,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ReputationRecord) void {
        self.historical_scores.deinit();
        for (self.events.items) |event| {
            self.allocator.free(event.description);
        }
        self.events.deinit();
    }
    
    /// Recalculate reputation score based on current data
    pub fn recalculateScore(self: *ReputationRecord, verification_level: VerificationLevel) !void {
        // Save current score to history
        try self.historical_scores.append(self.current_score);
        
        var new_score = ReputationScore{
            .last_calculated = @intCast(std.time.timestamp()),
            .calculation_count = self.current_score.calculation_count + 1,
        };
        
        // Calculate transaction score (0-100)
        if (self.successful_transactions + self.failed_transactions > 0) {
            const success_rate = (@as(u32, self.successful_transactions) * 100) / 
                (self.successful_transactions + self.failed_transactions);
            new_score.transaction_score = @min(100, @intCast(success_rate));
            
            // Penalty for disputes
            if (self.disputed_transactions > 0) {
                const dispute_rate = (self.disputed_transactions * 100) / self.successful_transactions;
                new_score.transaction_score = new_score.transaction_score -| @intCast(@min(50, dispute_rate));
            }
        }
        
        // Calculate verification score based on verification level
        new_score.verification_score = verification_level.getScore();
        
        // Calculate activity score
        new_score.activity_score = self.calculateActivityScore();
        
        // Calculate endorsement score
        new_score.endorsement_score = self.calculateEndorsementScore();
        
        // Calculate longevity score
        new_score.longevity_score = self.calculateLongevityScore();
        
        // Calculate governance score
        new_score.governance_score = @min(100, self.governance_participation_rate);
        
        // Record score change event
        const old_final = self.current_score.getFinalScore();
        const new_final = new_score.getFinalScore();
        
        if (new_final != old_final) {
            try self.addEvent(ReputationEvent{
                .event_type = .system_recalculation,
                .factor = .network_activity,
                .score_change = @as(i16, @intCast(new_final)) - @as(i16, @intCast(old_final)),
                .description = try self.allocator.dupe(u8, "Automated score recalculation"),
                .timestamp = @intCast(std.time.timestamp()),
            });
        }
        
        self.current_score = new_score;
    }
    
    /// Add reputation event to history
    pub fn addEvent(self: *ReputationRecord, event: ReputationEvent) !void {
        try self.events.append(event);
    }
    
    /// Apply manual adjustment (admin/governance action)
    pub fn applyManualAdjustment(self: *ReputationRecord, score_change: i16, reason: []const u8) !void {
        if (score_change > 0) {
            self.current_score.bonuses += @intCast(score_change);
        } else {
            self.current_score.penalties += @intCast(-score_change);
        }
        
        try self.addEvent(ReputationEvent{
            .event_type = .manual_adjustment,
            .factor = .protocol_compliance,
            .score_change = score_change,
            .description = try self.allocator.dupe(u8, reason),
            .timestamp = @intCast(std.time.timestamp()),
        });
    }
    
    /// Record successful transaction
    pub fn recordTransaction(self: *ReputationRecord, success: bool, disputed: bool) !void {
        if (success) {
            self.successful_transactions += 1;
            if (!disputed) {
                // Small bonus for clean transactions
                self.current_score.bonuses += 1;
            }
        } else {
            self.failed_transactions += 1;
        }
        
        if (disputed) {
            self.disputed_transactions += 1;
        }
        
        try self.addEvent(ReputationEvent{
            .event_type = if (success) .score_increase else .score_decrease,
            .factor = .transaction_history,
            .score_change = if (success) 1 else -2,
            .description = try self.allocator.dupe(u8, if (success) "Successful transaction" else "Failed transaction"),
            .timestamp = @intCast(std.time.timestamp()),
        });
    }
    
    /// Record endorsement given or received
    pub fn recordEndorsement(self: *ReputationRecord, received: bool, from_gid: ?GID) !void {
        if (received) {
            self.endorsements_received += 1;
        } else {
            self.endorsements_given += 1;
        }
        
        try self.addEvent(ReputationEvent{
            .event_type = .score_increase,
            .factor = .peer_endorsements,
            .score_change = if (received) 5 else 1,
            .description = try self.allocator.dupe(u8, if (received) "Endorsement received" else "Endorsement given"),
            .timestamp = @intCast(std.time.timestamp()),
            .related_gid = from_gid,
        });
    }
    
    fn calculateActivityScore(self: *ReputationRecord) u8 {
        const now = @as(u64, @intCast(std.time.timestamp()));
        const days_since_last_active = (now - self.last_active) / (24 * 3600);
        
        // Start with base activity score
        var score: u8 = 50;
        
        // Bonus for consecutive active days
        score += @min(30, self.consecutive_active_days / 10);
        
        // Penalty for inactivity
        if (days_since_last_active > 30) {
            score = score -| @intCast(@min(40, days_since_last_active - 30));
        }
        
        return score;
    }
    
    fn calculateEndorsementScore(self: *ReputationRecord) u8 {
        // Base score from endorsements received
        var score = @min(80, self.endorsements_received * 2);
        
        // Bonus for giving endorsements (shows community participation)
        score += @min(20, self.endorsements_given);
        
        return @min(100, score);
    }
    
    fn calculateLongevityScore(self: *ReputationRecord) u8 {
        const now = @as(u64, @intCast(std.time.timestamp()));
        const days_since_creation = (now - self.account_created) / (24 * 3600);
        
        // Score increases over time, capping at 100 after 2 years
        return @min(100, @intCast(days_since_creation / 7)); // 1 point per week
    }
    
    /// Get reputation summary for display
    pub fn getSummary(self: *ReputationRecord) ReputationSummary {
        const tier = self.current_score.getTier();
        
        return ReputationSummary{
            .gid = self.gid,
            .score = self.current_score.getFinalScore(),
            .tier = tier,
            .total_transactions = self.successful_transactions + self.failed_transactions,
            .success_rate = if (self.successful_transactions + self.failed_transactions > 0)
                (@as(u32, self.successful_transactions) * 100) / (self.successful_transactions + self.failed_transactions)
            else
                0,
            .endorsements = self.endorsements_received,
            .account_age_days = @intCast((@as(u64, @intCast(std.time.timestamp())) - self.account_created) / (24 * 3600)),
            .last_updated = self.current_score.last_calculated,
        };
    }
};

pub const ReputationSummary = struct {
    gid: GID,
    score: u16,
    tier: ReputationTier,
    total_transactions: u32,
    success_rate: u32, // Percentage
    endorsements: u32,
    account_age_days: u32,
    last_updated: u64,
};

/// Reputation service for managing identity reputation across the network
pub const ReputationService = struct {
    records: std.HashMap(GID, ReputationRecord, GIDContext, std.hash_map.default_max_load_percentage),
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
    
    pub fn init(allocator: std.mem.Allocator) ReputationService {
        return ReputationService{
            .records = std.HashMap(GID, ReputationRecord, GIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ReputationService) void {
        var iter = self.records.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.records.deinit();
    }
    
    /// Get or create reputation record for identity
    pub fn getRecord(self: *ReputationService, gid: GID) !*ReputationRecord {
        if (self.records.getPtr(gid)) |record| {
            return record;
        }
        
        const new_record = ReputationRecord.init(self.allocator, gid);
        try self.records.put(gid, new_record);
        return self.records.getPtr(gid).?;
    }
    
    /// Update reputation scores for all identities
    pub fn updateAllScores(self: *ReputationService) !void {
        var iter = self.records.iterator();
        while (iter.next()) |entry| {
            // Would need verification service integration here
            try entry.value_ptr.recalculateScore(.unverified);
        }
    }
    
    /// Get reputation rankings
    pub fn getTopReputations(self: *ReputationService, count: u32, allocator: std.mem.Allocator) ![]ReputationSummary {
        var summaries = std.ArrayList(ReputationSummary).init(allocator);
        
        var iter = self.records.iterator();
        while (iter.next()) |entry| {
            try summaries.append(entry.value_ptr.getSummary());
        }
        
        // Sort by score (descending)
        std.sort.pdq(ReputationSummary, summaries.items, {}, struct {
            fn lessThan(_: void, a: ReputationSummary, b: ReputationSummary) bool {
                return a.score > b.score;
            }
        }.lessThan);
        
        const result_count = @min(count, summaries.items.len);
        const result = try allocator.alloc(ReputationSummary, result_count);
        @memcpy(result, summaries.items[0..result_count]);
        
        summaries.deinit();
        return result;
    }
    
    /// Get network reputation statistics
    pub fn getNetworkStats(self: *ReputationService) NetworkReputationStats {
        var stats = NetworkReputationStats{};
        var total_score: u64 = 0;
        
        var tier_counts = [_]u32{0} ** 6;
        
        var iter = self.records.iterator();
        while (iter.next()) |entry| {
            const record = entry.value_ptr;
            const score = record.current_score.getFinalScore();
            const tier = record.current_score.getTier();
            
            stats.total_identities += 1;
            total_score += score;
            tier_counts[@intFromEnum(tier)] += 1;
            
            if (score >= 800) stats.high_reputation_count += 1;
            if (record.successful_transactions > 0) stats.active_participants += 1;
        }
        
        if (stats.total_identities > 0) {
            stats.average_score = @intCast(total_score / stats.total_identities);
        }
        
        stats.tier_distribution = tier_counts;
        
        return stats;
    }
    
    pub const NetworkReputationStats = struct {
        total_identities: u32 = 0,
        average_score: u16 = 0,
        high_reputation_count: u32 = 0,
        active_participants: u32 = 0,
        tier_distribution: [6]u32 = [_]u32{0} ** 6,
    };
};

test "reputation scoring" {
    const allocator = std.testing.allocator;
    
    const gid = GID{
        .public_key = [_]u8{1} ** 32,
        .chain_id = 1,
        .entity_type = .wallet,
        .version = 1,
    };
    
    // Test reputation record
    var record = ReputationRecord.init(allocator, gid);
    defer record.deinit();
    
    // Test initial score
    std.testing.expect(record.current_score.getFinalScore() == 500) catch unreachable;
    std.testing.expect(record.current_score.getTier() == .established) catch unreachable;
    
    // Test transaction recording
    try record.recordTransaction(true, false);
    std.testing.expect(record.successful_transactions == 1) catch unreachable;
    
    // Test reputation service
    var service = ReputationService.init(allocator);
    defer service.deinit();
    
    const managed_record = try service.getRecord(gid);
    std.testing.expect(managed_record.gid.chain_id == 1) catch unreachable;
    
    // Test tier privileges
    const tier_privileges = ReputationTier.trusted.getPrivileges();
    std.testing.expect(tier_privileges.can_vote) catch unreachable;
    std.testing.expect(tier_privileges.can_propose) catch unreachable;
}