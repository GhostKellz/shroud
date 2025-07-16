//! Identity Analytics Dashboard
//! Comprehensive analytics and insights for Ghost Chain identity ecosystem

const std = @import("std");
const qid = @import("qid.zig");
const verification = @import("verification.zig");
const reputation = @import("reputation.zig");
const privacy = @import("privacy.zig");
const profile = @import("profile.zig");
const social_linking = @import("social_linking.zig");

const GID = qid.GID;
const VerificationLevel = verification.VerificationLevel;
const ReputationTier = reputation.ReputationTier;
const PrivacySettings = privacy.PrivacySettings;
const SocialPlatform = social_linking.SocialPlatform;

/// Time-series data point for analytics
pub const DataPoint = struct {
    timestamp: u64,
    value: f64,
    metadata: ?[]const u8 = null,
};

/// Metrics collection for identity analytics
pub const IdentityMetrics = struct {
    gid: GID,
    
    /// Verification metrics
    verification_level: VerificationLevel,
    verification_score: u8,
    verification_history: std.ArrayList(DataPoint),
    
    /// Reputation metrics
    reputation_score: u16,
    reputation_tier: ReputationTier,
    reputation_history: std.ArrayList(DataPoint),
    
    /// Activity metrics
    daily_active_sessions: std.ArrayList(DataPoint),
    transaction_volume: std.ArrayList(DataPoint),
    social_interactions: std.ArrayList(DataPoint),
    
    /// Privacy metrics
    privacy_score: u8,
    data_sharing_level: u8,
    privacy_events: std.ArrayList(DataPoint),
    
    /// Social proof metrics
    verified_social_accounts: u8,
    social_proof_score: u16,
    social_growth: std.ArrayList(DataPoint),
    
    /// Engagement metrics
    profile_views: std.ArrayList(DataPoint),
    endorsements_received: std.ArrayList(DataPoint),
    network_connections: std.ArrayList(DataPoint),
    
    last_updated: u64,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, gid: GID) IdentityMetrics {
        return IdentityMetrics{
            .gid = gid,
            .verification_level = .unverified,
            .verification_score = 0,
            .verification_history = std.ArrayList(DataPoint).init(allocator),
            .reputation_score = 500,
            .reputation_tier = .established,
            .reputation_history = std.ArrayList(DataPoint).init(allocator),
            .daily_active_sessions = std.ArrayList(DataPoint).init(allocator),
            .transaction_volume = std.ArrayList(DataPoint).init(allocator),
            .social_interactions = std.ArrayList(DataPoint).init(allocator),
            .privacy_score = 50,
            .data_sharing_level = 2,
            .privacy_events = std.ArrayList(DataPoint).init(allocator),
            .verified_social_accounts = 0,
            .social_proof_score = 0,
            .social_growth = std.ArrayList(DataPoint).init(allocator),
            .profile_views = std.ArrayList(DataPoint).init(allocator),
            .endorsements_received = std.ArrayList(DataPoint).init(allocator),
            .network_connections = std.ArrayList(DataPoint).init(allocator),
            .last_updated = @intCast(std.time.timestamp()),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *IdentityMetrics) void {
        self.verification_history.deinit();
        self.reputation_history.deinit();
        self.daily_active_sessions.deinit();
        self.transaction_volume.deinit();
        self.social_interactions.deinit();
        self.privacy_events.deinit();
        self.social_growth.deinit();
        self.profile_views.deinit();
        self.endorsements_received.deinit();
        self.network_connections.deinit();
    }
    
    /// Record a new data point for a metric
    pub fn recordDataPoint(self: *IdentityMetrics, metric_type: MetricType, value: f64, metadata: ?[]const u8) !void {
        const now = @as(u64, @intCast(std.time.timestamp()));
        const data_point = DataPoint{
            .timestamp = now,
            .value = value,
            .metadata = if (metadata) |m| try self.allocator.dupe(u8, m) else null,
        };
        
        const metric_list = switch (metric_type) {
            .verification_score => &self.verification_history,
            .reputation_score => &self.reputation_history,
            .daily_sessions => &self.daily_active_sessions,
            .transaction_volume => &self.transaction_volume,
            .social_interactions => &self.social_interactions,
            .privacy_events => &self.privacy_events,
            .social_growth => &self.social_growth,
            .profile_views => &self.profile_views,
            .endorsements => &self.endorsements_received,
            .network_connections => &self.network_connections,
        };
        
        try metric_list.append(data_point);
        self.last_updated = now;
        
        // Keep only last 30 days of data
        self.pruneOldData(metric_list, 30);
    }
    
    pub const MetricType = enum {
        verification_score,
        reputation_score,
        daily_sessions,
        transaction_volume,
        social_interactions,
        privacy_events,
        social_growth,
        profile_views,
        endorsements,
        network_connections,
    };
    
    fn pruneOldData(self: *IdentityMetrics, metric_list: *std.ArrayList(DataPoint), days_to_keep: u32) void {
        _ = self;
        const cutoff = @as(u64, @intCast(std.time.timestamp())) - (days_to_keep * 24 * 3600);
        
        var i: usize = 0;
        while (i < metric_list.items.len) {
            if (metric_list.items[i].timestamp < cutoff) {
                if (metric_list.items[i].metadata) |metadata| {
                    // Note: This would need allocator tracking in a real implementation
                    _ = metadata; // Free metadata
                }
                _ = metric_list.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
    
    /// Calculate trend for a metric over specified period
    pub fn calculateTrend(self: *IdentityMetrics, metric_type: MetricType, days: u32) TrendAnalysis {
        const metric_list = switch (metric_type) {
            .verification_score => &self.verification_history,
            .reputation_score => &self.reputation_history,
            .daily_sessions => &self.daily_active_sessions,
            .transaction_volume => &self.transaction_volume,
            .social_interactions => &self.social_interactions,
            .privacy_events => &self.privacy_events,
            .social_growth => &self.social_growth,
            .profile_views => &self.profile_views,
            .endorsements => &self.endorsements_received,
            .network_connections => &self.network_connections,
        };
        
        const cutoff = @as(u64, @intCast(std.time.timestamp())) - (days * 24 * 3600);
        var recent_data = std.ArrayList(f64).init(self.allocator);
        defer recent_data.deinit();
        
        for (metric_list.items) |point| {
            if (point.timestamp >= cutoff) {
                recent_data.append(point.value) catch continue;
            }
        }
        
        return TrendAnalysis.calculate(recent_data.items);
    }
    
    /// Get summary statistics for all metrics
    pub fn getSummary(self: *IdentityMetrics) IdentityAnalyticsSummary {
        return IdentityAnalyticsSummary{
            .gid = self.gid,
            .verification_level = self.verification_level,
            .reputation_score = self.reputation_score,
            .reputation_tier = self.reputation_tier,
            .privacy_score = self.privacy_score,
            .social_accounts = self.verified_social_accounts,
            .social_proof_score = self.social_proof_score,
            .total_profile_views = self.getTotalValue(.profile_views),
            .total_endorsements = @intCast(self.getTotalValue(.endorsements)),
            .activity_trend = self.calculateTrend(.daily_sessions, 7),
            .reputation_trend = self.calculateTrend(.reputation_score, 30),
            .last_updated = self.last_updated,
        };
    }
    
    fn getTotalValue(self: *IdentityMetrics, metric_type: MetricType) f64 {
        const metric_list = switch (metric_type) {
            .verification_score => &self.verification_history,
            .reputation_score => &self.reputation_history,
            .daily_sessions => &self.daily_active_sessions,
            .transaction_volume => &self.transaction_volume,
            .social_interactions => &self.social_interactions,
            .privacy_events => &self.privacy_events,
            .social_growth => &self.social_growth,
            .profile_views => &self.profile_views,
            .endorsements => &self.endorsements_received,
            .network_connections => &self.network_connections,
        };
        
        var total: f64 = 0;
        for (metric_list.items) |point| {
            total += point.value;
        }
        return total;
    }
};

/// Trend analysis result
pub const TrendAnalysis = struct {
    direction: TrendDirection,
    magnitude: f64,      // Percentage change
    confidence: f64,     // 0-1 confidence score
    data_points: u32,
    
    pub const TrendDirection = enum {
        increasing,
        decreasing,
        stable,
        insufficient_data,
    };
    
    pub fn calculate(data: []const f64) TrendAnalysis {
        if (data.len < 2) {
            return TrendAnalysis{
                .direction = .insufficient_data,
                .magnitude = 0,
                .confidence = 0,
                .data_points = @intCast(data.len),
            };
        }
        
        // Simple linear regression slope calculation
        const n = @as(f64, @floatFromInt(data.len));
        var sum_x: f64 = 0;
        var sum_y: f64 = 0;
        var sum_xy: f64 = 0;
        var sum_x2: f64 = 0;
        
        for (data, 0..) |y, i| {
            const x = @as(f64, @floatFromInt(i));
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }
        
        const slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        const magnitude = @abs(slope) * 100; // Convert to percentage
        
        // Calculate confidence based on data consistency
        var variance: f64 = 0;
        const mean = sum_y / n;
        for (data) |value| {
            variance += (value - mean) * (value - mean);
        }
        variance /= n;
        
        const confidence = 1.0 - @min(1.0, variance / (mean * mean + 1));
        
        return TrendAnalysis{
            .direction = if (slope > 0.1) .increasing else if (slope < -0.1) .decreasing else .stable,
            .magnitude = magnitude,
            .confidence = confidence,
            .data_points = @intCast(data.len),
        };
    }
};

/// Individual identity analytics summary
pub const IdentityAnalyticsSummary = struct {
    gid: GID,
    verification_level: VerificationLevel,
    reputation_score: u16,
    reputation_tier: ReputationTier,
    privacy_score: u8,
    social_accounts: u8,
    social_proof_score: u16,
    total_profile_views: f64,
    total_endorsements: u32,
    activity_trend: TrendAnalysis,
    reputation_trend: TrendAnalysis,
    last_updated: u64,
};

/// Network-wide analytics aggregation
pub const NetworkAnalytics = struct {
    /// Identity distribution
    total_identities: u32 = 0,
    verification_distribution: [8]u32 = [_]u32{0} ** 8, // By verification level
    reputation_distribution: [6]u32 = [_]u32{0} ** 6,   // By reputation tier
    
    /// Activity metrics
    daily_active_identities: u32 = 0,
    weekly_active_identities: u32 = 0,
    monthly_active_identities: u32 = 0,
    
    /// Growth metrics
    new_identities_today: u32 = 0,
    new_identities_week: u32 = 0,
    new_identities_month: u32 = 0,
    
    /// Verification trends
    average_verification_score: f64 = 0,
    verification_completion_rate: f64 = 0, // % with verified level > unverified
    
    /// Reputation trends
    average_reputation_score: f64 = 0,
    high_reputation_percentage: f64 = 0, // % with reputation >= trusted
    
    /// Social proof metrics
    social_linking_adoption: f64 = 0,     // % with at least one verified social link
    average_social_accounts: f64 = 0,
    platform_popularity: [@typeInfo(SocialPlatform).Enum.fields.len]u32 = [_]u32{0} ** @typeInfo(SocialPlatform).Enum.fields.len,
    
    /// Privacy metrics
    average_privacy_score: f64 = 0,
    privacy_conscious_percentage: f64 = 0, // % with privacy score > 70
    
    /// Network health
    dispute_rate: f64 = 0,
    resolution_rate: f64 = 0,
    network_trust_score: f64 = 0,
    
    last_calculated: u64,
    
    pub fn init() NetworkAnalytics {
        return NetworkAnalytics{
            .last_calculated = @intCast(std.time.timestamp()),
        };
    }
};

/// Analytics dashboard service
pub const AnalyticsService = struct {
    identity_metrics: std.HashMap(GID, IdentityMetrics, GIDContext, std.hash_map.default_max_load_percentage),
    network_analytics: NetworkAnalytics,
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
    
    pub fn init(allocator: std.mem.Allocator) AnalyticsService {
        return AnalyticsService{
            .identity_metrics = std.HashMap(GID, IdentityMetrics, GIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .network_analytics = NetworkAnalytics.init(),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *AnalyticsService) void {
        var iter = self.identity_metrics.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.identity_metrics.deinit();
    }
    
    /// Get or create metrics for identity
    pub fn getMetrics(self: *AnalyticsService, gid: GID) !*IdentityMetrics {
        if (self.identity_metrics.getPtr(gid)) |metrics| {
            return metrics;
        }
        
        const new_metrics = IdentityMetrics.init(self.allocator, gid);
        try self.identity_metrics.put(gid, new_metrics);
        return self.identity_metrics.getPtr(gid).?;
    }
    
    /// Record event for identity
    pub fn recordEvent(self: *AnalyticsService, gid: GID, metric_type: IdentityMetrics.MetricType, value: f64, metadata: ?[]const u8) !void {
        const metrics = try self.getMetrics(gid);
        try metrics.recordDataPoint(metric_type, value, metadata);
    }
    
    /// Update analytics from identity services
    pub fn updateFromServices(
        self: *AnalyticsService, 
        verification_service: anytype,
        reputation_service: anytype,
        privacy_manager: anytype,
        social_service: anytype,
        profile_manager: anytype
    ) !void {
        _ = verification_service;
        _ = reputation_service; 
        _ = privacy_manager;
        _ = social_service;
        _ = profile_manager;
        
        // In a real implementation, this would iterate through all services
        // and update analytics based on current state
        
        try self.calculateNetworkAnalytics();
    }
    
    /// Calculate network-wide analytics
    pub fn calculateNetworkAnalytics(self: *AnalyticsService) !void {
        var analytics = NetworkAnalytics.init();
        var total_verification_score: f64 = 0;
        var total_reputation_score: f64 = 0;
        var total_privacy_score: f64 = 0;
        var total_social_accounts: f64 = 0;
        var identities_with_social: u32 = 0;
        var high_privacy_count: u32 = 0;
        var high_reputation_count: u32 = 0;
        
        var iter = self.identity_metrics.iterator();
        while (iter.next()) |entry| {
            const metrics = entry.value_ptr;
            
            analytics.total_identities += 1;
            
            // Verification distribution
            analytics.verification_distribution[@intFromEnum(metrics.verification_level)] += 1;
            total_verification_score += @floatFromInt(metrics.verification_score);
            
            // Reputation distribution
            analytics.reputation_distribution[@intFromEnum(metrics.reputation_tier)] += 1;
            total_reputation_score += @floatFromInt(metrics.reputation_score);
            
            if (metrics.reputation_tier == .trusted or 
                metrics.reputation_tier == .exemplary or 
                metrics.reputation_tier == .legendary) {
                high_reputation_count += 1;
            }
            
            // Privacy metrics
            total_privacy_score += @floatFromInt(metrics.privacy_score);
            if (metrics.privacy_score > 70) {
                high_privacy_count += 1;
            }
            
            // Social metrics
            if (metrics.verified_social_accounts > 0) {
                identities_with_social += 1;
                total_social_accounts += @floatFromInt(metrics.verified_social_accounts);
            }
        }
        
        // Calculate averages and percentages
        if (analytics.total_identities > 0) {
            analytics.average_verification_score = total_verification_score / @as(f64, @floatFromInt(analytics.total_identities));
            analytics.average_reputation_score = total_reputation_score / @as(f64, @floatFromInt(analytics.total_identities));
            analytics.average_privacy_score = total_privacy_score / @as(f64, @floatFromInt(analytics.total_identities));
            
            analytics.verification_completion_rate = (@as(f64, @floatFromInt(analytics.total_identities - analytics.verification_distribution[0])) / @as(f64, @floatFromInt(analytics.total_identities))) * 100;
            analytics.high_reputation_percentage = (@as(f64, @floatFromInt(high_reputation_count)) / @as(f64, @floatFromInt(analytics.total_identities))) * 100;
            analytics.privacy_conscious_percentage = (@as(f64, @floatFromInt(high_privacy_count)) / @as(f64, @floatFromInt(analytics.total_identities))) * 100;
            analytics.social_linking_adoption = (@as(f64, @floatFromInt(identities_with_social)) / @as(f64, @floatFromInt(analytics.total_identities))) * 100;
            
            if (identities_with_social > 0) {
                analytics.average_social_accounts = total_social_accounts / @as(f64, @floatFromInt(identities_with_social));
            }
        }
        
        // Calculate network trust score (composite metric)
        analytics.network_trust_score = (
            analytics.average_verification_score * 0.3 +
            (analytics.average_reputation_score / 10) * 0.4 +
            analytics.average_privacy_score * 0.2 +
            (analytics.social_linking_adoption / 100) * 0.1
        );
        
        self.network_analytics = analytics;
    }
    
    /// Get identity analytics summary
    pub fn getIdentitySummary(self: *AnalyticsService, gid: GID) ?IdentityAnalyticsSummary {
        if (self.identity_metrics.get(gid)) |metrics| {
            return metrics.getSummary();
        }
        return null;
    }
    
    /// Get network analytics
    pub fn getNetworkAnalytics(self: *AnalyticsService) NetworkAnalytics {
        return self.network_analytics;
    }
    
    /// Get top performers in various categories
    pub fn getTopPerformers(self: *AnalyticsService, category: PerformanceCategory, count: u32, allocator: std.mem.Allocator) ![]IdentityAnalyticsSummary {
        var summaries = std.ArrayList(IdentityAnalyticsSummary).init(allocator);
        
        var iter = self.identity_metrics.iterator();
        while (iter.next()) |entry| {
            try summaries.append(entry.value_ptr.getSummary());
        }
        
        // Sort by specified category
        std.sort.pdq(IdentityAnalyticsSummary, summaries.items, category, struct {
            fn lessThan(cat: PerformanceCategory, a: IdentityAnalyticsSummary, b: IdentityAnalyticsSummary) bool {
                return switch (cat) {
                    .reputation => a.reputation_score > b.reputation_score,
                    .verification => @intFromEnum(a.verification_level) > @intFromEnum(b.verification_level),
                    .social_proof => a.social_proof_score > b.social_proof_score,
                    .privacy => a.privacy_score > b.privacy_score,
                    .activity => a.total_profile_views > b.total_profile_views,
                };
            }
        }.lessThan);
        
        const result_count = @min(count, summaries.items.len);
        const result = try allocator.alloc(IdentityAnalyticsSummary, result_count);
        @memcpy(result, summaries.items[0..result_count]);
        
        summaries.deinit();
        return result;
    }
    
    pub const PerformanceCategory = enum {
        reputation,
        verification,
        social_proof,
        privacy,
        activity,
    };
};

test "identity analytics" {
    const allocator = std.testing.allocator;
    
    const gid = GID{
        .public_key = [_]u8{1} ** 32,
        .chain_id = 1,
        .entity_type = .wallet,
        .version = 1,
    };
    
    // Test identity metrics
    var metrics = IdentityMetrics.init(allocator, gid);
    defer metrics.deinit();
    
    // Record some test data
    try metrics.recordDataPoint(.reputation_score, 750, "Test reputation");
    try metrics.recordDataPoint(.verification_score, 85, "Test verification");
    
    // Test trend calculation
    const trend = metrics.calculateTrend(.reputation_score, 7);
    std.testing.expect(trend.data_points >= 1) catch unreachable;
    
    // Test analytics service
    var service = AnalyticsService.init(allocator);
    defer service.deinit();
    
    const managed_metrics = try service.getMetrics(gid);
    try service.recordEvent(gid, .profile_views, 10, "Profile viewed");
    
    std.testing.expect(managed_metrics.gid.chain_id == 1) catch unreachable;
    
    // Test network analytics calculation
    try service.calculateNetworkAnalytics();
    const network_stats = service.getNetworkAnalytics();
    std.testing.expect(network_stats.total_identities >= 1) catch unreachable;
}