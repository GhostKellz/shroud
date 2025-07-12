//! Privacy Controls System
//! Comprehensive privacy settings and data sharing controls for Ghost Chain identities

const std = @import("std");
const qid = @import("qid.zig");

const GID = qid.GID;

/// Data sharing consent levels
pub const DataSharingLevel = enum(u8) {
    none = 0,           // No data sharing
    minimal = 1,        // Only essential data
    functional = 2,     // Data needed for features
    analytics = 3,      // Include usage analytics
    marketing = 4,      // Include marketing data
    full = 5,          // All data sharing
    
    pub fn toString(self: DataSharingLevel) []const u8 {
        return switch (self) {
            .none => "No Data Sharing",
            .minimal => "Minimal Only",
            .functional => "Functional",
            .analytics => "With Analytics",
            .marketing => "With Marketing",
            .full => "Full Sharing",
        };
    }
    
    pub fn allowsDataType(self: DataSharingLevel, data_type: DataType) bool {
        return switch (data_type) {
            .essential => @intFromEnum(self) >= @intFromEnum(DataSharingLevel.minimal),
            .functional => @intFromEnum(self) >= @intFromEnum(DataSharingLevel.functional),
            .analytics => @intFromEnum(self) >= @intFromEnum(DataSharingLevel.analytics),
            .marketing => @intFromEnum(self) >= @intFromEnum(DataSharingLevel.marketing),
            .experimental => @intFromEnum(self) >= @intFromEnum(DataSharingLevel.full),
        };
    }
};

/// Types of data that can be shared
pub const DataType = enum {
    essential,      // Required for basic functionality
    functional,     // Enhances user experience
    analytics,      // Usage patterns and performance
    marketing,      // Personalization and recommendations
    experimental,   // Beta features and research
};

/// Visibility levels for different aspects of identity
pub const VisibilityLevel = enum(u8) {
    private = 0,        // Only me
    contacts = 1,       // Only my contacts
    verified = 2,       // Only verified users
    network = 3,        // My network (2nd degree)
    public = 4,         // Everyone
    
    pub fn toString(self: VisibilityLevel) []const u8 {
        return switch (self) {
            .private => "Private",
            .contacts => "Contacts Only",
            .verified => "Verified Users",
            .network => "Extended Network",
            .public => "Public",
        };
    }
    
    pub fn canAccess(self: VisibilityLevel, relationship: RelationshipType) bool {
        return switch (self) {
            .private => false,
            .contacts => relationship == .direct_contact,
            .verified => relationship == .direct_contact or relationship == .verified_user,
            .network => relationship != .stranger,
            .public => true,
        };
    }
};

/// Relationship types for access control
pub const RelationshipType = enum {
    self,           // The identity owner
    direct_contact, // Known contact
    verified_user,  // Verified but not contact
    network_connection, // Friend of friend
    stranger,       // Unknown user
};

/// Communication preferences
pub const CommunicationSettings = struct {
    allow_direct_messages: bool = true,
    allow_group_invites: bool = true,
    allow_service_notifications: bool = true,
    allow_marketing_messages: bool = false,
    allow_friend_requests: bool = true,
    require_verification_for_contact: bool = false,
    
    /// Message filtering settings
    auto_filter_spam: bool = true,
    require_payment_for_unsolicited: bool = false,
    minimum_stake_for_contact: u64 = 0, // Minimum tokens staked to contact
    
    /// Response time expectations
    typical_response_time: ResponseTime = .hours,
    
    pub const ResponseTime = enum {
        immediate,  // Within minutes
        hours,      // Within hours  
        days,       // Within days
        weeks,      // Whenever
        never,      // Don't expect responses
    };
};

/// Location privacy settings
pub const LocationSettings = struct {
    share_precise_location: bool = false,
    share_city_only: bool = false,
    share_country_only: bool = true,
    share_timezone: bool = true,
    
    /// Geofencing for enhanced privacy
    privacy_zones: std.ArrayList(PrivacyZone),
    
    pub const PrivacyZone = struct {
        name: []const u8,
        latitude: f64,
        longitude: f64,
        radius_meters: f64,
        privacy_level: VisibilityLevel,
    };
    
    pub fn init(allocator: std.mem.Allocator) LocationSettings {
        return LocationSettings{
            .privacy_zones = std.ArrayList(PrivacyZone).init(allocator),
        };
    }
    
    pub fn deinit(self: *LocationSettings) void {
        self.privacy_zones.deinit();
    }
};

/// Financial privacy settings
pub const FinancialSettings = struct {
    show_wallet_balance: VisibilityLevel = .private,
    show_transaction_history: VisibilityLevel = .private,
    show_nft_collection: VisibilityLevel = .contacts,
    show_staking_amount: VisibilityLevel = .private,
    show_defi_positions: VisibilityLevel = .private,
    
    /// Transaction privacy preferences
    default_transaction_privacy: TransactionPrivacy = .confidential,
    require_memo_encryption: bool = true,
    auto_use_stealth_addresses: bool = false,
    minimum_mix_size: u32 = 10, // For coin mixing
    
    pub const TransactionPrivacy = enum {
        public,         // Fully transparent
        pseudonymous,   // Address obfuscation
        confidential,   // Amount hiding
        anonymous,      // Full privacy with ZK proofs
    };
};

/// Activity and analytics settings
pub const ActivitySettings = struct {
    show_online_status: VisibilityLevel = .contacts,
    show_last_seen: VisibilityLevel = .contacts,
    show_activity_status: bool = true,
    track_read_receipts: bool = true,
    
    /// Analytics and improvement
    contribute_to_analytics: bool = true,
    allow_performance_tracking: bool = true,
    share_usage_patterns: bool = false,
    participate_in_research: bool = false,
};

/// Complete privacy settings for an identity
pub const PrivacySettings = struct {
    gid: GID,
    
    /// Core privacy controls
    public_profile: bool = false,
    discoverable_by_username: bool = true,
    discoverable_by_gid: bool = false,
    searchable_in_directory: bool = false,
    
    /// Data sharing preferences
    data_sharing_consent: DataSharingLevel = .functional,
    third_party_data_sharing: bool = false,
    cross_chain_data_sharing: bool = true,
    
    /// Visibility settings for profile elements
    profile_picture_visibility: VisibilityLevel = .public,
    display_name_visibility: VisibilityLevel = .public,
    bio_visibility: VisibilityLevel = .contacts,
    location_visibility: VisibilityLevel = .private,
    social_links_visibility: VisibilityLevel = .contacts,
    verification_badges_visibility: VisibilityLevel = .public,
    
    /// Detailed settings
    communication: CommunicationSettings = .{},
    location: LocationSettings,
    financial: FinancialSettings = .{},
    activity: ActivitySettings = .{},
    
    /// Advanced privacy
    use_tor_by_default: bool = false,
    rotate_addresses_regularly: bool = true,
    minimize_metadata_leakage: bool = true,
    
    /// Compliance and legal
    gdpr_compliance_mode: bool = false,
    data_retention_period_days: ?u32 = null, // null = indefinite
    
    last_updated: u64,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, gid: GID) PrivacySettings {
        return PrivacySettings{
            .gid = gid,
            .location = LocationSettings.init(allocator),
            .last_updated = @intCast(std.time.timestamp()),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *PrivacySettings) void {
        self.location.deinit();
    }
    
    /// Check if data type can be shared based on current settings
    pub fn canShareData(self: *PrivacySettings, data_type: DataType, requester_relationship: RelationshipType) bool {
        // Check overall data sharing consent
        if (!self.data_sharing_consent.allowsDataType(data_type)) {
            return false;
        }
        
        // Check specific permissions based on relationship
        return switch (data_type) {
            .essential => true, // Always allowed for functionality
            .functional => requester_relationship != .stranger,
            .analytics => self.activity.contribute_to_analytics,
            .marketing => false, // Never share marketing data with third parties
            .experimental => requester_relationship == .self,
        };
    }
    
    /// Check if profile element is visible to requester
    pub fn isVisible(self: *PrivacySettings, element: ProfileElement, requester_relationship: RelationshipType) bool {
        const visibility_level = switch (element) {
            .profile_picture => self.profile_picture_visibility,
            .display_name => self.display_name_visibility,
            .bio => self.bio_visibility,
            .location => self.location_visibility,
            .social_links => self.social_links_visibility,
            .verification_badges => self.verification_badges_visibility,
        };
        
        return visibility_level.canAccess(requester_relationship);
    }
    
    pub const ProfileElement = enum {
        profile_picture,
        display_name,
        bio,
        location,
        social_links,
        verification_badges,
    };
    
    /// Apply privacy preset for quick configuration
    pub fn applyPreset(self: *PrivacySettings, preset: PrivacyPreset) void {
        switch (preset) {
            .maximum_privacy => self.applyMaximumPrivacy(),
            .balanced => self.applyBalancedPrivacy(),
            .social => self.applySocialPrivacy(),
            .public_figure => self.applyPublicFigurePrivacy(),
            .business => self.applyBusinessPrivacy(),
        }
        
        self.last_updated = @intCast(std.time.timestamp());
    }
    
    pub const PrivacyPreset = enum {
        maximum_privacy,
        balanced,
        social,
        public_figure,
        business,
    };
    
    fn applyMaximumPrivacy(self: *PrivacySettings) void {
        self.public_profile = false;
        self.discoverable_by_username = false;
        self.discoverable_by_gid = false;
        self.data_sharing_consent = .minimal;
        self.profile_picture_visibility = .private;
        self.display_name_visibility = .contacts;
        self.bio_visibility = .private;
        self.communication.allow_direct_messages = false;
        self.communication.require_verification_for_contact = true;
        self.financial.show_wallet_balance = .private;
        self.activity.show_online_status = .private;
        self.use_tor_by_default = true;
    }
    
    fn applyBalancedPrivacy(self: *PrivacySettings) void {
        self.public_profile = false;
        self.discoverable_by_username = true;
        self.data_sharing_consent = .functional;
        self.profile_picture_visibility = .contacts;
        self.display_name_visibility = .public;
        self.bio_visibility = .contacts;
        self.communication.allow_direct_messages = true;
        self.activity.show_online_status = .contacts;
    }
    
    fn applySocialPrivacy(self: *PrivacySettings) void {
        self.public_profile = true;
        self.discoverable_by_username = true;
        self.data_sharing_consent = .analytics;
        self.profile_picture_visibility = .public;
        self.display_name_visibility = .public;
        self.bio_visibility = .public;
        self.communication.allow_direct_messages = true;
        self.activity.show_online_status = .network;
    }
    
    fn applyPublicFigurePrivacy(self: *PrivacySettings) void {
        self.public_profile = true;
        self.discoverable_by_username = true;
        self.searchable_in_directory = true;
        self.profile_picture_visibility = .public;
        self.display_name_visibility = .public;
        self.bio_visibility = .public;
        self.verification_badges_visibility = .public;
        self.financial.show_wallet_balance = .private; // Keep finances private
    }
    
    fn applyBusinessPrivacy(self: *PrivacySettings) void {
        self.public_profile = true;
        self.discoverable_by_username = true;
        self.searchable_in_directory = true;
        self.data_sharing_consent = .functional;
        self.profile_picture_visibility = .public;
        self.display_name_visibility = .public;
        self.bio_visibility = .public;
        self.communication.allow_direct_messages = true;
        self.financial.show_transaction_history = .verified; // Business transparency
    }
    
    /// Get privacy score (0-100, higher = more private)
    pub fn getPrivacyScore(self: *PrivacySettings) u8 {
        var score: u32 = 0;
        
        // Profile visibility penalties
        if (self.public_profile) score -= 10;
        if (self.discoverable_by_username) score -= 5;
        if (self.searchable_in_directory) score -= 10;
        
        // Data sharing penalties
        score -= @as(u32, @intFromEnum(self.data_sharing_consent)) * 5;
        if (self.third_party_data_sharing) score -= 15;
        
        // Financial privacy bonuses
        if (self.financial.show_wallet_balance == .private) score += 10;
        if (self.financial.default_transaction_privacy == .anonymous) score += 15;
        
        // Communication privacy bonuses
        if (!self.communication.allow_direct_messages) score += 5;
        if (self.communication.require_verification_for_contact) score += 10;
        
        // Advanced privacy bonuses
        if (self.use_tor_by_default) score += 20;
        if (self.rotate_addresses_regularly) score += 10;
        if (self.minimize_metadata_leakage) score += 10;
        
        // Start with base score and adjust
        const base_score: u32 = 50;
        const final_score = @min(100, @max(0, base_score + score));
        
        return @intCast(final_score);
    }
    
    /// Validate settings for consistency
    pub fn validate(self: *PrivacySettings) []const PrivacyWarning {
        var warnings = std.ArrayList(PrivacyWarning).init(self.allocator);
        
        // Check for conflicting settings
        if (self.public_profile and self.data_sharing_consent == .none) {
            warnings.append(.public_profile_no_data_sharing) catch {};
        }
        
        if (self.financial.show_wallet_balance == .public and self.financial.default_transaction_privacy == .anonymous) {
            warnings.append(.public_balance_private_transactions) catch {};
        }
        
        if (self.use_tor_by_default and self.location.share_precise_location) {
            warnings.append(.tor_with_location_sharing) catch {};
        }
        
        return warnings.toOwnedSlice() catch &[_]PrivacyWarning{};
    }
    
    pub const PrivacyWarning = enum {
        public_profile_no_data_sharing,
        public_balance_private_transactions,
        tor_with_location_sharing,
        high_visibility_with_privacy_tools,
        inconsistent_communication_settings,
    };
};

/// Privacy manager for handling multiple identities
pub const PrivacyManager = struct {
    settings: std.HashMap(GID, PrivacySettings, GIDContext, std.hash_map.default_max_load_percentage),
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
    
    pub fn init(allocator: std.mem.Allocator) PrivacyManager {
        return PrivacyManager{
            .settings = std.HashMap(GID, PrivacySettings, GIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *PrivacyManager) void {
        var iter = self.settings.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.settings.deinit();
    }
    
    /// Get privacy settings for identity
    pub fn getSettings(self: *PrivacyManager, gid: GID) !*PrivacySettings {
        if (self.settings.getPtr(gid)) |settings| {
            return settings;
        }
        
        // Create default settings
        const new_settings = PrivacySettings.init(self.allocator, gid);
        try self.settings.put(gid, new_settings);
        return self.settings.getPtr(gid).?;
    }
    
    /// Update privacy settings
    pub fn updateSettings(self: *PrivacyManager, gid: GID, new_settings: PrivacySettings) !void {
        if (self.settings.getPtr(gid)) |settings| {
            settings.deinit();
        }
        try self.settings.put(gid, new_settings);
    }
    
    /// Check data access permissions
    pub fn checkDataAccess(self: *PrivacyManager, owner_gid: GID, requester_gid: GID, data_type: DataType) !bool {
        const settings = try self.getSettings(owner_gid);
        
        // Determine relationship (simplified)
        const relationship: RelationshipType = if (std.mem.eql(u8, &owner_gid.public_key, &requester_gid.public_key))
            .self
        else
            .stranger; // In real implementation, would check contacts/verification
        
        return settings.canShareData(data_type, relationship);
    }
    
    /// Get aggregated privacy statistics
    pub fn getPrivacyStats(self: *PrivacyManager) PrivacyStats {
        var stats = PrivacyStats{};
        var iter = self.settings.iterator();
        
        while (iter.next()) |entry| {
            const settings = entry.value_ptr;
            const score = settings.getPrivacyScore();
            
            stats.total_identities += 1;
            stats.average_privacy_score = ((stats.average_privacy_score * (stats.total_identities - 1)) + score) / stats.total_identities;
            
            if (settings.public_profile) stats.public_profiles += 1;
            if (settings.use_tor_by_default) stats.tor_users += 1;
            if (settings.financial.default_transaction_privacy == .anonymous) stats.anonymous_transactions += 1;
        }
        
        return stats;
    }
    
    pub const PrivacyStats = struct {
        total_identities: u32 = 0,
        average_privacy_score: u8 = 0,
        public_profiles: u32 = 0,
        tor_users: u32 = 0,
        anonymous_transactions: u32 = 0,
    };
};

test "privacy settings" {
    const allocator = std.testing.allocator;
    
    const gid = GID{
        .public_key = [_]u8{1} ** 32,
        .chain_id = 1,
        .entity_type = .wallet,
        .version = 1,
    };
    
    var settings = PrivacySettings.init(allocator, gid);
    defer settings.deinit();
    
    // Test preset application
    settings.applyPreset(.maximum_privacy);
    std.testing.expect(!settings.public_profile) catch unreachable;
    std.testing.expect(settings.data_sharing_consent == .minimal) catch unreachable;
    
    // Test privacy score
    const privacy_score = settings.getPrivacyScore();
    std.testing.expect(privacy_score > 70) catch unreachable; // High privacy
    
    // Test data sharing permissions
    std.testing.expect(settings.canShareData(.essential, .self)) catch unreachable;
    std.testing.expect(!settings.canShareData(.marketing, .stranger)) catch unreachable;
    
    // Test privacy manager
    var manager = PrivacyManager.init(allocator);
    defer manager.deinit();
    
    const retrieved_settings = try manager.getSettings(gid);
    std.testing.expect(retrieved_settings.gid.chain_id == 1) catch unreachable;
}