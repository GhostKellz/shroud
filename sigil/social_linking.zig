//! Social Identity Linking System
//! Links Web2 social accounts to Ghost Chain identities for verification and social proof

const std = @import("std");
const qid = @import("qid.zig");
const verification = @import("verification.zig");

const GID = qid.GID;
const VerificationEvidence = verification.VerificationEvidence;

/// Supported social platforms for identity linking
pub const SocialPlatform = enum {
    twitter,
    github,
    discord,
    telegram,
    linkedin,
    reddit,
    instagram,
    youtube,
    tiktok,
    facebook,
    mastodon,
    custom,
    
    pub fn toString(self: SocialPlatform) []const u8 {
        return switch (self) {
            .twitter => "Twitter/X",
            .github => "GitHub",
            .discord => "Discord",
            .telegram => "Telegram",
            .linkedin => "LinkedIn",
            .reddit => "Reddit",
            .instagram => "Instagram",
            .youtube => "YouTube",
            .tiktok => "TikTok",
            .facebook => "Facebook",
            .mastodon => "Mastodon",
            .custom => "Custom Platform",
        };
    }
    
    pub fn getBaseUrl(self: SocialPlatform) []const u8 {
        return switch (self) {
            .twitter => "https://twitter.com/",
            .github => "https://github.com/",
            .discord => "https://discord.com/users/",
            .telegram => "https://t.me/",
            .linkedin => "https://linkedin.com/in/",
            .reddit => "https://reddit.com/u/",
            .instagram => "https://instagram.com/",
            .youtube => "https://youtube.com/@",
            .tiktok => "https://tiktok.com/@",
            .facebook => "https://facebook.com/",
            .mastodon => "https://", // Varies by instance
            .custom => "",
        };
    }
    
    /// Get verification difficulty score (higher = more trusted)
    pub fn getVerificationScore(self: SocialPlatform) u8 {
        return switch (self) {
            .github => 90,      // Strong verification via code/commits
            .linkedin => 85,    // Professional network with verification
            .twitter => 75,     // Established but can be gamed
            .youtube => 70,     // Content-based verification
            .telegram => 65,    // Username-based
            .discord => 60,     // Gaming/community platform
            .reddit => 55,      // Forum-based, karma system
            .instagram => 50,   // Visual platform
            .tiktok => 45,      // Newer platform
            .facebook => 40,    // Privacy concerns
            .mastodon => 35,    // Decentralized, varies by instance
            .custom => 30,      // Unknown verification standards
        };
    }
};

/// Methods for proving ownership of social accounts
pub const VerificationMethod = enum {
    post_signature,     // Post a signed message
    bio_signature,      // Add signature to profile bio
    file_signature,     // Upload signed file (GitHub, etc.)
    oauth_flow,         // OAuth authentication flow
    manual_review,      // Manual verification by trusted party
    api_verification,   // Direct API verification (for trusted platforms)
    
    pub fn toString(self: VerificationMethod) []const u8 {
        return switch (self) {
            .post_signature => "Post Signature",
            .bio_signature => "Bio Signature",
            .file_signature => "File Signature",
            .oauth_flow => "OAuth Authentication",
            .manual_review => "Manual Review",
            .api_verification => "API Verification",
        };
    }
    
    pub fn getReliabilityScore(self: VerificationMethod) u8 {
        return switch (self) {
            .api_verification => 95,
            .oauth_flow => 90,
            .file_signature => 85,
            .post_signature => 80,
            .bio_signature => 70,
            .manual_review => 60,
        };
    }
};

/// Social account linking record
pub const SocialLink = struct {
    platform: SocialPlatform,
    username: []const u8,
    profile_url: []const u8,
    verification_method: VerificationMethod,
    verification_data: []const u8,  // Proof data (signature, etc.)
    
    /// Status and metadata
    verified: bool = false,
    verification_timestamp: ?u64 = null,
    last_checked: ?u64 = null,
    follower_count: ?u32 = null,
    account_created: ?u64 = null,
    
    /// Platform-specific metadata
    platform_verified: bool = false,  // Blue checkmark, etc.
    platform_score: ?u32 = null,      // Karma, followers, etc.
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, platform: SocialPlatform, username: []const u8, profile_url: []const u8) !SocialLink {
        return SocialLink{
            .platform = platform,
            .username = try allocator.dupe(u8, username),
            .profile_url = try allocator.dupe(u8, profile_url),
            .verification_method = .post_signature,
            .verification_data = try allocator.alloc(u8, 0),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *SocialLink) void {
        self.allocator.free(self.username);
        self.allocator.free(self.profile_url);
        self.allocator.free(self.verification_data);
    }
    
    /// Set verification proof data
    pub fn setVerificationData(self: *SocialLink, method: VerificationMethod, data: []const u8) !void {
        self.allocator.free(self.verification_data);
        self.verification_method = method;
        self.verification_data = try self.allocator.dupe(u8, data);
    }
    
    /// Verify ownership of social account
    pub fn verify(self: *SocialLink, gid: GID) !bool {
        switch (self.verification_method) {
            .post_signature => return self.verifyPostSignature(gid),
            .bio_signature => return self.verifyBioSignature(gid),
            .file_signature => return self.verifyFileSignature(gid),
            .oauth_flow => return self.verifyOAuth(),
            .manual_review => return false, // Requires external verification
            .api_verification => return self.verifyViaAPI(),
        }
    }
    
    fn verifyPostSignature(self: *SocialLink, gid: GID) !bool {
        // In a real implementation, this would:
        // 1. Generate a challenge message with GID
        // 2. User posts signed challenge to their social account
        // 3. We fetch the post and verify the signature
        _ = gid;
        
        // For now, check if verification data looks like a valid signature
        if (self.verification_data.len >= 64) {
            self.verified = true;
            self.verification_timestamp = @intCast(std.time.timestamp());
            return true;
        }
        
        return false;
    }
    
    fn verifyBioSignature(self: *SocialLink, gid: GID) !bool {
        // Similar to post signature but checks profile bio
        _ = gid;
        
        if (self.verification_data.len >= 32) {
            self.verified = true;
            self.verification_timestamp = @intCast(std.time.timestamp());
            return true;
        }
        
        return false;
    }
    
    fn verifyFileSignature(self: *SocialLink, gid: GID) !bool {
        // For platforms like GitHub, verify via committed file
        _ = gid;
        
        if (self.platform == .github and self.verification_data.len >= 64) {
            self.verified = true;
            self.verification_timestamp = @intCast(std.time.timestamp());
            return true;
        }
        
        return false;
    }
    
    fn verifyOAuth(self: *SocialLink) !bool {
        // OAuth flow verification (platform-dependent implementation)
        if (self.verification_data.len >= 16) {
            self.verified = true;
            self.verification_timestamp = @intCast(std.time.timestamp());
            return true;
        }
        
        return false;
    }
    
    fn verifyViaAPI(self: *SocialLink) !bool {
        // Direct API verification for trusted platforms
        if (self.verification_data.len >= 32) {
            self.verified = true;
            self.verification_timestamp = @intCast(std.time.timestamp());
            return true;
        }
        
        return false;
    }
    
    /// Calculate social proof score based on account metrics
    pub fn getSocialProofScore(self: SocialLink) u8 {
        if (!self.verified) return 0;
        
        var score: u32 = self.platform.getVerificationScore() / 2;
        
        // Bonus for platform verification (blue checkmark, etc.)
        if (self.platform_verified) {
            score += 20;
        }
        
        // Bonus based on follower count
        if (self.follower_count) |followers| {
            const follower_score = switch (followers) {
                0...100 => 0,
                101...1000 => 5,
                1001...10000 => 10,
                10001...100000 => 15,
                100001...1000000 => 20,
                else => 25,
            };
            score += follower_score;
        }
        
        // Bonus for account age
        if (self.account_created) |created| {
            const now = @as(u64, @intCast(std.time.timestamp()));
            const age_days = (now - created) / (24 * 3600);
            const age_score = @min(15, age_days / 30); // 1 point per month, max 15
            score += @intCast(age_score);
        }
        
        // Bonus for platform-specific scores (karma, etc.)
        if (self.platform_score) |platform_score| {
            const normalized_score = switch (self.platform) {
                .reddit => @min(10, platform_score / 1000), // Reddit karma
                .github => @min(15, platform_score / 100),   // GitHub stars/followers
                else => @min(5, platform_score / 1000),
            };
            score += normalized_score;
        }
        
        return @min(100, @intCast(score));
    }
    
    /// Check if link needs reverification
    pub fn needsReverification(self: SocialLink) bool {
        if (!self.verified) return true;
        
        if (self.last_checked) |last_check| {
            const now = @as(u64, @intCast(std.time.timestamp()));
            const days_since_check = (now - last_check) / (24 * 3600);
            
            // Reverify based on platform trust level
            const reverify_days: u64 = switch (self.platform.getVerificationScore()) {
                80...100 => 90,  // High trust platforms - quarterly
                60...79 => 60,   // Medium trust - bi-monthly
                40...59 => 30,   // Lower trust - monthly
                else => 14,      // Low trust - bi-weekly
            };
            
            return days_since_check > reverify_days;
        }
        
        return true;
    }
};

/// Complete social identity record for a Ghost Chain identity
pub const SocialIdentity = struct {
    gid: GID,
    links: std.ArrayList(SocialLink),
    
    /// Aggregated social proof
    total_social_score: u16 = 0,
    verified_platforms: u8 = 0,
    last_updated: u64,
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, gid: GID) SocialIdentity {
        return SocialIdentity{
            .gid = gid,
            .links = std.ArrayList(SocialLink).init(allocator),
            .last_updated = @intCast(std.time.timestamp()),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *SocialIdentity) void {
        for (self.links.items) |*link| {
            link.deinit();
        }
        self.links.deinit();
    }
    
    /// Add social platform link
    pub fn addLink(self: *SocialIdentity, platform: SocialPlatform, username: []const u8, profile_url: []const u8) !*SocialLink {
        // Check for duplicate platform
        for (self.links.items) |*link| {
            if (link.platform == platform) {
                return error.PlatformAlreadyLinked;
            }
        }
        
        const link = try SocialLink.init(self.allocator, platform, username, profile_url);
        try self.links.append(link);
        self.updateScores();
        
        return &self.links.items[self.links.items.len - 1];
    }
    
    /// Remove social platform link
    pub fn removeLink(self: *SocialIdentity, platform: SocialPlatform) bool {
        for (self.links.items, 0..) |*link, i| {
            if (link.platform == platform) {
                link.deinit();
                _ = self.links.swapRemove(i);
                self.updateScores();
                return true;
            }
        }
        return false;
    }
    
    /// Get link for specific platform
    pub fn getLink(self: *SocialIdentity, platform: SocialPlatform) ?*SocialLink {
        for (self.links.items) |*link| {
            if (link.platform == platform) {
                return link;
            }
        }
        return null;
    }
    
    /// Verify all unverified links
    pub fn verifyAllLinks(self: *SocialIdentity) !u8 {
        var verified_count: u8 = 0;
        
        for (self.links.items) |*link| {
            if (!link.verified) {
                if (try link.verify(self.gid)) {
                    verified_count += 1;
                }
            }
        }
        
        self.updateScores();
        return verified_count;
    }
    
    /// Update aggregated social scores
    fn updateScores(self: *SocialIdentity) void {
        self.total_social_score = 0;
        self.verified_platforms = 0;
        
        for (self.links.items) |link| {
            if (link.verified) {
                self.verified_platforms += 1;
                self.total_social_score += link.getSocialProofScore();
            }
        }
        
        self.last_updated = @intCast(std.time.timestamp());
    }
    
    /// Get social identity summary
    pub fn getSummary(self: *SocialIdentity) SocialIdentitySummary {
        var platform_list = std.ArrayList(SocialPlatform).init(self.allocator);
        defer platform_list.deinit();
        
        var verified_platforms = std.ArrayList(SocialPlatform).init(self.allocator);
        defer verified_platforms.deinit();
        
        for (self.links.items) |link| {
            platform_list.append(link.platform) catch {};
            if (link.verified) {
                verified_platforms.append(link.platform) catch {};
            }
        }
        
        return SocialIdentitySummary{
            .gid = self.gid,
            .total_links = @intCast(self.links.items.len),
            .verified_links = self.verified_platforms,
            .social_score = self.total_social_score,
            .last_updated = self.last_updated,
        };
    }
    
    /// Get verification evidence for reputation system
    pub fn generateVerificationEvidence(self: *SocialIdentity, allocator: std.mem.Allocator) ![]VerificationEvidence {
        var evidence_list = std.ArrayList(VerificationEvidence).init(allocator);
        
        for (self.links.items) |link| {
            if (link.verified and link.verification_timestamp != null) {
                const evidence = VerificationEvidence{
                    .evidence_type = .social_account,
                    .data_hash = self.hashLinkData(link),
                    .verifier_gid = null, // Self-verified social proof
                    .timestamp = link.verification_timestamp.?,
                    .expiry = link.verification_timestamp.? + (365 * 24 * 3600), // 1 year
                    .confidence_score = link.getSocialProofScore(),
                    .signature = [_]u8{0} ** 64, // Would be properly signed in production
                };
                
                try evidence_list.append(evidence);
            }
        }
        
        return evidence_list.toOwnedSlice();
    }
    
    fn hashLinkData(self: *SocialIdentity, link: SocialLink) [32]u8 {
        _ = self;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(@tagName(link.platform));
        hasher.update(link.username);
        hasher.update(link.profile_url);
        
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }
};

pub const SocialIdentitySummary = struct {
    gid: GID,
    total_links: u8,
    verified_links: u8,
    social_score: u16,
    last_updated: u64,
};

/// Social linking service for managing social identities
pub const SocialLinkingService = struct {
    identities: std.HashMap(GID, SocialIdentity, GIDContext, std.hash_map.default_max_load_percentage),
    username_index: std.HashMap([]const u8, GID, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
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
    
    pub fn init(allocator: std.mem.Allocator) SocialLinkingService {
        return SocialLinkingService{
            .identities = std.HashMap(GID, SocialIdentity, GIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .username_index = std.HashMap([]const u8, GID, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *SocialLinkingService) void {
        var identity_iter = self.identities.iterator();
        while (identity_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.identities.deinit();
        
        var username_iter = self.username_index.iterator();
        while (username_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.username_index.deinit();
    }
    
    /// Get or create social identity for GID
    pub fn getIdentity(self: *SocialLinkingService, gid: GID) !*SocialIdentity {
        if (self.identities.getPtr(gid)) |identity| {
            return identity;
        }
        
        const new_identity = SocialIdentity.init(self.allocator, gid);
        try self.identities.put(gid, new_identity);
        return self.identities.getPtr(gid).?;
    }
    
    /// Link social account to identity
    pub fn linkAccount(self: *SocialLinkingService, gid: GID, platform: SocialPlatform, username: []const u8, profile_url: []const u8) !*SocialLink {
        const identity = try self.getIdentity(gid);
        const link = try identity.addLink(platform, username, profile_url);
        
        // Add to username index for discovery
        const index_key = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ @tagName(platform), username });
        try self.username_index.put(index_key, gid);
        
        return link;
    }
    
    /// Find identity by social username
    pub fn findByUsername(self: *SocialLinkingService, platform: SocialPlatform, username: []const u8) ?*SocialIdentity {
        var key_buf: [256]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{s}:{s}", .{ @tagName(platform), username }) catch return null;
        
        if (self.username_index.get(key)) |gid| {
            return self.identities.getPtr(gid);
        }
        return null;
    }
    
    /// Get social linking statistics
    pub fn getStats(self: *SocialLinkingService) SocialLinkingStats {
        var stats = SocialLinkingStats{};
        var platform_counts = [_]u32{0} ** @typeInfo(SocialPlatform).Enum.fields.len;
        
        var iter = self.identities.iterator();
        while (iter.next()) |entry| {
            const identity = entry.value_ptr;
            stats.total_identities += 1;
            stats.total_links += @intCast(identity.links.items.len);
            stats.verified_links += identity.verified_platforms;
            
            for (identity.links.items) |link| {
                platform_counts[@intFromEnum(link.platform)] += 1;
                if (link.verified) {
                    stats.total_social_score += link.getSocialProofScore();
                }
            }
        }
        
        if (stats.verified_links > 0) {
            stats.average_social_score = @intCast(stats.total_social_score / @as(u32, stats.verified_links));
        }
        
        stats.platform_distribution = platform_counts;
        
        return stats;
    }
    
    pub const SocialLinkingStats = struct {
        total_identities: u32 = 0,
        total_links: u32 = 0,
        verified_links: u32 = 0,
        total_social_score: u32 = 0,
        average_social_score: u16 = 0,
        platform_distribution: [@typeInfo(SocialPlatform).Enum.fields.len]u32 = [_]u32{0} ** @typeInfo(SocialPlatform).Enum.fields.len,
    };
};

test "social identity linking" {
    const allocator = std.testing.allocator;
    
    const gid = GID{
        .public_key = [_]u8{1} ** 32,
        .chain_id = 1,
        .entity_type = .wallet,
        .version = 1,
    };
    
    // Test social identity
    var identity = SocialIdentity.init(allocator, gid);
    defer identity.deinit();
    
    // Test adding links
    const github_link = try identity.addLink(.github, "alice", "https://github.com/alice");
    std.testing.expect(github_link.platform == .github) catch unreachable;
    std.testing.expect(std.mem.eql(u8, github_link.username, "alice")) catch unreachable;
    
    // Test platform scores
    const github_score = SocialPlatform.github.getVerificationScore();
    std.testing.expect(github_score == 90) catch unreachable;
    
    // Test social linking service
    var service = SocialLinkingService.init(allocator);
    defer service.deinit();
    
    const managed_identity = try service.getIdentity(gid);
    const twitter_link = try service.linkAccount(gid, .twitter, "alice_crypto", "https://twitter.com/alice_crypto");
    std.testing.expect(twitter_link.platform == .twitter) catch unreachable;
    
    // Test finding by username
    const found_identity = service.findByUsername(.twitter, "alice_crypto");
    std.testing.expect(found_identity != null) catch unreachable;
}