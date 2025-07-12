//! Identity Metadata & Profiles System
//! Rich profile information and metadata for Ghost Chain identities

const std = @import("std");
const qid = @import("qid.zig");
const privacy = @import("privacy.zig");

const GID = qid.GID;
const PrivacySettings = privacy.PrivacySettings;
const VisibilityLevel = privacy.VisibilityLevel;

/// Content addressing for decentralized storage
pub const ContentHash = struct {
    hash_type: HashType,
    hash: [32]u8,
    
    pub const HashType = enum(u8) {
        sha256 = 0,
        blake3 = 1,
        ipfs_cid = 2,
        arweave = 3,
    };
    
    /// Create content hash from data
    pub fn fromData(data: []const u8, hash_type: HashType) ContentHash {
        var hash: [32]u8 = undefined;
        
        switch (hash_type) {
            .sha256 => std.crypto.hash.sha2.Sha256.hash(data, &hash, .{}),
            .blake3 => std.crypto.hash.Blake3.hash(data, &hash, .{}),
            .ipfs_cid => {
                // Simplified IPFS CID - in production would use proper CID encoding
                std.crypto.hash.Blake3.hash(data, &hash, .{});
            },
            .arweave => {
                // Simplified Arweave hash
                std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
            },
        }
        
        return ContentHash{
            .hash_type = hash_type,
            .hash = hash,
        };
    }
    
    /// Convert to string representation
    pub fn toString(self: ContentHash, allocator: std.mem.Allocator) ![]u8 {
        const prefix = switch (self.hash_type) {
            .sha256 => "sha256:",
            .blake3 => "blake3:",
            .ipfs_cid => "ipfs:",
            .arweave => "ar:",
        };
        
        var result = try allocator.alloc(u8, prefix.len + 64);
        @memcpy(result[0..prefix.len], prefix);
        _ = std.fmt.bufPrint(result[prefix.len..], "{}", .{std.fmt.fmtSliceHexLower(&self.hash)}) catch unreachable;
        
        return result;
    }
};

/// Social media and external links
pub const SocialLinks = struct {
    twitter: ?[]const u8 = null,
    github: ?[]const u8 = null,
    discord: ?[]const u8 = null,
    telegram: ?[]const u8 = null,
    linkedin: ?[]const u8 = null,
    website: ?[]const u8 = null,
    blog: ?[]const u8 = null,
    youtube: ?[]const u8 = null,
    instagram: ?[]const u8 = null,
    custom_links: std.ArrayList(CustomLink),
    
    pub const CustomLink = struct {
        name: []const u8,
        url: []const u8,
        verified: bool = false,
        icon_hash: ?ContentHash = null,
    };
    
    pub fn init(allocator: std.mem.Allocator) SocialLinks {
        return SocialLinks{
            .custom_links = std.ArrayList(CustomLink).init(allocator),
        };
    }
    
    pub fn deinit(self: *SocialLinks, allocator: std.mem.Allocator) void {
        // Free all allocated strings
        if (self.twitter) |s| allocator.free(s);
        if (self.github) |s| allocator.free(s);
        if (self.discord) |s| allocator.free(s);
        if (self.telegram) |s| allocator.free(s);
        if (self.linkedin) |s| allocator.free(s);
        if (self.website) |s| allocator.free(s);
        if (self.blog) |s| allocator.free(s);
        if (self.youtube) |s| allocator.free(s);
        if (self.instagram) |s| allocator.free(s);
        
        for (self.custom_links.items) |link| {
            allocator.free(link.name);
            allocator.free(link.url);
        }
        self.custom_links.deinit();
    }
    
    pub fn addCustomLink(self: *SocialLinks, name: []const u8, url: []const u8) !void {
        try self.custom_links.append(CustomLink{
            .name = name,
            .url = url,
        });
    }
    
    pub fn getTotalLinks(self: SocialLinks) u32 {
        var count: u32 = 0;
        if (self.twitter != null) count += 1;
        if (self.github != null) count += 1;
        if (self.discord != null) count += 1;
        if (self.telegram != null) count += 1;
        if (self.linkedin != null) count += 1;
        if (self.website != null) count += 1;
        if (self.blog != null) count += 1;
        if (self.youtube != null) count += 1;
        if (self.instagram != null) count += 1;
        return count + @as(u32, @intCast(self.custom_links.items.len));
    }
};

/// Professional information
pub const ProfessionalInfo = struct {
    title: ?[]const u8 = null,
    company: ?[]const u8 = null,
    industry: ?[]const u8 = null,
    skills: std.ArrayList([]const u8),
    experience_years: ?u8 = null,
    education: std.ArrayList(Education),
    certifications: std.ArrayList(Certification),
    
    pub const Education = struct {
        institution: []const u8,
        degree: []const u8,
        field_of_study: ?[]const u8 = null,
        graduation_year: ?u16 = null,
        verified: bool = false,
    };
    
    pub const Certification = struct {
        name: []const u8,
        issuer: []const u8,
        issue_date: ?u64 = null,
        expiry_date: ?u64 = null,
        credential_id: ?[]const u8 = null,
        verification_url: ?[]const u8 = null,
        verified: bool = false,
    };
    
    pub fn init(allocator: std.mem.Allocator) ProfessionalInfo {
        return ProfessionalInfo{
            .skills = std.ArrayList([]const u8).init(allocator),
            .education = std.ArrayList(Education).init(allocator),
            .certifications = std.ArrayList(Certification).init(allocator),
        };
    }
    
    pub fn deinit(self: *ProfessionalInfo, allocator: std.mem.Allocator) void {
        if (self.title) |s| allocator.free(s);
        if (self.company) |s| allocator.free(s);
        if (self.industry) |s| allocator.free(s);
        
        for (self.skills.items) |skill| {
            allocator.free(skill);
        }
        self.skills.deinit();
        
        for (self.education.items) |edu| {
            allocator.free(edu.institution);
            allocator.free(edu.degree);
            if (edu.field_of_study) |s| allocator.free(s);
        }
        self.education.deinit();
        
        for (self.certifications.items) |cert| {
            allocator.free(cert.name);
            allocator.free(cert.issuer);
            if (cert.credential_id) |s| allocator.free(s);
            if (cert.verification_url) |s| allocator.free(s);
        }
        self.certifications.deinit();
    }
    
    pub fn addSkill(self: *ProfessionalInfo, skill: []const u8) !void {
        try self.skills.append(skill);
    }
    
    pub fn hasSkill(self: ProfessionalInfo, skill: []const u8) bool {
        for (self.skills.items) |s| {
            if (std.mem.eql(u8, s, skill)) return true;
        }
        return false;
    }
};

/// Location information with privacy controls
pub const LocationInfo = struct {
    country: ?[]const u8 = null,
    country_code: ?[]const u8 = null, // ISO 3166-1 alpha-2
    state_province: ?[]const u8 = null,
    city: ?[]const u8 = null,
    timezone: ?[]const u8 = null,
    
    /// Precise coordinates (only if privacy allows)
    latitude: ?f64 = null,
    longitude: ?f64 = null,
    
    /// Location verification
    verified_by_ip: bool = false,
    verified_by_document: bool = false,
    last_updated: u64,
    
    pub fn init() LocationInfo {
        return LocationInfo{
            .last_updated = @intCast(std.time.timestamp()),
        };
    }
    
    pub fn deinit(self: *LocationInfo, allocator: std.mem.Allocator) void {
        if (self.country) |s| allocator.free(s);
        if (self.country_code) |s| allocator.free(s);
        if (self.state_province) |s| allocator.free(s);
        if (self.city) |s| allocator.free(s);
        if (self.timezone) |s| allocator.free(s);
    }
    
    /// Get location string based on privacy settings
    pub fn getLocationString(self: LocationInfo, privacy_level: VisibilityLevel, allocator: std.mem.Allocator) !?[]u8 {
        return switch (privacy_level) {
            .private => null,
            .contacts, .verified => if (self.city != null and self.country != null) 
                try std.fmt.allocPrint(allocator, "{s}, {s}", .{ self.city.?, self.country.? })
            else if (self.country != null)
                try allocator.dupe(u8, self.country.?)
            else null,
            .network => if (self.state_province != null and self.country != null)
                try std.fmt.allocPrint(allocator, "{s}, {s}", .{ self.state_province.?, self.country.? })
            else if (self.country != null)
                try allocator.dupe(u8, self.country.?)
            else null,
            .public => if (self.country != null)
                try allocator.dupe(u8, self.country.?)
            else null,
        };
    }
};

/// Complete identity profile
pub const IdentityProfile = struct {
    gid: GID,
    
    /// Basic information
    display_name: ?[]const u8 = null,
    username: ?[]const u8 = null, // Unique username for discovery
    bio: ?[]const u8 = null,
    tagline: ?[]const u8 = null, // Short description
    
    /// Visual identity
    avatar_hash: ?ContentHash = null,
    banner_hash: ?ContentHash = null,
    theme_colors: ?ThemeColors = null,
    
    /// Contact information
    email: ?[]const u8 = null,
    phone: ?[]const u8 = null,
    preferred_contact_method: ContactMethod = .ghost_message,
    
    /// Rich profile data
    social_links: SocialLinks,
    professional: ProfessionalInfo,
    location: LocationInfo,
    
    /// Identity metadata
    preferred_pronouns: ?[]const u8 = null,
    birth_year: ?u16 = null, // Year only for privacy
    languages: std.ArrayList([]const u8),
    interests: std.ArrayList([]const u8),
    
    /// Crypto-specific
    public_key_sharing: bool = true, // Allow others to encrypt to you
    preferred_networks: std.ArrayList(u32), // Chain IDs
    ens_names: std.ArrayList([]const u8), // Associated ENS names
    
    /// Profile metadata
    created_at: u64,
    last_updated: u64,
    profile_version: u32 = 1,
    
    /// Stats and engagement
    profile_views: u64 = 0,
    last_active: u64,
    
    allocator: std.mem.Allocator,
    
    pub const ThemeColors = struct {
        primary: [3]u8,   // RGB
        secondary: [3]u8,
        accent: [3]u8,
    };
    
    pub const ContactMethod = enum {
        ghost_message,
        email,
        social_media,
        phone,
        any,
    };
    
    pub fn init(allocator: std.mem.Allocator, gid: GID) IdentityProfile {
        const now = @as(u64, @intCast(std.time.timestamp()));
        
        return IdentityProfile{
            .gid = gid,
            .social_links = SocialLinks.init(allocator),
            .professional = ProfessionalInfo.init(allocator),
            .location = LocationInfo.init(),
            .languages = std.ArrayList([]const u8).init(allocator),
            .interests = std.ArrayList([]const u8).init(allocator),
            .preferred_networks = std.ArrayList(u32).init(allocator),
            .ens_names = std.ArrayList([]const u8).init(allocator),
            .created_at = now,
            .last_updated = now,
            .last_active = now,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *IdentityProfile) void {
        if (self.display_name) |s| self.allocator.free(s);
        if (self.username) |s| self.allocator.free(s);
        if (self.bio) |s| self.allocator.free(s);
        if (self.tagline) |s| self.allocator.free(s);
        if (self.email) |s| self.allocator.free(s);
        if (self.phone) |s| self.allocator.free(s);
        if (self.preferred_pronouns) |s| self.allocator.free(s);
        
        self.social_links.deinit(self.allocator);
        self.professional.deinit(self.allocator);
        self.location.deinit(self.allocator);
        
        for (self.languages.items) |lang| {
            self.allocator.free(lang);
        }
        self.languages.deinit();
        
        for (self.interests.items) |interest| {
            self.allocator.free(interest);
        }
        self.interests.deinit();
        
        for (self.ens_names.items) |name| {
            self.allocator.free(name);
        }
        self.ens_names.deinit();
        
        self.preferred_networks.deinit();
    }
    
    /// Update display name with validation
    pub fn setDisplayName(self: *IdentityProfile, name: []const u8) !void {
        if (name.len == 0 or name.len > 64) {
            return error.InvalidDisplayName;
        }
        
        if (self.display_name) |old_name| {
            self.allocator.free(old_name);
        }
        
        self.display_name = try self.allocator.dupe(u8, name);
        self.updateTimestamp();
    }
    
    /// Update username with validation
    pub fn setUsername(self: *IdentityProfile, username: []const u8) !void {
        if (username.len < 3 or username.len > 32) {
            return error.InvalidUsername;
        }
        
        // Validate username format (alphanumeric + underscore/dash)
        for (username) |char| {
            if (!std.ascii.isAlphanumeric(char) and char != '_' and char != '-') {
                return error.InvalidUsername;
            }
        }
        
        if (self.username) |old_username| {
            self.allocator.free(old_username);
        }
        
        self.username = try self.allocator.dupe(u8, username);
        self.updateTimestamp();
    }
    
    /// Update bio with length validation
    pub fn setBio(self: *IdentityProfile, bio: []const u8) !void {
        if (bio.len > 500) {
            return error.BioTooLong;
        }
        
        if (self.bio) |old_bio| {
            self.allocator.free(old_bio);
        }
        
        self.bio = try self.allocator.dupe(u8, bio);
        self.updateTimestamp();
    }
    
    /// Add language with duplicate checking
    pub fn addLanguage(self: *IdentityProfile, language: []const u8) !void {
        // Check for duplicates
        for (self.languages.items) |lang| {
            if (std.mem.eql(u8, lang, language)) {
                return; // Already exists
            }
        }
        
        const lang_copy = try self.allocator.dupe(u8, language);
        try self.languages.append(lang_copy);
        self.updateTimestamp();
    }
    
    /// Add interest with duplicate checking
    pub fn addInterest(self: *IdentityProfile, interest: []const u8) !void {
        // Check for duplicates
        for (self.interests.items) |existing| {
            if (std.mem.eql(u8, existing, interest)) {
                return; // Already exists
            }
        }
        
        const interest_copy = try self.allocator.dupe(u8, interest);
        try self.interests.append(interest_copy);
        self.updateTimestamp();
    }
    
    /// Set avatar from image data
    pub fn setAvatar(self: *IdentityProfile, image_data: []const u8, hash_type: ContentHash.HashType) void {
        self.avatar_hash = ContentHash.fromData(image_data, hash_type);
        self.updateTimestamp();
    }
    
    /// Get profile completeness percentage
    pub fn getCompletenessScore(self: IdentityProfile) u8 {
        var score: u8 = 0;
        
        // Basic info (30 points)
        if (self.display_name != null) score += 10;
        if (self.username != null) score += 10;
        if (self.bio != null) score += 10;
        
        // Visual identity (20 points)
        if (self.avatar_hash != null) score += 15;
        if (self.theme_colors != null) score += 5;
        
        // Contact info (15 points)
        if (self.email != null) score += 10;
        if (self.location.country != null) score += 5;
        
        // Rich profile data (35 points)
        if (self.social_links.getTotalLinks() > 0) score += 10;
        if (self.professional.skills.items.len > 0) score += 10;
        if (self.languages.items.len > 0) score += 5;
        if (self.interests.items.len > 0) score += 5;
        if (self.preferred_pronouns != null) score += 5;
        
        return @min(100, score);
    }
    
    /// Get profile as filtered view based on privacy settings
    pub fn getFilteredView(self: *IdentityProfile, privacy_settings: *PrivacySettings, viewer_relationship: privacy.RelationshipType, allocator: std.mem.Allocator) !ProfileView {
        var view = ProfileView{
            .gid = self.gid,
            .profile_views = self.profile_views,
            .last_active = self.last_active,
        };
        
        // Apply privacy filters
        if (privacy_settings.isVisible(.display_name, viewer_relationship)) {
            view.display_name = if (self.display_name) |name| try allocator.dupe(u8, name) else null;
        }
        
        if (privacy_settings.isVisible(.bio, viewer_relationship)) {
            view.bio = if (self.bio) |bio| try allocator.dupe(u8, bio) else null;
        }
        
        if (privacy_settings.isVisible(.profile_picture, viewer_relationship)) {
            view.avatar_hash = self.avatar_hash;
        }
        
        if (privacy_settings.isVisible(.social_links, viewer_relationship)) {
            view.social_link_count = self.social_links.getTotalLinks();
        }
        
        if (privacy_settings.isVisible(.location, viewer_relationship)) {
            view.location = try self.location.getLocationString(privacy_settings.location_visibility, allocator);
        }
        
        view.completeness_score = self.getCompletenessScore();
        
        return view;
    }
    
    /// Record profile view for analytics
    pub fn recordView(self: *IdentityProfile) void {
        self.profile_views += 1;
        // In production, might also record viewer details if privacy allows
    }
    
    /// Update activity timestamp
    pub fn markActive(self: *IdentityProfile) void {
        self.last_active = @intCast(std.time.timestamp());
    }
    
    fn updateTimestamp(self: *IdentityProfile) void {
        self.last_updated = @intCast(std.time.timestamp());
        self.profile_version += 1;
    }
};

/// Filtered profile view for privacy protection
pub const ProfileView = struct {
    gid: GID,
    display_name: ?[]const u8 = null,
    username: ?[]const u8 = null,
    bio: ?[]const u8 = null,
    avatar_hash: ?ContentHash = null,
    location: ?[]const u8 = null,
    social_link_count: u32 = 0,
    completeness_score: u8 = 0,
    profile_views: u64 = 0,
    last_active: u64,
    
    pub fn deinit(self: *ProfileView, allocator: std.mem.Allocator) void {
        if (self.display_name) |s| allocator.free(s);
        if (self.username) |s| allocator.free(s);
        if (self.bio) |s| allocator.free(s);
        if (self.location) |s| allocator.free(s);
    }
};

/// Profile manager for handling multiple identity profiles
pub const ProfileManager = struct {
    profiles: std.HashMap(GID, IdentityProfile, GIDContext, std.hash_map.default_max_load_percentage),
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
    
    pub fn init(allocator: std.mem.Allocator) ProfileManager {
        return ProfileManager{
            .profiles = std.HashMap(GID, IdentityProfile, GIDContext, std.hash_map.default_max_load_percentage).init(allocator),
            .username_index = std.HashMap([]const u8, GID, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ProfileManager) void {
        var profile_iter = self.profiles.iterator();
        while (profile_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.profiles.deinit();
        
        var username_iter = self.username_index.iterator();
        while (username_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.username_index.deinit();
    }
    
    /// Get or create profile for identity
    pub fn getProfile(self: *ProfileManager, gid: GID) !*IdentityProfile {
        if (self.profiles.getPtr(gid)) |profile| {
            return profile;
        }
        
        const new_profile = IdentityProfile.init(self.allocator, gid);
        try self.profiles.put(gid, new_profile);
        return self.profiles.getPtr(gid).?;
    }
    
    /// Reserve username for identity
    pub fn setUsername(self: *ProfileManager, gid: GID, username: []const u8) !void {
        // Check if username is already taken
        if (self.username_index.contains(username)) {
            return error.UsernameTaken;
        }
        
        const profile = try self.getProfile(gid);
        
        // Remove old username from index if it exists
        if (profile.username) |old_username| {
            _ = self.username_index.remove(old_username);
            self.allocator.free(old_username);
        }
        
        // Set new username
        try profile.setUsername(username);
        
        // Add to index
        const username_copy = try self.allocator.dupe(u8, username);
        try self.username_index.put(username_copy, gid);
    }
    
    /// Find profile by username
    pub fn getProfileByUsername(self: *ProfileManager, username: []const u8) ?*IdentityProfile {
        if (self.username_index.get(username)) |gid| {
            return self.profiles.getPtr(gid);
        }
        return null;
    }
    
    /// Search profiles by display name or bio
    pub fn searchProfiles(self: *ProfileManager, query: []const u8, allocator: std.mem.Allocator) ![]GID {
        var results = std.ArrayList(GID).init(allocator);
        
        var iter = self.profiles.iterator();
        while (iter.next()) |entry| {
            const profile = entry.value_ptr;
            var matches = false;
            
            // Search in display name
            if (profile.display_name) |name| {
                if (std.ascii.indexOfIgnoreCase(name, query) != null) {
                    matches = true;
                }
            }
            
            // Search in bio
            if (!matches and profile.bio) |bio| {
                if (std.ascii.indexOfIgnoreCase(bio, query) != null) {
                    matches = true;
                }
            }
            
            // Search in interests
            if (!matches) {
                for (profile.interests.items) |interest| {
                    if (std.ascii.indexOfIgnoreCase(interest, query) != null) {
                        matches = true;
                        break;
                    }
                }
            }
            
            if (matches) {
                try results.append(entry.key_ptr.*);
            }
        }
        
        return results.toOwnedSlice();
    }
    
    /// Get profile statistics
    pub fn getStats(self: *ProfileManager) ProfileStats {
        var stats = ProfileStats{};
        var iter = self.profiles.iterator();
        
        while (iter.next()) |entry| {
            const profile = entry.value_ptr;
            
            stats.total_profiles += 1;
            
            if (profile.display_name != null) stats.profiles_with_names += 1;
            if (profile.avatar_hash != null) stats.profiles_with_avatars += 1;
            if (profile.bio != null) stats.profiles_with_bios += 1;
            if (profile.social_links.getTotalLinks() > 0) stats.profiles_with_social += 1;
            
            const completeness = profile.getCompletenessScore();
            stats.average_completeness = ((stats.average_completeness * (stats.total_profiles - 1)) + completeness) / stats.total_profiles;
        }
        
        return stats;
    }
    
    pub const ProfileStats = struct {
        total_profiles: u32 = 0,
        profiles_with_names: u32 = 0,
        profiles_with_avatars: u32 = 0,
        profiles_with_bios: u32 = 0,
        profiles_with_social: u32 = 0,
        average_completeness: u8 = 0,
    };
};

test "profile creation and management" {
    const allocator = std.testing.allocator;
    
    const gid = GID{
        .public_key = [_]u8{1} ** 32,
        .chain_id = 1,
        .entity_type = .wallet,
        .version = 1,
    };
    
    // Test profile creation
    var profile = IdentityProfile.init(allocator, gid);
    defer profile.deinit();
    
    // Test basic setters
    try profile.setDisplayName("Alice Ghost");
    try profile.setBio("Blockchain enthusiast and developer");
    try profile.addLanguage("English");
    try profile.addInterest("DeFi");
    
    // Test completeness score
    const score = profile.getCompletenessScore();
    std.testing.expect(score > 0) catch unreachable;
    
    // Test profile manager
    var manager = ProfileManager.init(allocator);
    defer manager.deinit();
    
    const managed_profile = try manager.getProfile(gid);
    try manager.setUsername(gid, "alice_ghost");
    
    const found_profile = manager.getProfileByUsername("alice_ghost");
    std.testing.expect(found_profile != null) catch unreachable;
    std.testing.expect(std.mem.eql(u8, &found_profile.?.gid.public_key, &gid.public_key)) catch unreachable;
}