const std = @import("std");
const guardian = @import("guardian.zig");
const identity = @import("identity.zig");
const access_token = @import("access_token.zig");
const zk_proof = @import("zk_proof.zig");
const cross_chain = @import("cross_chain.zig");

pub const HierarchicalTrustError = error{
    InvalidDelegationChain,
    CircularDelegation,
    DelegationDepthExceeded,
    InsufficientAuthority,
    ExpiredDelegation,
    UnauthorizedDelegator,
    InvalidTrustLevel,
    OutOfMemory,
};

pub const TrustLevel = enum(u8) {
    none = 0,
    basic = 1,
    verified = 2,
    trusted = 3,
    ultimate = 4,
    
    pub fn canDelegate(self: TrustLevel, target_level: TrustLevel) bool {
        return @intFromEnum(self) > @intFromEnum(target_level);
    }
    
    pub fn toString(self: TrustLevel) []const u8 {
        return switch (self) {
            .none => "none",
            .basic => "basic",
            .verified => "verified",
            .trusted => "trusted",
            .ultimate => "ultimate",
        };
    }
};

pub const DelegationScope = struct {
    resource_patterns: std.ArrayList([]const u8),
    permissions: std.ArrayList(guardian.Permission),
    conditions: std.ArrayList(DelegationCondition),
    max_depth: u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, max_depth: u8) DelegationScope {
        return DelegationScope{
            .resource_patterns = std.ArrayList([]const u8).init(allocator),
            .permissions = std.ArrayList(guardian.Permission).init(allocator),
            .conditions = std.ArrayList(DelegationCondition).init(allocator),
            .max_depth = max_depth,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *DelegationScope) void {
        self.resource_patterns.deinit();
        self.permissions.deinit();
        for (self.conditions.items) |*condition| {
            condition.deinit();
        }
        self.conditions.deinit();
    }
    
    pub fn addResourcePattern(self: *DelegationScope, pattern: []const u8) !void {
        try self.resource_patterns.append(pattern);
    }
    
    pub fn addPermission(self: *DelegationScope, permission: guardian.Permission) !void {
        try self.permissions.append(permission);
    }
    
    pub fn addCondition(self: *DelegationScope, condition: DelegationCondition) !void {
        try self.conditions.append(condition);
    }
    
    pub fn matchesResource(self: *const DelegationScope, resource: []const u8) bool {
        for (self.resource_patterns.items) |pattern| {
            if (matchesPattern(pattern, resource)) return true;
        }
        return false;
    }
    
    pub fn hasPermission(self: *const DelegationScope, permission: guardian.Permission) bool {
        for (self.permissions.items) |perm| {
            if (perm == permission) return true;
        }
        return false;
    }
    
    fn matchesPattern(pattern: []const u8, resource: []const u8) bool {
        if (std.mem.eql(u8, pattern, "*")) return true;
        if (std.mem.eql(u8, pattern, resource)) return true;
        if (std.mem.endsWith(u8, pattern, "*")) {
            const prefix = pattern[0..pattern.len-1];
            return std.mem.startsWith(u8, resource, prefix);
        }
        return false;
    }
};

pub const DelegationCondition = struct {
    condition_type: ConditionType,
    parameters: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    pub const ConditionType = enum {
        time_window,
        ip_whitelist,
        geolocation,
        mfa_required,
        stake_threshold,
        reputation_score,
        chain_verification,
    };
    
    pub fn init(allocator: std.mem.Allocator, condition_type: ConditionType) DelegationCondition {
        return DelegationCondition{
            .condition_type = condition_type,
            .parameters = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *DelegationCondition) void {
        self.parameters.deinit();
    }
    
    pub fn setParameter(self: *DelegationCondition, key: []const u8, value: []const u8) !void {
        try self.parameters.put(key, value);
    }
    
    pub fn evaluate(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        return switch (self.condition_type) {
            .time_window => self.evaluateTimeWindow(context),
            .ip_whitelist => self.evaluateIPWhitelist(context),
            .geolocation => self.evaluateGeolocation(context),
            .mfa_required => self.evaluateMFA(context),
            .stake_threshold => self.evaluateStakeThreshold(context),
            .reputation_score => self.evaluateReputationScore(context),
            .chain_verification => self.evaluateChainVerification(context),
        };
    }
    
    fn evaluateTimeWindow(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        const start_time_str = self.parameters.get("start_time") orelse return false;
        const end_time_str = self.parameters.get("end_time") orelse return false;
        
        const start_time = std.fmt.parseInt(u64, start_time_str, 10) catch return false;
        const end_time = std.fmt.parseInt(u64, end_time_str, 10) catch return false;
        
        return context.timestamp >= start_time and context.timestamp <= end_time;
    }
    
    fn evaluateIPWhitelist(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        const allowed_ips = self.parameters.get("allowed_ips") orelse return false;
        const client_ip = context.client_ip orelse return false;
        
        var ip_iter = std.mem.split(u8, allowed_ips, ",");
        while (ip_iter.next()) |ip| {
            if (std.mem.eql(u8, std.mem.trim(u8, ip, " "), client_ip)) return true;
        }
        return false;
    }
    
    fn evaluateGeolocation(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        const allowed_countries = self.parameters.get("allowed_countries") orelse return false;
        const client_country = context.client_country orelse return false;
        
        return std.mem.indexOf(u8, allowed_countries, client_country) != null;
    }
    
    fn evaluateMFA(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        _ = self;
        return context.mfa_verified;
    }
    
    fn evaluateStakeThreshold(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        const min_stake_str = self.parameters.get("min_stake") orelse return false;
        const min_stake = std.fmt.parseInt(u64, min_stake_str, 10) catch return false;
        
        return context.stake_amount >= min_stake;
    }
    
    fn evaluateReputationScore(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        const min_score_str = self.parameters.get("min_score") orelse return false;
        const min_score = std.fmt.parseInt(u32, min_score_str, 10) catch return false;
        
        return context.reputation_score >= min_score;
    }
    
    fn evaluateChainVerification(self: *const DelegationCondition, context: *const HierarchicalContext) bool {
        const required_chain_str = self.parameters.get("required_chain") orelse return false;
        const required_chain = cross_chain.ChainType.fromString(required_chain_str) orelse return false;
        
        return context.verified_chains.contains(@intFromEnum(required_chain));
    }
};

pub const HierarchicalDelegation = struct {
    id: []const u8,
    delegator: []const u8,
    delegate: []const u8,
    trust_level: TrustLevel,
    scope: DelegationScope,
    parent_delegation: ?[]const u8,
    child_delegations: std.ArrayList([]const u8),
    depth: u8,
    issued_at: u64,
    expires_at: u64,
    signature: access_token.Signature,
    zk_proof: ?zk_proof.ZkProof,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, id: []const u8, delegator: []const u8, delegate: []const u8, trust_level: TrustLevel, scope: DelegationScope, expires_in_seconds: u64) HierarchicalDelegation {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return HierarchicalDelegation{
            .id = id,
            .delegator = delegator,
            .delegate = delegate,
            .trust_level = trust_level,
            .scope = scope,
            .parent_delegation = null,
            .child_delegations = std.ArrayList([]const u8).init(allocator),
            .depth = 0,
            .issued_at = now,
            .expires_at = now + expires_in_seconds,
            .signature = access_token.Signature{ .bytes = std.mem.zeroes([64]u8) },
            .zk_proof = null,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *HierarchicalDelegation) void {
        self.scope.deinit();
        self.child_delegations.deinit();
        if (self.zk_proof) |*proof| {
            proof.deinit();
        }
    }
    
    pub fn addChildDelegation(self: *HierarchicalDelegation, child_id: []const u8) !void {
        try self.child_delegations.append(child_id);
    }
    
    pub fn setParent(self: *HierarchicalDelegation, parent_id: []const u8, parent_depth: u8) !void {
        self.parent_delegation = parent_id;
        self.depth = parent_depth + 1;
        
        if (self.depth > self.scope.max_depth) {
            return HierarchicalTrustError.DelegationDepthExceeded;
        }
    }
    
    pub fn isExpired(self: *const HierarchicalDelegation) bool {
        const now = @as(u64, @intCast(std.time.timestamp()));
        return now > self.expires_at;
    }
    
    pub fn canDelegate(self: *const HierarchicalDelegation, target_trust_level: TrustLevel) bool {
        return self.trust_level.canDelegate(target_trust_level) and self.depth < self.scope.max_depth;
    }
    
    pub fn validateAccess(self: *const HierarchicalDelegation, resource: []const u8, permission: guardian.Permission, context: *const HierarchicalContext) bool {
        if (self.isExpired()) return false;
        if (!self.scope.matchesResource(resource)) return false;
        if (!self.scope.hasPermission(permission)) return false;
        
        // Evaluate all conditions
        for (self.scope.conditions.items) |condition| {
            if (!condition.evaluate(context)) return false;
        }
        
        return true;
    }
    
    pub fn sign(self: *HierarchicalDelegation, private_key: access_token.PrivateKey) !void {
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();
        
        try payload.appendSlice(self.id);
        try payload.appendSlice(self.delegator);
        try payload.appendSlice(self.delegate);
        try payload.append(@intFromEnum(self.trust_level));
        try payload.append(self.depth);
        
        var issued_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &issued_bytes, self.issued_at, .little);
        try payload.appendSlice(&issued_bytes);
        
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        try payload.appendSlice(&expires_bytes);
        
        // Add scope data
        for (self.scope.resource_patterns.items) |pattern| {
            try payload.appendSlice(pattern);
        }
        
        for (self.scope.permissions.items) |perm| {
            try payload.append(@intFromEnum(perm));
        }
        
        self.signature = try access_token.signData(payload.items, private_key);
    }
    
    pub fn verify(self: *const HierarchicalDelegation, public_key: access_token.PublicKey) bool {
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();
        
        payload.appendSlice(self.id) catch return false;
        payload.appendSlice(self.delegator) catch return false;
        payload.appendSlice(self.delegate) catch return false;
        payload.append(@intFromEnum(self.trust_level)) catch return false;
        payload.append(self.depth) catch return false;
        
        var issued_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &issued_bytes, self.issued_at, .little);
        payload.appendSlice(&issued_bytes) catch return false;
        
        var expires_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &expires_bytes, self.expires_at, .little);
        payload.appendSlice(&expires_bytes) catch return false;
        
        // Add scope data
        for (self.scope.resource_patterns.items) |pattern| {
            payload.appendSlice(pattern) catch return false;
        }
        
        for (self.scope.permissions.items) |perm| {
            payload.append(@intFromEnum(perm)) catch return false;
        }
        
        return access_token.verifyData(self.signature, payload.items, public_key);
    }
    
    pub fn createZkProof(self: *HierarchicalDelegation, proof_system: *zk_proof.ZkProofSystem) !void {
        var witness = zk_proof.ZkWitness.init(self.allocator, self.id);
        defer witness.deinit();
        
        try witness.addPrivateInput(self.delegator);
        try witness.addPrivateInput(self.delegate);
        witness.setSecretKey(self.signature.bytes[0..32].*);
        
        var public_inputs = zk_proof.ZkPublicInputs.init(.delegation_chain);
        
        self.zk_proof = try proof_system.generateProof(.delegation_chain, &witness, &public_inputs);
    }
};

pub const HierarchicalContext = struct {
    timestamp: u64,
    client_ip: ?[]const u8,
    client_country: ?[]const u8,
    mfa_verified: bool,
    stake_amount: u64,
    reputation_score: u32,
    verified_chains: std.AutoHashMap(u8, void),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) HierarchicalContext {
        return HierarchicalContext{
            .timestamp = @intCast(std.time.timestamp()),
            .client_ip = null,
            .client_country = null,
            .mfa_verified = false,
            .stake_amount = 0,
            .reputation_score = 0,
            .verified_chains = std.AutoHashMap(u8, void).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *HierarchicalContext) void {
        self.verified_chains.deinit();
    }
    
    pub fn setClientIP(self: *HierarchicalContext, ip: []const u8) void {
        self.client_ip = ip;
    }
    
    pub fn setClientCountry(self: *HierarchicalContext, country: []const u8) void {
        self.client_country = country;
    }
    
    pub fn setMFAVerified(self: *HierarchicalContext, verified: bool) void {
        self.mfa_verified = verified;
    }
    
    pub fn setStakeAmount(self: *HierarchicalContext, amount: u64) void {
        self.stake_amount = amount;
    }
    
    pub fn setReputationScore(self: *HierarchicalContext, score: u32) void {
        self.reputation_score = score;
    }
    
    pub fn addVerifiedChain(self: *HierarchicalContext, chain: cross_chain.ChainType) !void {
        try self.verified_chains.put(@intFromEnum(chain), {});
    }
};

pub const HierarchicalTrustManager = struct {
    delegations: std.HashMap([]const u8, HierarchicalDelegation, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    delegation_chains: std.HashMap([]const u8, std.ArrayList([]const u8), std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    trust_roots: std.ArrayList([]const u8),
    max_delegation_depth: u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, max_depth: u8) HierarchicalTrustManager {
        return HierarchicalTrustManager{
            .delegations = std.HashMap([]const u8, HierarchicalDelegation, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .delegation_chains = std.HashMap([]const u8, std.ArrayList([]const u8), std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .trust_roots = std.ArrayList([]const u8).init(allocator),
            .max_delegation_depth = max_depth,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *HierarchicalTrustManager) void {
        var delegation_iter = self.delegations.iterator();
        while (delegation_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.delegations.deinit();
        
        var chain_iter = self.delegation_chains.iterator();
        while (chain_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.delegation_chains.deinit();
        
        self.trust_roots.deinit();
    }
    
    pub fn addTrustRoot(self: *HierarchicalTrustManager, root_identity: []const u8) !void {
        try self.trust_roots.append(root_identity);
    }
    
    pub fn createDelegation(self: *HierarchicalTrustManager, delegation: HierarchicalDelegation, parent_id: ?[]const u8) HierarchicalTrustError!void {
        // Validate delegation depth
        if (delegation.depth >= self.max_delegation_depth) {
            return HierarchicalTrustError.DelegationDepthExceeded;
        }
        
        // Check for circular delegation
        if (try self.wouldCreateCycle(delegation.delegator, delegation.delegate)) {
            return HierarchicalTrustError.CircularDelegation;
        }
        
        // Validate delegator authority
        if (parent_id) |parent| {
            const parent_delegation = self.delegations.get(parent) orelse return HierarchicalTrustError.UnauthorizedDelegator;
            if (!parent_delegation.canDelegate(delegation.trust_level)) {
                return HierarchicalTrustError.InsufficientAuthority;
            }
        } else {
            // Must be a trust root for top-level delegation
            var is_trust_root = false;
            for (self.trust_roots.items) |root| {
                if (std.mem.eql(u8, root, delegation.delegator)) {
                    is_trust_root = true;
                    break;
                }
            }
            if (!is_trust_root) {
                return HierarchicalTrustError.UnauthorizedDelegator;
            }
        }
        
        // Store delegation
        try self.delegations.put(delegation.id, delegation);
        
        // Update delegation chains
        try self.updateDelegationChain(delegation.delegate, delegation.id);
        
        // Update parent-child relationships
        if (parent_id) |parent| {
            if (self.delegations.getPtr(parent)) |parent_delegation| {
                try parent_delegation.addChildDelegation(delegation.id);
            }
        }
    }
    
    pub fn validateAccess(self: *HierarchicalTrustManager, delegate_id: []const u8, resource: []const u8, permission: guardian.Permission, context: *const HierarchicalContext) HierarchicalTrustError!bool {
        // Get delegation chain for delegate
        const chain = self.delegation_chains.get(delegate_id) orelse return false;
        
        // Check each delegation in the chain
        for (chain.items) |delegation_id| {
            const delegation = self.delegations.get(delegation_id) orelse continue;
            if (delegation.validateAccess(resource, permission, context)) {
                return true;
            }
        }
        
        return false;
    }
    
    pub fn getDelegationChain(self: *HierarchicalTrustManager, identity_id: []const u8) ?[]const []const u8 {
        if (self.delegation_chains.get(identity_id)) |chain| {
            return chain.items;
        }
        return null;
    }
    
    pub fn revokeDelegation(self: *HierarchicalTrustManager, delegation_id: []const u8) HierarchicalTrustError!void {
        const delegation = self.delegations.getPtr(delegation_id) orelse return HierarchicalTrustError.InvalidDelegationChain;
        
        // Recursively revoke all child delegations
        for (delegation.child_delegations.items) |child_id| {
            try self.revokeDelegation(child_id);
        }
        
        // Remove from delegation chains
        self.removeDelegationFromChains(delegation_id);
        
        // Remove the delegation
        var removed_delegation = self.delegations.fetchRemove(delegation_id).?;
        removed_delegation.value.deinit();
    }
    
    fn wouldCreateCycle(self: *HierarchicalTrustManager, delegator: []const u8, delegate: []const u8) HierarchicalTrustError!bool {
        // Check if delegate already has authority over delegator
        const delegate_chain = self.delegation_chains.get(delegate) orelse return false;
        
        for (delegate_chain.items) |delegation_id| {
            const delegation = self.delegations.get(delegation_id) orelse continue;
            if (std.mem.eql(u8, delegation.delegator, delegator)) {
                return true; // Would create cycle
            }
        }
        
        return false;
    }
    
    fn updateDelegationChain(self: *HierarchicalTrustManager, identity_id: []const u8, delegation_id: []const u8) !void {
        var chain = self.delegation_chains.get(identity_id) orelse blk: {
            const new_chain = std.ArrayList([]const u8).init(self.allocator);
            try self.delegation_chains.put(identity_id, new_chain);
            break :blk self.delegation_chains.getPtr(identity_id).?;
        };
        
        try chain.append(delegation_id);
    }
    
    fn removeDelegationFromChains(self: *HierarchicalTrustManager, delegation_id: []const u8) void {
        var chain_iter = self.delegation_chains.iterator();
        while (chain_iter.next()) |entry| {
            const chain = entry.value_ptr;
            for (chain.items, 0..) |id, i| {
                if (std.mem.eql(u8, id, delegation_id)) {
                    _ = chain.orderedRemove(i);
                    break;
                }
            }
        }
    }
};

pub const TrustMetrics = struct {
    identity_id: []const u8,
    trust_score: f32,
    delegation_count: u32,
    successful_operations: u64,
    failed_operations: u64,
    last_activity: u64,
    reputation_sources: std.ArrayList(ReputationSource),
    allocator: std.mem.Allocator,
    
    pub const ReputationSource = struct {
        source_chain: cross_chain.ChainType,
        source_contract: []const u8,
        score: f32,
        weight: f32,
        last_updated: u64,
    };
    
    pub fn init(allocator: std.mem.Allocator, identity_id: []const u8) TrustMetrics {
        return TrustMetrics{
            .identity_id = identity_id,
            .trust_score = 0.0,
            .delegation_count = 0,
            .successful_operations = 0,
            .failed_operations = 0,
            .last_activity = @intCast(std.time.timestamp()),
            .reputation_sources = std.ArrayList(ReputationSource).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *TrustMetrics) void {
        self.reputation_sources.deinit();
    }
    
    pub fn addReputationSource(self: *TrustMetrics, source: ReputationSource) !void {
        try self.reputation_sources.append(source);
        self.recalculateTrustScore();
    }
    
    pub fn recordSuccessfulOperation(self: *TrustMetrics) void {
        self.successful_operations += 1;
        self.last_activity = @intCast(std.time.timestamp());
        self.recalculateTrustScore();
    }
    
    pub fn recordFailedOperation(self: *TrustMetrics) void {
        self.failed_operations += 1;
        self.last_activity = @intCast(std.time.timestamp());
        self.recalculateTrustScore();
    }
    
    fn recalculateTrustScore(self: *TrustMetrics) void {
        var weighted_score: f32 = 0.0;
        var total_weight: f32 = 0.0;
        
        // Calculate weighted average from reputation sources
        for (self.reputation_sources.items) |source| {
            weighted_score += source.score * source.weight;
            total_weight += source.weight;
        }
        
        var base_score: f32 = if (total_weight > 0) weighted_score / total_weight else 0.5;
        
        // Adjust based on operation history
        const total_ops = self.successful_operations + self.failed_operations;
        if (total_ops > 0) {
            const success_rate = @as(f32, @floatFromInt(self.successful_operations)) / @as(f32, @floatFromInt(total_ops));
            base_score = base_score * 0.7 + success_rate * 0.3;
        }
        
        // Apply recency decay
        const now = @as(f32, @floatFromInt(@as(u64, @intCast(std.time.timestamp()))));
        const last_activity_f32 = @as(f32, @floatFromInt(self.last_activity));
        const days_since_activity = (now - last_activity_f32) / (24.0 * 60.0 * 60.0);
        const decay_factor = @max(0.1, @exp(-days_since_activity / 30.0)); // 30-day half-life
        
        self.trust_score = @max(0.0, @min(1.0, base_score * decay_factor));
    }
    
    pub fn getTrustLevel(self: *const TrustMetrics) TrustLevel {
        if (self.trust_score >= 0.9) return .ultimate;
        if (self.trust_score >= 0.7) return .trusted;
        if (self.trust_score >= 0.5) return .verified;
        if (self.trust_score >= 0.2) return .basic;
        return .none;
    }
};

pub fn createDefaultDelegationScope(allocator: std.mem.Allocator) !DelegationScope {
    var scope = DelegationScope.init(allocator, 3);
    try scope.addResourcePattern("*");
    try scope.addPermission(.read);
    try scope.addPermission(.write);
    return scope;
}

pub fn createAdminDelegationScope(allocator: std.mem.Allocator) !DelegationScope {
    var scope = DelegationScope.init(allocator, 5);
    try scope.addResourcePattern("*");
    try scope.addPermission(.read);
    try scope.addPermission(.write);
    try scope.addPermission(.execute);
    try scope.addPermission(.admin);
    try scope.addPermission(.delegate);
    return scope;
}

pub fn version() []const u8 {
    return "0.1.0";
}