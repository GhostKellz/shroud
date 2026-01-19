//! Multi-Party Authorization System for SHROUD
//! M-of-N authorization for high-value operations and distributed decision making

const std = @import("std");
const identity = @import("identity.zig");
const advanced_tokens = @import("advanced_tokens.zig");
const zk_proofs = @import("zk_proofs.zig");
const time_utils = @import("time_utils.zig");

/// Authorization participant information
pub const AuthorizationParticipant = struct {
    did: []const u8,
    role: ParticipantRole,
    weight: u32,
    public_key: [32]u8,
    status: ParticipantStatus,
    joined_at: i64,
    last_activity: i64,

    pub const ParticipantRole = enum {
        owner,
        admin,
        approver,
        observer,
        emergency_contact,
    };

    pub const ParticipantStatus = enum {
        active,
        suspended,
        revoked,
        pending,
    };

    pub fn init(did: []const u8, role: ParticipantRole, weight: u32, public_key: [32]u8) AuthorizationParticipant {
        return AuthorizationParticipant{
            .did = did,
            .role = role,
            .weight = weight,
            .public_key = public_key,
            .status = .active,
            .joined_at = time_utils.milliTimestamp(),
            .last_activity = time_utils.milliTimestamp(),
        };
    }

    pub fn isActive(self: *const AuthorizationParticipant) bool {
        return self.status == .active;
    }

    pub fn updateActivity(self: *AuthorizationParticipant) void {
        self.last_activity = time_utils.milliTimestamp();
    }
};

/// Authorization signature from a participant
pub const AuthorizationSignature = struct {
    participant_did: []const u8,
    signature: [64]u8,
    signed_at: i64,
    signature_type: SignatureType,
    metadata: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,

    pub const SignatureType = enum {
        approve,
        reject,
        abstain,
        conditional_approve,
    };

    pub fn init(allocator: std.mem.Allocator, participant_did: []const u8, signature: [64]u8, sig_type: SignatureType) AuthorizationSignature {
        return AuthorizationSignature{
            .participant_did = participant_did,
            .signature = signature,
            .signed_at = time_utils.milliTimestamp(),
            .signature_type = sig_type,
            .metadata = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AuthorizationSignature) void {
        self.metadata.deinit();
    }

    pub fn addMetadata(self: *AuthorizationSignature, key: []const u8, value: []const u8) !void {
        try self.metadata.put(key, value);
    }
};

/// Multi-party authorization request
pub const MultiPartyAuthRequest = struct {
    request_id: []const u8,
    operation_type: OperationType,
    operation_data: []const u8,
    requester_did: []const u8,
    required_approvals: u32,
    required_weight: u32,
    deadline: ?i64,
    created_at: i64,
    status: RequestStatus,
    signatures: std.ArrayList(AuthorizationSignature),
    participants: std.ArrayList(AuthorizationParticipant),
    reason: []const u8,
    emergency_override: bool,
    allocator: std.mem.Allocator,

    pub const OperationType = enum {
        high_value_transaction,
        identity_recovery,
        permission_grant,
        system_configuration,
        emergency_action,
        asset_transfer,
        contract_execution,
    };

    pub const RequestStatus = enum {
        pending,
        approved,
        rejected,
        expired,
        cancelled,
        emergency_approved,
    };

    pub fn init(allocator: std.mem.Allocator, request_id: []const u8, operation_type: OperationType, operation_data: []const u8, requester_did: []const u8) MultiPartyAuthRequest {
        return MultiPartyAuthRequest{
            .request_id = request_id,
            .operation_type = operation_type,
            .operation_data = operation_data,
            .requester_did = requester_did,
            .required_approvals = 2, // Default M-of-N: 2
            .required_weight = 100, // Default weight threshold
            .deadline = null,
            .created_at = time_utils.milliTimestamp(),
            .status = .pending,
            .signatures = std.ArrayList(AuthorizationSignature){},
            .participants = std.ArrayList(AuthorizationParticipant){},
            .reason = "",
            .emergency_override = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MultiPartyAuthRequest) void {
        for (self.signatures.items) |*sig| {
            sig.deinit();
        }
        self.signatures.deinit(self.allocator);
        self.participants.deinit(self.allocator);
    }

    pub fn addParticipant(self: *MultiPartyAuthRequest, participant: AuthorizationParticipant) !void {
        try self.participants.append(self.allocator, participant);
    }

    pub fn addSignature(self: *MultiPartyAuthRequest, signature: AuthorizationSignature) !void {
        try self.signatures.append(self.allocator, signature);
        self.updateStatus();
    }

    pub fn setDeadline(self: *MultiPartyAuthRequest, hours_from_now: u32) void {
        self.deadline = time_utils.milliTimestamp() + (@as(i64, @intCast(hours_from_now)) * 60 * 60 * 1000);
    }

    pub fn setThreshold(self: *MultiPartyAuthRequest, required_approvals: u32, required_weight: u32) void {
        self.required_approvals = required_approvals;
        self.required_weight = required_weight;
    }

    pub fn isExpired(self: *const MultiPartyAuthRequest) bool {
        if (self.deadline) |deadline| {
            return time_utils.milliTimestamp() > deadline;
        }
        return false;
    }

    pub fn getApprovalCount(self: *const MultiPartyAuthRequest) u32 {
        var count: u32 = 0;
        for (self.signatures.items) |signature| {
            if (signature.signature_type == .approve) {
                count += 1;
            }
        }
        return count;
    }

    pub fn getApprovalWeight(self: *const MultiPartyAuthRequest) u32 {
        var total_weight: u32 = 0;
        for (self.signatures.items) |signature| {
            if (signature.signature_type == .approve) {
                // Find participant weight
                for (self.participants.items) |participant| {
                    if (std.mem.eql(u8, participant.did, signature.participant_did)) {
                        total_weight += participant.weight;
                        break;
                    }
                }
            }
        }
        return total_weight;
    }

    pub fn getRejectionCount(self: *const MultiPartyAuthRequest) u32 {
        var count: u32 = 0;
        for (self.signatures.items) |signature| {
            if (signature.signature_type == .reject) {
                count += 1;
            }
        }
        return count;
    }

    fn updateStatus(self: *MultiPartyAuthRequest) void {
        if (self.isExpired()) {
            self.status = .expired;
            return;
        }

        const approval_count = self.getApprovalCount();
        const approval_weight = self.getApprovalWeight();
        const rejection_count = self.getRejectionCount();

        // Check if we have enough approvals
        if (approval_count >= self.required_approvals and approval_weight >= self.required_weight) {
            self.status = .approved;
        }
        // Check if too many rejections (more than half)
        else if (rejection_count > self.participants.items.len / 2) {
            self.status = .rejected;
        }
        // Otherwise remain pending
        else {
            self.status = .pending;
        }
    }
};

/// Emergency recovery context for identity restoration
pub const EmergencyRecoveryContext = struct {
    recovery_id: []const u8,
    lost_identity_did: []const u8,
    recovery_contacts: std.ArrayList(AuthorizationParticipant),
    required_confirmations: u32,
    recovery_method: RecoveryMethod,
    initiated_at: i64,
    expires_at: i64,
    confirmations: std.ArrayList(AuthorizationSignature),
    new_identity_proposal: ?[]const u8,
    allocator: std.mem.Allocator,

    pub const RecoveryMethod = enum {
        social_recovery,
        guardian_consensus,
        time_lock_recovery,
        legal_recovery,
        biometric_recovery,
    };

    pub fn init(allocator: std.mem.Allocator, recovery_id: []const u8, lost_identity_did: []const u8, method: RecoveryMethod) EmergencyRecoveryContext {
        return EmergencyRecoveryContext{
            .recovery_id = recovery_id,
            .lost_identity_did = lost_identity_did,
            .recovery_contacts = std.ArrayList(AuthorizationParticipant){},
            .required_confirmations = 3, // Default 3-of-N recovery
            .recovery_method = method,
            .initiated_at = time_utils.milliTimestamp(),
            .expires_at = time_utils.milliTimestamp() + (7 * 24 * 60 * 60 * 1000), // 7 days
            .confirmations = std.ArrayList(AuthorizationSignature){},
            .new_identity_proposal = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EmergencyRecoveryContext) void {
        self.recovery_contacts.deinit(self.allocator);
        for (self.confirmations.items) |*confirmation| {
            confirmation.deinit();
        }
        self.confirmations.deinit(self.allocator);
    }

    pub fn addRecoveryContact(self: *EmergencyRecoveryContext, contact: AuthorizationParticipant) !void {
        try self.recovery_contacts.append(self.allocator, contact);
    }

    pub fn addConfirmation(self: *EmergencyRecoveryContext, confirmation: AuthorizationSignature) !void {
        try self.confirmations.append(self.allocator, confirmation);
    }

    pub fn isRecoveryApproved(self: *const EmergencyRecoveryContext) bool {
        if (self.isExpired()) return false;

        var approval_count: u32 = 0;
        for (self.confirmations.items) |confirmation| {
            if (confirmation.signature_type == .approve) {
                approval_count += 1;
            }
        }

        return approval_count >= self.required_confirmations;
    }

    pub fn isExpired(self: *const EmergencyRecoveryContext) bool {
        return time_utils.milliTimestamp() > self.expires_at;
    }
};

/// Multi-party authorization system
pub const MultiPartyAuthSystem = struct {
    active_requests: std.HashMap([]const u8, MultiPartyAuthRequest, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    recovery_contexts: std.HashMap([]const u8, EmergencyRecoveryContext, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    participant_registry: std.HashMap([]const u8, AuthorizationParticipant, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    signature_threshold: u32,
    weight_threshold: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MultiPartyAuthSystem {
        return MultiPartyAuthSystem{
            .active_requests = std.HashMap([]const u8, MultiPartyAuthRequest, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .recovery_contexts = std.HashMap([]const u8, EmergencyRecoveryContext, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .participant_registry = std.HashMap([]const u8, AuthorizationParticipant, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .signature_threshold = 2,
            .weight_threshold = 100,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MultiPartyAuthSystem) void {
        var request_iter = self.active_requests.iterator();
        while (request_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.active_requests.deinit();

        var recovery_iter = self.recovery_contexts.iterator();
        while (recovery_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.recovery_contexts.deinit();

        self.participant_registry.deinit();
    }

    /// Register a participant in the authorization system
    pub fn registerParticipant(self: *MultiPartyAuthSystem, participant: AuthorizationParticipant) !void {
        try self.participant_registry.put(participant.did, participant);
    }

    /// Create a new multi-party authorization request
    pub fn createAuthRequest(self: *MultiPartyAuthSystem, request_id: []const u8, operation_type: MultiPartyAuthRequest.OperationType, operation_data: []const u8, requester_did: []const u8) !void {
        var request = MultiPartyAuthRequest.init(self.allocator, request_id, operation_type, operation_data, requester_did);
        request.setThreshold(self.signature_threshold, self.weight_threshold);

        // Add relevant participants based on operation type
        try self.addRelevantParticipants(&request, operation_type);

        try self.active_requests.put(request_id, request);
    }

    /// Submit a signature for an authorization request
    pub fn submitSignature(self: *MultiPartyAuthSystem, request_id: []const u8, signature: AuthorizationSignature) !bool {
        if (self.active_requests.getPtr(request_id)) |request| {
            // Verify the participant is authorized
            if (!self.isParticipantAuthorized(signature.participant_did, request)) {
                return error.UnauthorizedParticipant;
            }

            // Check for duplicate signatures
            for (request.signatures.items) |existing_sig| {
                if (std.mem.eql(u8, existing_sig.participant_did, signature.participant_did)) {
                    return error.DuplicateSignature;
                }
            }

            // Add signature and update status
            try request.addSignature(signature);

            return request.status == .approved;
        }
        return error.RequestNotFound;
    }

    /// Initiate emergency identity recovery
    pub fn initiateEmergencyRecovery(self: *MultiPartyAuthSystem, recovery_id: []const u8, lost_identity_did: []const u8, method: EmergencyRecoveryContext.RecoveryMethod) !void {
        var recovery_context = EmergencyRecoveryContext.init(self.allocator, recovery_id, lost_identity_did, method);

        // Add emergency contacts based on the lost identity
        try self.addEmergencyContacts(&recovery_context, lost_identity_did);

        try self.recovery_contexts.put(recovery_id, recovery_context);
    }

    /// Submit confirmation for emergency recovery
    pub fn submitRecoveryConfirmation(self: *MultiPartyAuthSystem, recovery_id: []const u8, confirmation: AuthorizationSignature) !bool {
        if (self.recovery_contexts.getPtr(recovery_id)) |recovery| {
            try recovery.addConfirmation(confirmation);
            return recovery.isRecoveryApproved();
        }
        return error.RecoveryNotFound;
    }

    /// Get status of an authorization request
    pub fn getRequestStatus(self: *MultiPartyAuthSystem, request_id: []const u8) ?MultiPartyAuthRequest.RequestStatus {
        if (self.active_requests.get(request_id)) |request| {
            return request.status;
        }
        return null;
    }

    /// Clean up expired requests
    pub fn cleanupExpiredRequests(self: *MultiPartyAuthSystem) !void {
        var to_remove = std.ArrayList([]const u8){};
        defer to_remove.deinit(self.allocator);

        var iterator = self.active_requests.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                entry.value_ptr.status = .expired;
                try to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (to_remove.items) |request_id| {
            if (self.active_requests.fetchRemove(request_id)) |removed| {
                removed.value.deinit(self.allocator);
            }
        }
    }

    fn addRelevantParticipants(self: *MultiPartyAuthSystem, request: *MultiPartyAuthRequest, operation_type: MultiPartyAuthRequest.OperationType) !void {
        var participant_iter = self.participant_registry.iterator();
        while (participant_iter.next()) |entry| {
            const participant = entry.value_ptr.*;

            // Add participants based on operation type and role
            const should_include = switch (operation_type) {
                .high_value_transaction => participant.role == .owner or participant.role == .admin,
                .identity_recovery => participant.role == .emergency_contact or participant.role == .admin,
                .permission_grant => participant.role == .admin or participant.role == .approver,
                .system_configuration => participant.role == .owner or participant.role == .admin,
                .emergency_action => participant.role != .observer,
                .asset_transfer => participant.role == .owner or participant.role == .admin,
                .contract_execution => participant.role == .admin or participant.role == .approver,
            };

            if (should_include and participant.isActive()) {
                try request.addParticipant(participant);
            }
        }
    }

    fn addEmergencyContacts(self: *MultiPartyAuthSystem, recovery: *EmergencyRecoveryContext, lost_identity_did: []const u8) !void {
        _ = lost_identity_did;

        var participant_iter = self.participant_registry.iterator();
        while (participant_iter.next()) |entry| {
            const participant = entry.value_ptr.*;
            if (participant.role == .emergency_contact and participant.isActive()) {
                try recovery.addRecoveryContact(participant);
            }
        }
    }

    fn isParticipantAuthorized(self: *MultiPartyAuthSystem, participant_did: []const u8, request: *const MultiPartyAuthRequest) bool {
        _ = self;

        for (request.participants.items) |participant| {
            if (std.mem.eql(u8, participant.did, participant_did) and participant.isActive()) {
                return true;
            }
        }
        return false;
    }
};

test "multi-party authorization basic flow" {
    var auth_system = MultiPartyAuthSystem.init(std.testing.allocator);
    defer auth_system.deinit();

    // Register participants
    const alice = AuthorizationParticipant.init("did:shroud:alice", .owner, 100, [_]u8{1} ** 32);
    const bob = AuthorizationParticipant.init("did:shroud:bob", .admin, 75, [_]u8{2} ** 32);
    const charlie = AuthorizationParticipant.init("did:shroud:charlie", .approver, 50, [_]u8{3} ** 32);

    try auth_system.registerParticipant(alice);
    try auth_system.registerParticipant(bob);
    try auth_system.registerParticipant(charlie);

    // Create authorization request
    try auth_system.createAuthRequest("req-001", .high_value_transaction, "transfer 1000 ETH", "did:shroud:alice");

    // Submit approval signatures
    const alice_sig = AuthorizationSignature.init(std.testing.allocator, "did:shroud:alice", [_]u8{0xAA} ** 64, .approve);
    const bob_sig = AuthorizationSignature.init(std.testing.allocator, "did:shroud:bob", [_]u8{0xBB} ** 64, .approve);

    const alice_approved = try auth_system.submitSignature("req-001", alice_sig);
    try std.testing.expect(!alice_approved); // Not enough signatures yet

    const bob_approved = try auth_system.submitSignature("req-001", bob_sig);
    try std.testing.expect(bob_approved); // Should be approved now

    // Check final status
    const status = auth_system.getRequestStatus("req-001");
    try std.testing.expect(status.? == .approved);
}

test "emergency identity recovery" {
    var auth_system = MultiPartyAuthSystem.init(std.testing.allocator);
    defer auth_system.deinit();

    // Register emergency contacts
    const contact1 = AuthorizationParticipant.init("did:shroud:contact1", .emergency_contact, 100, [_]u8{1} ** 32);
    const contact2 = AuthorizationParticipant.init("did:shroud:contact2", .emergency_contact, 100, [_]u8{2} ** 32);
    const contact3 = AuthorizationParticipant.init("did:shroud:contact3", .emergency_contact, 100, [_]u8{3} ** 32);

    try auth_system.registerParticipant(contact1);
    try auth_system.registerParticipant(contact2);
    try auth_system.registerParticipant(contact3);

    // Initiate recovery
    try auth_system.initiateEmergencyRecovery("recovery-001", "did:shroud:lost_user", .social_recovery);

    // Submit confirmations
    const conf1 = AuthorizationSignature.init(std.testing.allocator, "did:shroud:contact1", [_]u8{0x11} ** 64, .approve);
    const conf2 = AuthorizationSignature.init(std.testing.allocator, "did:shroud:contact2", [_]u8{0x22} ** 64, .approve);
    const conf3 = AuthorizationSignature.init(std.testing.allocator, "did:shroud:contact3", [_]u8{0x33} ** 64, .approve);

    const approved1 = try auth_system.submitRecoveryConfirmation("recovery-001", conf1);
    try std.testing.expect(!approved1); // Need more confirmations

    const approved2 = try auth_system.submitRecoveryConfirmation("recovery-001", conf2);
    try std.testing.expect(!approved2); // Still need one more

    const approved3 = try auth_system.submitRecoveryConfirmation("recovery-001", conf3);
    try std.testing.expect(approved3); // Should be approved now
}

test "authorization thresholds and weights" {
    var auth_system = MultiPartyAuthSystem.init(std.testing.allocator);
    defer auth_system.deinit();

    // Register participants with different weights
    const owner = AuthorizationParticipant.init("did:shroud:owner", .owner, 200, [_]u8{1} ** 32);
    const admin = AuthorizationParticipant.init("did:shroud:admin", .admin, 100, [_]u8{2} ** 32);
    const approver = AuthorizationParticipant.init("did:shroud:approver", .approver, 50, [_]u8{3} ** 32);

    try auth_system.registerParticipant(owner);
    try auth_system.registerParticipant(admin);
    try auth_system.registerParticipant(approver);

    // Set higher thresholds
    auth_system.signature_threshold = 2;
    auth_system.weight_threshold = 150;

    // Create request
    try auth_system.createAuthRequest("req-002", .system_configuration, "update system params", "did:shroud:owner");

    // Owner approval alone should be sufficient (weight 200 > threshold 150)
    const owner_sig = AuthorizationSignature.init(std.testing.allocator, "did:shroud:owner", [_]u8{0xAA} ** 64, .approve);
    const admin_sig = AuthorizationSignature.init(std.testing.allocator, "did:shroud:admin", [_]u8{0xBB} ** 64, .approve);

    const first_approved = try auth_system.submitSignature("req-002", owner_sig);
    try std.testing.expect(!first_approved); // Need 2 signatures minimum

    const second_approved = try auth_system.submitSignature("req-002", admin_sig);
    try std.testing.expect(second_approved); // Should be approved (2 sigs + 300 weight)
}
