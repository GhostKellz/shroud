const std = @import("std");
const testing = std.testing;
const hierarchical_trust = @import("hierarchical_trust.zig");
const guardian = @import("guardian.zig");
const access_token = @import("access_token.zig");
const cross_chain = @import("cross_chain.zig");

test "TrustLevel delegation authority" {
    try testing.expect(hierarchical_trust.TrustLevel.ultimate.canDelegate(.trusted));
    try testing.expect(hierarchical_trust.TrustLevel.trusted.canDelegate(.verified));
    try testing.expect(hierarchical_trust.TrustLevel.verified.canDelegate(.basic));
    try testing.expect(!hierarchical_trust.TrustLevel.basic.canDelegate(.verified));
    try testing.expect(!hierarchical_trust.TrustLevel.none.canDelegate(.basic));
}

test "DelegationScope creation and matching" {
    const allocator = testing.allocator;
    
    var scope = hierarchical_trust.DelegationScope.init(allocator, 3);
    defer scope.deinit();
    
    // Add resource patterns
    try scope.addResourcePattern("/users/*");
    try scope.addResourcePattern("/public/docs");
    try scope.addResourcePattern("*");
    
    // Add permissions
    try scope.addPermission(.read);
    try scope.addPermission(.write);
    
    // Test resource matching
    try testing.expect(scope.matchesResource("/users/alice"));
    try testing.expect(scope.matchesResource("/users/bob/profile"));
    try testing.expect(scope.matchesResource("/public/docs"));
    try testing.expect(scope.matchesResource("/anything")); // matches "*"
    
    // Test permission checking
    try testing.expect(scope.hasPermission(.read));
    try testing.expect(scope.hasPermission(.write));
    try testing.expect(!scope.hasPermission(.admin));
}

test "DelegationCondition evaluation" {
    const allocator = testing.allocator;
    
    // Create hierarchical context
    var context = hierarchical_trust.HierarchicalContext.init(allocator);
    defer context.deinit();
    
    context.setClientIP("192.168.1.100");
    context.setClientCountry("US");
    context.setMFAVerified(true);
    context.setStakeAmount(1000);
    context.setReputationScore(850);
    try context.addVerifiedChain(.ethereum);
    
    // Test IP whitelist condition
    var ip_condition = hierarchical_trust.DelegationCondition.init(allocator, .ip_whitelist);
    defer ip_condition.deinit();
    try ip_condition.setParameter("allowed_ips", "192.168.1.100,10.0.0.1");
    
    try testing.expect(ip_condition.evaluate(&context));
    
    // Test MFA condition
    var mfa_condition = hierarchical_trust.DelegationCondition.init(allocator, .mfa_required);
    defer mfa_condition.deinit();
    
    try testing.expect(mfa_condition.evaluate(&context));
    
    // Test stake threshold condition
    var stake_condition = hierarchical_trust.DelegationCondition.init(allocator, .stake_threshold);
    defer stake_condition.deinit();
    try stake_condition.setParameter("min_stake", "500");
    
    try testing.expect(stake_condition.evaluate(&context));
    
    // Test reputation score condition
    var reputation_condition = hierarchical_trust.DelegationCondition.init(allocator, .reputation_score);
    defer reputation_condition.deinit();
    try reputation_condition.setParameter("min_score", "800");
    
    try testing.expect(reputation_condition.evaluate(&context));
    
    // Test chain verification condition
    var chain_condition = hierarchical_trust.DelegationCondition.init(allocator, .chain_verification);
    defer chain_condition.deinit();
    try chain_condition.setParameter("required_chain", "ethereum");
    
    try testing.expect(chain_condition.evaluate(&context));
}

test "HierarchicalDelegation creation and validation" {
    const allocator = testing.allocator;
    
    // Create delegation scope
    var scope = try hierarchical_trust.createDefaultDelegationScope(allocator);
    
    // Create hierarchical delegation
    var delegation = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "delegation_001",
        "did:shroud:alice",
        "did:shroud:bob",
        .trusted,
        scope,
        86400 // 24 hours
    );
    defer delegation.deinit();
    
    try testing.expect(!delegation.isExpired());
    try testing.expect(delegation.canDelegate(.verified));
    try testing.expect(!delegation.canDelegate(.ultimate));
    try testing.expect(delegation.depth == 0);
    
    // Sign delegation
    const keypair = try access_token.generateEphemeralKeyPair();
    try delegation.sign(keypair.private_key);
    
    // Verify signature
    try testing.expect(delegation.verify(keypair.public_key));
    
    // Test access validation
    var context = hierarchical_trust.HierarchicalContext.init(allocator);
    defer context.deinit();
    
    const has_access = delegation.validateAccess("test_resource", .read, &context);
    try testing.expect(has_access);
}

test "HierarchicalTrustManager delegation management" {
    const allocator = testing.allocator;
    
    var trust_manager = hierarchical_trust.HierarchicalTrustManager.init(allocator, 5);
    defer trust_manager.deinit();
    
    // Add trust root
    try trust_manager.addTrustRoot("did:shroud:root");
    
    // Create root delegation
    var root_scope = try hierarchical_trust.createAdminDelegationScope(allocator);
    var root_delegation = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "root_delegation",
        "did:shroud:root",
        "did:shroud:admin",
        .ultimate,
        root_scope,
        86400
    );
    
    try trust_manager.createDelegation(root_delegation, null);
    
    // Create child delegation
    var child_scope = try hierarchical_trust.createDefaultDelegationScope(allocator);
    var child_delegation = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "child_delegation",
        "did:shroud:admin",
        "did:shroud:user",
        .verified,
        child_scope,
        86400
    );
    try child_delegation.setParent("root_delegation", 0);
    
    try trust_manager.createDelegation(child_delegation, "root_delegation");
    
    // Validate access through delegation chain
    var context = hierarchical_trust.HierarchicalContext.init(allocator);
    defer context.deinit();
    
    const has_access = try trust_manager.validateAccess("did:shroud:user", "test_resource", .read, &context);
    try testing.expect(has_access);
    
    // Test delegation chain retrieval
    const chain = trust_manager.getDelegationChain("did:shroud:user");
    try testing.expect(chain != null);
    try testing.expect(chain.?.len == 1);
}

test "TrustMetrics calculation" {
    const allocator = testing.allocator;
    
    var metrics = hierarchical_trust.TrustMetrics.init(allocator, "did:shroud:alice");
    defer metrics.deinit();
    
    // Initially should have no trust
    try testing.expect(metrics.getTrustLevel() == .none);
    
    // Add reputation source
    const reputation_source = hierarchical_trust.TrustMetrics.ReputationSource{
        .source_chain = .ethereum,
        .source_contract = "0x1234",
        .score = 0.8,
        .weight = 1.0,
        .last_updated = @intCast(std.time.timestamp()),
    };
    try metrics.addReputationSource(reputation_source);
    
    // Should have better trust level
    try testing.expect(metrics.trust_score > 0.0);
    
    // Record successful operations
    metrics.recordSuccessfulOperation();
    metrics.recordSuccessfulOperation();
    metrics.recordSuccessfulOperation();
    
    // Should have high trust level
    const trust_level = metrics.getTrustLevel();
    try testing.expect(@intFromEnum(trust_level) >= @intFromEnum(hierarchical_trust.TrustLevel.verified));
    
    // Record failed operation
    metrics.recordFailedOperation();
    
    // Trust score should be updated
    try testing.expect(metrics.failed_operations == 1);
    try testing.expect(metrics.successful_operations == 3);
}

test "Circular delegation detection" {
    const allocator = testing.allocator;
    
    var trust_manager = hierarchical_trust.HierarchicalTrustManager.init(allocator, 5);
    defer trust_manager.deinit();
    
    // Add trust roots
    try trust_manager.addTrustRoot("did:shroud:alice");
    try trust_manager.addTrustRoot("did:shroud:bob");
    
    // Create first delegation: alice -> bob
    var scope1 = try hierarchical_trust.createDefaultDelegationScope(allocator);
    var delegation1 = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "alice_to_bob",
        "did:shroud:alice",
        "did:shroud:bob",
        .trusted,
        scope1,
        86400
    );
    
    try trust_manager.createDelegation(delegation1, null);
    
    // Attempt to create circular delegation: bob -> alice
    var scope2 = try hierarchical_trust.createDefaultDelegationScope(allocator);
    var delegation2 = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "bob_to_alice",
        "did:shroud:bob",
        "did:shroud:alice",
        .verified,
        scope2,
        86400
    );
    
    // This should fail due to circular delegation
    const result = trust_manager.createDelegation(delegation2, "alice_to_bob");
    try testing.expectError(hierarchical_trust.HierarchicalTrustError.CircularDelegation, result);
    
    // Clean up the delegation that wasn't added
    delegation2.deinit();
}

test "Delegation depth limits" {
    const allocator = testing.allocator;
    
    var trust_manager = hierarchical_trust.HierarchicalTrustManager.init(allocator, 2); // Max depth 2
    defer trust_manager.deinit();
    
    try trust_manager.addTrustRoot("did:shroud:root");
    
    // Create delegations at different depths
    var scope1 = try hierarchical_trust.createDefaultDelegationScope(allocator);
    var delegation1 = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "depth_0",
        "did:shroud:root",
        "did:shroud:level1",
        .ultimate,
        scope1,
        86400
    );
    
    try trust_manager.createDelegation(delegation1, null);
    
    var scope2 = try hierarchical_trust.createDefaultDelegationScope(allocator);
    var delegation2 = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "depth_1",
        "did:shroud:level1",
        "did:shroud:level2",
        .trusted,
        scope2,
        86400
    );
    try delegation2.setParent("depth_0", 0);
    
    try trust_manager.createDelegation(delegation2, "depth_0");
    
    // Attempt to create delegation beyond max depth
    var scope3 = try hierarchical_trust.createDefaultDelegationScope(allocator);
    var delegation3 = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "depth_2",
        "did:shroud:level2",
        "did:shroud:level3",
        .verified,
        scope3,
        86400
    );
    try delegation3.setParent("depth_1", 1);
    
    // This should fail due to depth limit
    const result = trust_manager.createDelegation(delegation3, "depth_1");
    try testing.expectError(hierarchical_trust.HierarchicalTrustError.DelegationDepthExceeded, result);
    
    // Clean up the delegation that wasn't added
    delegation3.deinit();
}

test "Delegation revocation cascade" {
    const allocator = testing.allocator;
    
    var trust_manager = hierarchical_trust.HierarchicalTrustManager.init(allocator, 5);
    defer trust_manager.deinit();
    
    try trust_manager.addTrustRoot("did:shroud:root");
    
    // Create delegation tree
    var root_scope = try hierarchical_trust.createAdminDelegationScope(allocator);
    var root_delegation = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "root_del",
        "did:shroud:root",
        "did:shroud:admin",
        .ultimate,
        root_scope,
        86400
    );
    
    try trust_manager.createDelegation(root_delegation, null);
    
    var child_scope = try hierarchical_trust.createDefaultDelegationScope(allocator);
    var child_delegation = hierarchical_trust.HierarchicalDelegation.init(
        allocator,
        "child_del",
        "did:shroud:admin",
        "did:shroud:user",
        .verified,
        child_scope,
        86400
    );
    try child_delegation.setParent("root_del", 0);
    
    try trust_manager.createDelegation(child_delegation, "root_del");
    
    // Verify delegations exist
    try testing.expect(trust_manager.delegations.count() == 2);
    
    // Revoke root delegation (should cascade to children)
    try trust_manager.revokeDelegation("root_del");
    
    // All delegations should be removed
    try testing.expect(trust_manager.delegations.count() == 0);
}