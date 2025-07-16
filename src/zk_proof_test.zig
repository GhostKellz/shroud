const std = @import("std");
const testing = std.testing;
const zk_proof = @import("zk_proof.zig");
const access_token = @import("access_token.zig");

test "ZkProof basic functionality" {
    const allocator = testing.allocator;
    
    // Create ZK proof system
    var proof_system = zk_proof.ZkProofSystem.init(allocator);
    defer proof_system.deinit();
    
    // Create witness
    var witness = zk_proof.ZkWitness.init(allocator, "test_identity");
    defer witness.deinit();
    
    const secret_key = [_]u8{1} ** 32;
    witness.setSecretKey(secret_key);
    try witness.addPrivateInput("private_data");
    
    // Create public inputs
    var public_inputs = zk_proof.ZkPublicInputs.init(.identity_verification);
    
    // Generate proof
    var proof = try proof_system.generateProof(.identity_verification, &witness, &public_inputs);
    defer proof.deinit();
    
    // Verify proof
    const is_valid = try proof_system.verifyProof(&proof);
    try testing.expect(is_valid);
}

test "ZkAttestation creation and verification" {
    const allocator = testing.allocator;
    
    // Generate signing keypair
    const keypair = try access_token.generateEphemeralKeyPair();
    
    // Create ZK proof system
    var proof_system = zk_proof.ZkProofSystem.init(allocator);
    defer proof_system.deinit();
    
    // Create identity attestation
    const secret_key = [_]u8{42} ** 32;
    var attestation = try proof_system.createIdentityAttestation(
        "did:shroud:alice",
        secret_key,
        3600, // 1 hour
        keypair.private_key
    );
    defer attestation.deinit();
    
    // Verify attestation
    const is_valid = try proof_system.verifyIdentityAttestation(&attestation, keypair.public_key);
    try testing.expect(is_valid);
    
    try testing.expect(!attestation.isExpired());
}

test "EphemeralIdentity functionality" {
    const allocator = testing.allocator;
    
    // Create ephemeral identity
    var ephemeral = try zk_proof.EphemeralIdentity.init(allocator, .anonymous, 3600);
    defer ephemeral.deinit();
    
    try testing.expect(!ephemeral.isExpired());
    
    // Create ZK proof system for proof generation
    var proof_system = zk_proof.ZkProofSystem.init(allocator);
    defer proof_system.deinit();
    
    // Create proof for ephemeral identity
    try ephemeral.createProof(&proof_system, .identity_verification);
    
    // Verify proof
    const is_valid = try ephemeral.verifyProof(&proof_system);
    try testing.expect(is_valid);
}

test "Privacy levels" {
    const allocator = testing.allocator;
    
    // Test different privacy levels
    const privacy_levels = [_]zk_proof.PrivacyLevel{ .public, .pseudonymous, .anonymous, .unlinkable };
    
    for (privacy_levels) |level| {
        var ephemeral = try zk_proof.EphemeralIdentity.init(allocator, level, 3600);
        defer ephemeral.deinit();
        
        try testing.expect(ephemeral.privacy_level == level);
        try testing.expect(!ephemeral.isExpired());
    }
}

test "ZkProof circuit types" {
    const allocator = testing.allocator;
    
    var proof_system = zk_proof.ZkProofSystem.init(allocator);
    defer proof_system.deinit();
    
    const circuit_types = [_]zk_proof.ZkCircuitType{
        .identity_verification,
        .permission_check,
        .delegation_chain,
        .balance_proof,
        .reputation_proof,
    };
    
    for (circuit_types) |circuit_type| {
        var witness = zk_proof.ZkWitness.init(allocator, "test_data");
        defer witness.deinit();
        
        witness.setSecretKey([_]u8{1} ** 32);
        try witness.addPrivateInput("test_input");
        
        var public_inputs = zk_proof.ZkPublicInputs.init(circuit_type);
        
        var proof = try proof_system.generateProof(circuit_type, &witness, &public_inputs);
        defer proof.deinit();
        
        const is_valid = try proof_system.verifyProof(&proof);
        try testing.expect(is_valid);
        try testing.expect(proof.circuit_type == circuit_type);
    }
}

test "ZkAttestation expiration" {
    const allocator = testing.allocator;
    
    // Create attestation with very short expiration
    var attestation = zk_proof.ZkAttestation.init(allocator, "test_identity", .identity_ownership, 0);
    defer attestation.deinit();
    
    // Should be expired immediately
    try testing.expect(attestation.isExpired());
}

test "ZkWitness management" {
    const allocator = testing.allocator;
    
    var witness = zk_proof.ZkWitness.init(allocator, "identity_data");
    defer witness.deinit();
    
    // Add multiple private inputs
    try witness.addPrivateInput("input1");
    try witness.addPrivateInput("input2");
    try witness.addPrivateInput("input3");
    
    try testing.expect(witness.private_inputs.items.len == 3);
    try testing.expect(std.mem.eql(u8, witness.private_inputs.items[0], "input1"));
    try testing.expect(std.mem.eql(u8, witness.private_inputs.items[1], "input2"));
    try testing.expect(std.mem.eql(u8, witness.private_inputs.items[2], "input3"));
    
    // Set secret key
    const secret_key = [_]u8{99} ** 32;
    witness.setSecretKey(secret_key);
    try testing.expect(std.mem.eql(u8, &witness.secret_key, &secret_key));
}