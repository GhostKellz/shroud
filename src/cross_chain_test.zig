const std = @import("std");
const testing = std.testing;
const cross_chain = @import("cross_chain.zig");
const zk_proof = @import("zk_proof.zig");
const access_token = @import("access_token.zig");

test "DID parsing and formatting" {
    const allocator = testing.allocator;
    
    // Test valid DID
    const did_string = "did:shroud:ethereum:0x1234567890123456789012345678901234567890";
    const did = try cross_chain.DID.parse(did_string);
    
    try testing.expect(std.mem.eql(u8, did.method, "shroud"));
    try testing.expect(did.chain == .ethereum);
    try testing.expect(std.mem.eql(u8, did.identifier, "0x1234567890123456789012345678901234567890"));
    
    // Test DID to string conversion
    const reconstructed = try did.toString(allocator);
    defer allocator.free(reconstructed);
    try testing.expect(std.mem.eql(u8, reconstructed, did_string));
    
    // Test invalid DID
    const invalid_did = "invalid:did:format";
    const parse_result = cross_chain.DID.parse(invalid_did);
    try testing.expectError(cross_chain.CrossChainError.InvalidDID, parse_result);
}

test "ChainType conversion" {
    // Test string to ChainType conversion
    try testing.expect(cross_chain.ChainType.fromString("ethereum") == .ethereum);
    try testing.expect(cross_chain.ChainType.fromString("polygon") == .polygon);
    try testing.expect(cross_chain.ChainType.fromString("solana") == .solana);
    try testing.expect(cross_chain.ChainType.fromString("ghostchain") == .ghostchain);
    try testing.expect(cross_chain.ChainType.fromString("invalid") == null);
    
    // Test ChainType to string conversion
    try testing.expect(std.mem.eql(u8, cross_chain.ChainType.ethereum.toString(), "ethereum"));
    try testing.expect(std.mem.eql(u8, cross_chain.ChainType.polygon.toString(), "polygon"));
    try testing.expect(std.mem.eql(u8, cross_chain.ChainType.solana.toString(), "solana"));
    try testing.expect(std.mem.eql(u8, cross_chain.ChainType.ghostchain.toString(), "ghostchain"));
}

test "CrossChainIdentity creation and anchoring" {
    const allocator = testing.allocator;
    
    const primary_did = cross_chain.DID{
        .method = "shroud",
        .chain = .ethereum,
        .identifier = "0x1234567890123456789012345678901234567890",
    };
    
    var identity = cross_chain.CrossChainIdentity.init(allocator, primary_did);
    defer identity.deinit();
    
    // Test anchoring to different chains
    try identity.anchorToChain(.polygon, "0xpolygonaddress", "polygon_proof");
    try identity.anchorToChain(.solana, "solana_pubkey", "solana_proof");
    
    try testing.expect(identity.verifyOnChain(.polygon));
    try testing.expect(identity.verifyOnChain(.solana));
    try testing.expect(!identity.verifyOnChain(.bitcoin));
    
    try testing.expect(identity.anchored_chains.count() == 2);
}

test "VerifiableCredential creation and verification" {
    const allocator = testing.allocator;
    
    const issuer_did = cross_chain.DID{
        .method = "shroud",
        .chain = .ethereum,
        .identifier = "issuer123",
    };
    
    const subject_did = cross_chain.DID{
        .method = "shroud",
        .chain = .ethereum,
        .identifier = "subject456",
    };
    
    var credential = cross_chain.VerifiableCredential.init(
        allocator,
        "cred_001",
        issuer_did,
        subject_did,
        "IdentityCredential",
        86400 // 24 hours
    );
    defer credential.deinit();
    
    // Add claims
    try credential.addClaim("name", "Alice");
    try credential.addClaim("role", "developer");
    try credential.addClaim("verified", "true");
    
    try testing.expect(!credential.isExpired());
    try testing.expect(credential.claims.count() == 3);
    
    // Sign credential
    const keypair = try access_token.generateEphemeralKeyPair();
    try credential.sign(keypair.private_key);
    
    // Verify credential
    const is_valid = credential.verify(keypair.public_key);
    try testing.expect(is_valid);
}

test "CrossChainResolver setup and resolution" {
    const allocator = testing.allocator;
    
    var resolver = cross_chain.CrossChainResolver.init(allocator);
    defer resolver.deinit();
    
    // Add default chain configurations
    try cross_chain.createDefaultChainConfigs(allocator, &resolver);
    
    // Should have supported chains
    try testing.expect(resolver.supported_chains.count() >= 4);
    try testing.expect(resolver.supported_chains.contains(.ethereum));
    try testing.expect(resolver.supported_chains.contains(.polygon));
    try testing.expect(resolver.supported_chains.contains(.ghostchain));
    try testing.expect(resolver.supported_chains.contains(.keystone));
}

test "CrossChainResolver DID resolution" {
    const allocator = testing.allocator;
    
    var resolver = cross_chain.CrossChainResolver.init(allocator);
    defer resolver.deinit();
    
    // Add chain support
    try cross_chain.createDefaultChainConfigs(allocator, &resolver);
    
    // Resolve a DID
    const did_string = "did:shroud:ethereum:0x1234567890123456789012345678901234567890";
    var resolved_identity = try resolver.resolveDID(did_string);
    
    try testing.expect(std.mem.eql(u8, resolved_identity.primary_did.method, "shroud"));
    try testing.expect(resolved_identity.primary_did.chain == .ethereum);
    try testing.expect(resolved_identity.anchored_chains.count() >= 1);
    try testing.expect(resolved_identity.verifiable_credentials.items.len >= 1);
}

test "ChainConfig management" {
    const allocator = testing.allocator;
    
    var config = cross_chain.ChainConfig.init(allocator, "https://mainnet.infura.io/v3/", 1);
    defer config.deinit();
    
    // Add DID methods
    try config.addDIDMethod("ethr");
    try config.addDIDMethod("shroud");
    try config.addDIDMethod("custom");
    
    try testing.expect(config.supported_did_methods.items.len == 3);
    try testing.expect(std.mem.eql(u8, config.supported_did_methods.items[0], "ethr"));
    
    // Set contract address
    config.setContractAddress("0x1234567890123456789012345678901234567890");
    try testing.expect(config.contract_address != null);
    try testing.expect(std.mem.eql(u8, config.contract_address.?, "0x1234567890123456789012345678901234567890"));
}

test "CrossChainProof creation and verification" {
    const allocator = testing.allocator;
    
    const primary_did = cross_chain.DID{
        .method = "shroud",
        .chain = .ethereum,
        .identifier = "test_identity",
    };
    
    var identity = cross_chain.CrossChainIdentity.init(allocator, primary_did);
    defer identity.deinit();
    
    // Anchor to multiple chains
    try identity.anchorToChain(.polygon, "polygon_addr", "polygon_proof");
    try identity.anchorToChain(.solana, "solana_addr", "solana_proof");
    
    // Create ZK proof system
    var proof_system = zk_proof.ZkProofSystem.init(allocator);
    defer proof_system.deinit();
    
    // Create cross-chain proof
    var cross_chain_proof = try identity.createCrossChainProof(.polygon, &proof_system);
    defer cross_chain_proof.deinit();
    
    try testing.expect(cross_chain_proof.source_chain == .ethereum);
    try testing.expect(cross_chain_proof.target_chain == .polygon);
    
    // Verify proof
    const is_valid = try cross_chain_proof.verify(&proof_system);
    try testing.expect(is_valid);
}

test "ChainAnchor validation" {
    const allocator = testing.allocator;
    
    const anchor = cross_chain.ChainAnchor.init(allocator, .ethereum, "0xaddress", "proof_data");
    
    try testing.expect(anchor.isValid());
    try testing.expect(anchor.chain == .ethereum);
    try testing.expect(std.mem.eql(u8, anchor.address, "0xaddress"));
    try testing.expect(std.mem.eql(u8, anchor.proof, "proof_data"));
    
    // Test invalid anchor
    const invalid_anchor = cross_chain.ChainAnchor.init(allocator, .ethereum, "", "");
    try testing.expect(!invalid_anchor.isValid());
}

test "VerifiableCredential expiration" {
    const allocator = testing.allocator;
    
    const issuer_did = cross_chain.DID{
        .method = "shroud",
        .chain = .ethereum,
        .identifier = "issuer",
    };
    
    const subject_did = cross_chain.DID{
        .method = "shroud",
        .chain = .ethereum,
        .identifier = "subject",
    };
    
    // Create credential with immediate expiration
    var credential = cross_chain.VerifiableCredential.init(
        allocator,
        "expired_cred",
        issuer_did,
        subject_did,
        "TestCredential",
        0 // Expires immediately
    );
    defer credential.deinit();
    
    try testing.expect(credential.isExpired());
}