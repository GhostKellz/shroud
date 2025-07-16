# Shroud Integration Guide

## Overview

This guide provides practical examples for integrating Shroud into various crypto projects and blockchain applications. Shroud serves as a lightweight identity and privacy framework for zero-trust environments.

## Integration Patterns

### 1. DeFi Protocol Integration

#### Decentralized Exchange (DEX)

```zig
const std = @import("std");
const shroud = @import("shroud");

const DEXUser = struct {
    identity: shroud.identity.Identity,
    trading_permissions: []const shroud.guardian.Permission,
    kyc_proof: ?shroud.zk_proof.ZKProof,
};

pub fn authenticateTrader(user_did: []const u8, signature: [64]u8) !DEXUser {
    // Validate user identity
    const identity = shroud.identity.resolveIdentity(user_did);
    
    // Check trading permissions
    const trading_role = shroud.guardian.Role{
        .name = "trader",
        .permissions = &[_]shroud.guardian.Permission{ .read, .write },
    };
    
    // Issue trading token
    const trading_token = shroud.access_token.issueToken(
        identity,
        trading_role.permissions,
        86400 // 24 hours
    );
    
    return DEXUser{
        .identity = identity,
        .trading_permissions = trading_role.permissions,
        .kyc_proof = null, // Optional privacy-preserving KYC
    };
}

pub fn validateTrade(user: DEXUser, trade_amount: u64) bool {
    // Check if user has trading permissions
    if (!shroud.guardian.canAccess(user.trading_permissions, .write)) {
        return false;
    }
    
    // Validate KYC for large trades
    if (trade_amount > 10000 and user.kyc_proof == null) {
        return false;
    }
    
    return true;
}
```

#### Lending Protocol

```zig
const LendingPool = struct {
    admin_identity: shroud.identity.Identity,
    borrower_roles: std.HashMap([]const u8, shroud.guardian.Role),
    
    pub fn approveLoan(self: *LendingPool, borrower_did: []const u8, amount: u64) !void {
        // Create hierarchical trust for loan approval
        const loan_authority = shroud.hierarchical_trust.createAuthority("loan_officer");
        const borrower_identity = shroud.identity.resolveIdentity(borrower_did);
        
        // Delegate specific borrowing permissions
        const borrowing_role = shroud.guardian.Role{
            .name = "borrower",
            .permissions = &[_]shroud.guardian.Permission{ .read, .write },
        };
        
        // Issue loan token with expiration
        const loan_token = shroud.access_token.issueToken(
            borrower_identity,
            borrowing_role.permissions,
            2592000 // 30 days
        );
        
        // Store borrower role for future validation
        try self.borrower_roles.put(borrower_did, borrowing_role);
    }
};
```

### 2. NFT Marketplace Integration

```zig
const NFTMarketplace = struct {
    const CreatorRole = shroud.guardian.Role{
        .name = "creator",
        .permissions = &[_]shroud.guardian.Permission{ .read, .write, .execute },
    };
    
    const BuyerRole = shroud.guardian.Role{
        .name = "buyer",
        .permissions = &[_]shroud.guardian.Permission{ .read, .write },
    };
    
    pub fn mintNFT(creator_identity: shroud.identity.Identity, metadata: []const u8) ![]const u8 {
        // Validate creator permissions
        if (!shroud.guardian.canAccess(CreatorRole, .execute)) {
            return error.InsufficientPermissions;
        }
        
        // Generate provenance proof
        const provenance_proof = shroud.zk_proof.generateProof(metadata, "nft_creation_circuit");
        
        // Create NFT with embedded identity
        const nft_token = shroud.access_token.issueToken(
            creator_identity,
            CreatorRole.permissions,
            0 // No expiration for NFT ownership
        );
        
        return nft_token.signature;
    }
    
    pub fn transferNFT(from: shroud.identity.Identity, to: shroud.identity.Identity, nft_id: []const u8) !void {
        // Validate ownership through hierarchical trust
        const ownership_path = shroud.hierarchical_trust.validateTrustPath(from, to);
        
        if (!ownership_path.valid) {
            return error.InvalidTransfer;
        }
        
        // Update ownership in cross-chain compatible format
        _ = shroud.cross_chain.updateOwnership(nft_id, to);
    }
};
```

### 3. DAO Governance Integration

```zig
const DAO = struct {
    governance_token: []const u8,
    proposal_threshold: u64,
    
    const GovernanceRole = shroud.guardian.Role{
        .name = "governance",
        .permissions = &[_]shroud.guardian.Permission{ .read, .write, .admin },
    };
    
    pub fn createProposal(member_identity: shroud.identity.Identity, proposal: []const u8) ![]const u8 {
        // Validate governance token balance (simplified)
        const voting_power = getVotingPower(member_identity);
        
        if (voting_power < self.proposal_threshold) {
            return error.InsufficientVotingPower;
        }
        
        // Create proposal with zero-knowledge proof of eligibility
        const eligibility_proof = shroud.zk_proof.generateProof(
            voting_power,
            "governance_eligibility_circuit"
        );
        
        // Issue proposal token
        const proposal_token = shroud.access_token.issueToken(
            member_identity,
            GovernanceRole.permissions,
            604800 // 7 days voting period
        );
        
        return proposal_token.signature;
    }
    
    pub fn vote(voter_identity: shroud.identity.Identity, proposal_id: []const u8, vote: bool) !void {
        // Validate voting rights through hierarchical trust
        const voting_authority = shroud.hierarchical_trust.createAuthority("dao_member");
        const has_voting_rights = shroud.hierarchical_trust.validateAuthority(voter_identity, voting_authority);
        
        if (!has_voting_rights) {
            return error.NoVotingRights;
        }
        
        // Record vote with privacy preservation
        const vote_proof = shroud.zk_proof.generateProof(
            if (vote) "yes" else "no",
            "vote_privacy_circuit"
        );
        
        // Store vote commitment
        recordVote(proposal_id, vote_proof);
    }
};
```

### 4. Cross-Chain Bridge Integration

```zig
const CrossChainBridge = struct {
    supported_chains: []const shroud.cross_chain.ChainId,
    
    pub fn bridgeTokens(
        from_chain: shroud.cross_chain.ChainId,
        to_chain: shroud.cross_chain.ChainId,
        user_identity: shroud.identity.Identity,
        amount: u64
    ) !void {
        // Validate user identity across chains
        const from_identity = shroud.cross_chain.resolveIdentity(from_chain, user_identity);
        const to_identity = shroud.cross_chain.bridgeIdentity(from_identity, to_chain);
        
        // Create bridge authority
        const bridge_authority = shroud.hierarchical_trust.createAuthority("bridge_validator");
        
        // Validate bridge operation
        const bridge_token = shroud.access_token.issueToken(
            from_identity,
            &[_]shroud.guardian.Permission{ .read, .write, .execute },
            3600 // 1 hour for bridge completion
        );
        
        // Generate proof of legitimate bridge operation
        const bridge_proof = shroud.zk_proof.generateProof(
            amount,
            "bridge_validation_circuit"
        );
        
        // Execute cross-chain transfer
        try executeBridge(from_chain, to_chain, to_identity, amount, bridge_proof);
    }
};
```

### 5. Privacy-Preserving Analytics

```zig
const PrivacyAnalytics = struct {
    pub fn trackUserActivity(user_identity: shroud.identity.Identity, activity: []const u8) !void {
        // Generate zero-knowledge proof of activity without revealing details
        const activity_proof = shroud.zk_proof.generateProof(
            activity,
            "activity_privacy_circuit"
        );
        
        // Create anonymized tracking token
        const tracking_token = shroud.access_token.issueToken(
            user_identity,
            &[_]shroud.guardian.Permission{.read},
            86400 // 24 hours
        );
        
        // Store anonymized analytics
        storeAnalytics(activity_proof, tracking_token);
    }
    
    pub fn generateReport(admin_identity: shroud.identity.Identity) ![]const u8 {
        // Validate admin permissions
        const admin_role = shroud.guardian.Role{
            .name = "analytics_admin",
            .permissions = &[_]shroud.guardian.Permission{ .read, .admin },
        };
        
        if (!shroud.guardian.canAccess(admin_role, .admin)) {
            return error.InsufficientPermissions;
        }
        
        // Generate aggregated report without individual user data
        return generateAggregatedReport();
    }
};
```

### 6. Identity Wallet Integration

```zig
const IdentityWallet = struct {
    master_identity: shroud.identity.Identity,
    derived_identities: std.ArrayList(shroud.identity.Identity),
    
    pub fn createDerivedIdentity(self: *IdentityWallet, purpose: []const u8) !shroud.identity.Identity {
        // Create hierarchical identity derivation
        const derived_authority = shroud.hierarchical_trust.delegateAuthority(
            self.master_identity,
            purpose
        );
        
        // Generate new identity for specific purpose
        const derived_identity = shroud.identity.generateIdentity();
        
        // Create access token for derived identity
        const derived_token = shroud.access_token.issueToken(
            derived_identity,
            &[_]shroud.guardian.Permission{ .read, .write },
            0 // No expiration
        );
        
        try self.derived_identities.append(derived_identity);
        return derived_identity;
    }
    
    pub fn signWithDerivedIdentity(
        self: *IdentityWallet,
        identity_index: usize,
        data: []const u8
    ) ![64]u8 {
        if (identity_index >= self.derived_identities.items.len) {
            return error.InvalidIdentityIndex;
        }
        
        const derived_identity = self.derived_identities.items[identity_index];
        return shroud.identity.sign(derived_identity, data);
    }
};
```

## Integration Best Practices

### 1. Security Guidelines

- **Always validate tokens**: Check expiration and permissions before granting access
- **Use ephemeral keys**: Generate short-lived cryptographic material
- **Implement proper role hierarchy**: Follow principle of least privilege
- **Validate cross-chain operations**: Ensure identity consistency across chains

### 2. Performance Optimization

- **Cache identity resolutions**: Avoid repeated DID lookups
- **Batch token operations**: Group multiple token validations
- **Use WASM for browser integration**: Leverage WebAssembly for client-side operations
- **Implement token refresh**: Use refresh tokens for long-lived sessions

### 3. Privacy Considerations

- **Zero-knowledge proofs**: Use ZK proofs for sensitive operations
- **Minimal data exposure**: Only expose necessary identity information
- **Anonymized tracking**: Implement privacy-preserving analytics
- **Consent management**: Respect user privacy preferences

### 4. Testing Integration

```zig
test "DEX integration" {
    const testing = std.testing;
    
    // Test user authentication
    const user_identity = shroud.identity.generateIdentity();
    const signature = shroud.identity.sign(user_identity, "test_data");
    
    const user = try authenticateTrader(user_identity.did, signature);
    try testing.expect(user.identity.public_key.len == 32);
    
    // Test trade validation
    const can_trade = validateTrade(user, 1000);
    try testing.expect(can_trade);
}

test "NFT marketplace integration" {
    const testing = std.testing;
    
    const creator_identity = shroud.identity.generateIdentity();
    const nft_id = try NFTMarketplace.mintNFT(creator_identity, "test_metadata");
    
    try testing.expect(nft_id.len > 0);
}
```

## Common Integration Patterns

### 1. Middleware Pattern

```zig
pub fn shroudMiddleware(request: *Request, response: *Response, next: fn(*Request, *Response) void) !void {
    // Extract identity from request
    const auth_header = request.headers.get("Authorization");
    if (auth_header == null) {
        response.status = 401;
        return;
    }
    
    // Validate token
    const token = parseAuthToken(auth_header.?);
    if (!shroud.access_token.validateToken(token)) {
        response.status = 403;
        return;
    }
    
    // Attach identity to request context
    request.context.identity = token.identity;
    next(request, response);
}
```

### 2. Event-Driven Integration

```zig
const EventHandler = struct {
    pub fn handleIdentityCreated(identity: shroud.identity.Identity) !void {
        // Emit event for external systems
        emitEvent("identity.created", identity.did);
        
        // Create default permissions
        const default_role = shroud.guardian.Role{
            .name = "user",
            .permissions = &[_]shroud.guardian.Permission{.read},
        };
        
        // Store in external system
        try storeUserProfile(identity, default_role);
    }
    
    pub fn handleTokenExpired(token: shroud.access_token.AccessToken) !void {
        // Clean up expired tokens
        cleanupExpiredToken(token);
        
        // Notify user for renewal
        notifyTokenExpiration(token.identity);
    }
};
```

## Deployment Considerations

### 1. Environment Setup

```bash
# Build for production
zig build -Drelease-fast

# WASM target for browser integration
zig build -Dtarget=wasm32-freestanding

# Cross-compilation for different platforms
zig build -Dtarget=x86_64-linux-gnu
```

### 2. Configuration Management

```zig
const Config = struct {
    token_expiry_default: i64 = 3600,
    max_delegation_depth: u32 = 5,
    supported_chains: []const shroud.cross_chain.ChainId = &[_]shroud.cross_chain.ChainId{
        .ethereum,
        .polygon,
        .arbitrum,
    },
    zk_circuit_paths: []const []const u8 = &[_][]const u8{
        "circuits/kyc_verification.wasm",
        "circuits/governance_eligibility.wasm",
        "circuits/bridge_validation.wasm",
    },
};
```

This integration guide provides practical examples for incorporating Shroud into various crypto projects while maintaining security, privacy, and performance standards.