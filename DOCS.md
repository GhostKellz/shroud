# Shroud Documentation

## Overview

Shroud is a lightweight identity and privacy framework designed for zero-trust environments. It serves as a trust validator, token issuer, and permission gate for blockchain and distributed systems.

**Core Purpose**: Shroud is not storage, not a runtime, not a ledger. It's a focused tool for identity management and access control.

## Architecture

### Core Components

- **Guardian**: Lightweight policy module for role-based access control (RBAC)
- **Identity**: Ephemeral key generation, signing, and delegation management
- **Access Tokens**: Token-bound permissions and validation
- **ZK Proofs**: Zero-knowledge proof integration for privacy-preserving attestations
- **Cross-Chain**: Multi-blockchain identity and trust validation
- **Hierarchical Trust**: Trust delegation trees and contract graphs
- **WASM Guardian**: WebAssembly-compatible validator runtime

### Module Structure

```
src/
   guardian.zig          # RBAC and permission management
   identity.zig          # Identity creation and management
   access_token.zig      # Token generation and validation
   zk_proof.zig         # Zero-knowledge proof utilities
   cross_chain.zig      # Cross-chain identity validation
   hierarchical_trust.zig # Trust delegation structures
   wasm_guardian.zig    # WASM-compatible validator
   main.zig             # Entry point and API
```

## API Reference

### Guardian Module

```zig
const Permission = enum {
    read,
    write,
    execute,
    admin,
};

const Role = struct {
    name: []const u8,
    permissions: []const Permission,
};

// Check if a role has a specific permission
pub fn canAccess(role: Role, permission: Permission) bool;

// Validate role inheritance
pub fn validateRole(parent: Role, child: Role) bool;
```

### Identity Module

```zig
const Identity = struct {
    public_key: [32]u8,
    private_key: [32]u8,
    did: []const u8,
};

// Generate ephemeral identity
pub fn generateIdentity() Identity;

// Sign data with identity
pub fn sign(identity: Identity, data: []const u8) [64]u8;

// Verify signature
pub fn verify(public_key: [32]u8, signature: [64]u8, data: []const u8) bool;
```

### Access Token Module

```zig
const AccessToken = struct {
    identity: []const u8,
    permissions: []const Permission,
    expires_at: i64,
    signature: [64]u8,
};

// Issue new access token
pub fn issueToken(identity: Identity, permissions: []const Permission, ttl: i64) AccessToken;

// Validate access token
pub fn validateToken(token: AccessToken) bool;

// Check if token has expired
pub fn isExpired(token: AccessToken) bool;
```

### ZK Proof Module

```zig
const ZKProof = struct {
    proof: []const u8,
    public_inputs: []const u8,
    verification_key: []const u8,
};

// Generate zero-knowledge proof
pub fn generateProof(witness: []const u8, circuit: []const u8) ZKProof;

// Verify zero-knowledge proof
pub fn verifyProof(proof: ZKProof) bool;
```

## Usage Examples

### Basic Identity Management

```zig
const std = @import("std");
const shroud = @import("shroud");

pub fn main() !void {
    // Generate new identity
    const identity = shroud.identity.generateIdentity();
    
    // Create role with permissions
    const admin_role = shroud.guardian.Role{
        .name = "admin",
        .permissions = &[_]shroud.guardian.Permission{ .read, .write, .admin },
    };
    
    // Issue access token
    const token = shroud.access_token.issueToken(
        identity,
        admin_role.permissions,
        3600 // 1 hour TTL
    );
    
    // Validate token
    if (shroud.access_token.validateToken(token)) {
        std.debug.print("Token is valid\n", .{});
    }
}
```

### Cross-Chain Identity Validation

```zig
const cross_chain = @import("shroud").cross_chain;

pub fn validateCrossChain() !void {
    const ethereum_identity = cross_chain.importIdentity(.ethereum, "0x...");
    const polygon_identity = cross_chain.bridgeIdentity(ethereum_identity, .polygon);
    
    const is_valid = cross_chain.validateIdentity(polygon_identity);
    if (is_valid) {
        std.debug.print("Cross-chain identity validated\n", .{});
    }
}
```

### Hierarchical Trust

```zig
const hierarchical = @import("shroud").hierarchical_trust;

pub fn setupTrustHierarchy() !void {
    const root_authority = hierarchical.createAuthority("root");
    const department_authority = hierarchical.delegateAuthority(root_authority, "engineering");
    const user_authority = hierarchical.delegateAuthority(department_authority, "developer");
    
    const trust_path = hierarchical.validateTrustPath(user_authority, root_authority);
    if (trust_path.valid) {
        std.debug.print("Trust path validated\n", .{});
    }
}
```

## Building and Testing

### Prerequisites

- Zig 0.11 or later
- Standard library dependencies

### Build

```bash
zig build
```

### Test

```bash
zig build test
```

### Run

```bash
zig run src/main.zig
```

## Integration Points

### Keystone Integration
- Plug into Keystone as identity/auth module
- Emit ZNS-compatible DIDs
- Runtime validation inside ZVM

### DID Compatibility
- W3C DID specification compliance
- ZNS (Zig Name Service) integration
- Cross-chain DID resolution

### WASM Support
- WebAssembly-compatible validator runtime
- Browser-friendly identity operations
- Crypto-agnostic design with pluggable signature providers

## Security Considerations

- **Zero-trust architecture**: Never trust, always verify
- **Ephemeral keys**: Short-lived cryptographic material
- **Token expiration**: Automatic token invalidation
- **Role-based access**: Principle of least privilege
- **Cross-chain validation**: Multi-blockchain identity verification

## Performance

- Lightweight design focused on core functionality
- Minimal memory footprint
- Fast cryptographic operations
- Efficient token validation

## Future Roadmap

- AccessContract abstraction
- Enhanced WASM runtime
- zkID compatibility mode
- Advanced delegation patterns
- Multi-signature support