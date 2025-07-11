# Shroud FFI Documentation

> Foreign Function Interface guide for integrating Shroud into Rust and Zig crypto projects

## Overview

Shroud provides C-compatible FFI libraries for seamless integration with Rust projects through GhostBridge. This document covers the FFI interface, build process, and integration patterns.

## Available FFI Libraries

### 1. **libzcrypto** - Cryptographic Operations
- Ed25519 key generation, signing, and verification
- Secp256k1 operations
- Blake3 hashing
- X25519 key exchange
- Post-quantum crypto (ML-KEM, ML-DSA) - *in development*

### 2. **libzquic** - QUIC Network Transport
- QUIC server and client implementation
- Stream management
- Connection handling
- Certificate configuration

### 3. **libghostbridge** - gRPC-over-QUIC Transport
- High-performance RPC communication
- Unary and streaming RPC support
- Built on QUIC for enhanced security and performance

## Building FFI Libraries

### Prerequisites
- Zig 0.13.0 or later
- C compiler (for linking)

### Build Commands

```bash
# Build all FFI libraries (shared and static)
zig build ffi

# Output location: zig-out/lib/
# - libzquic.so / libzquic.a
# - libzcrypto.so / libzcrypto.a
# - libghostbridge.so / libghostbridge.a
```

## Rust Integration

### 1. Project Structure

```
your-rust-project/
├── Cargo.toml
├── build.rs
├── lib/              # Pre-built Shroud libraries
│   ├── libghostbridge.a
│   ├── libzcrypto.a
│   └── libzquic.a
├── include/          # C headers
│   ├── ghostbridge.h
│   ├── zcrypto.h
│   └── zquic.h
└── src/
    ├── main.rs
    └── ffi/
        ├── mod.rs
        ├── ghostbridge.rs
        ├── zcrypto.rs
        └── zquic.rs
```

### 2. Cargo.toml Configuration

```toml
[package]
name = "your-crypto-project"
version = "0.1.0"
edition = "2021"

[dependencies]
libc = "0.2"

[build-dependencies]
cc = "1.0"
```

### 3. build.rs

```rust
fn main() {
    // Link pre-built Shroud libraries
    println!("cargo:rustc-link-search=native=lib");
    println!("cargo:rustc-link-lib=static=ghostbridge");
    println!("cargo:rustc-link-lib=static=zcrypto");
    println!("cargo:rustc-link-lib=static=zquic");
    
    // Link system libraries
    println!("cargo:rustc-link-lib=c");
    println!("cargo:rustc-link-lib=pthread");
}
```

### 4. FFI Bindings (src/ffi/zcrypto.rs)

```rust
use libc::{c_char, c_int, c_void, size_t};

#[repr(C)]
pub struct ZCryptoKeyPair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 64],
}

#[repr(C)]
pub struct ZCryptoSignature {
    pub bytes: [u8; 64],
}

extern "C" {
    // Key generation
    pub fn zcrypto_ed25519_generate(out_keypair: *mut ZCryptoKeyPair) -> c_int;
    pub fn zcrypto_ed25519_from_seed(
        seed: *const u8,
        seed_len: size_t,
        out_keypair: *mut ZCryptoKeyPair
    ) -> c_int;
    
    // Signing
    pub fn zcrypto_ed25519_sign(
        message: *const u8,
        message_len: size_t,
        private_key: *const u8,
        out_signature: *mut ZCryptoSignature
    ) -> c_int;
    
    // Verification
    pub fn zcrypto_ed25519_verify(
        signature: *const ZCryptoSignature,
        message: *const u8,
        message_len: size_t,
        public_key: *const u8
    ) -> c_int;
    
    // Hashing
    pub fn zcrypto_blake3_hash(
        data: *const u8,
        data_len: size_t,
        out_hash: *mut u8
    ) -> c_int;
}

// Safe Rust wrapper
pub struct ZCrypto;

impl ZCrypto {
    pub fn generate_ed25519_keypair() -> Result<ZCryptoKeyPair, i32> {
        let mut keypair = ZCryptoKeyPair {
            public_key: [0; 32],
            private_key: [0; 64],
        };
        
        let result = unsafe { zcrypto_ed25519_generate(&mut keypair) };
        
        if result == 0 {
            Ok(keypair)
        } else {
            Err(result)
        }
    }
    
    pub fn sign_ed25519(message: &[u8], private_key: &[u8; 64]) -> Result<ZCryptoSignature, i32> {
        let mut signature = ZCryptoSignature { bytes: [0; 64] };
        
        let result = unsafe {
            zcrypto_ed25519_sign(
                message.as_ptr(),
                message.len(),
                private_key.as_ptr(),
                &mut signature
            )
        };
        
        if result == 0 {
            Ok(signature)
        } else {
            Err(result)
        }
    }
    
    pub fn verify_ed25519(
        signature: &ZCryptoSignature,
        message: &[u8],
        public_key: &[u8; 32]
    ) -> bool {
        let result = unsafe {
            zcrypto_ed25519_verify(
                signature,
                message.as_ptr(),
                message.len(),
                public_key.as_ptr()
            )
        };
        
        result == 1
    }
}
```

### 5. GhostBridge FFI Bindings (src/ffi/ghostbridge.rs)

```rust
use libc::{c_char, c_int, c_void, size_t};
use std::ffi::{CStr, CString};

#[repr(C)]
pub struct GhostBridgeConfig {
    pub server_addr: *const c_char,
    pub server_port: u16,
    pub max_streams: u32,
    pub idle_timeout_ms: u32,
}

#[repr(C)]
pub struct GhostBridgeClient {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct GrpcRequest {
    pub method: *const c_char,
    pub payload: *const u8,
    pub payload_len: size_t,
}

#[repr(C)]
pub struct GrpcResponse {
    pub status_code: c_int,
    pub payload: *mut u8,
    pub payload_len: size_t,
}

extern "C" {
    // Client lifecycle
    pub fn ghostbridge_client_create(config: *const GhostBridgeConfig) -> *mut GhostBridgeClient;
    pub fn ghostbridge_client_destroy(client: *mut GhostBridgeClient);
    
    // RPC operations
    pub fn ghostbridge_unary_call(
        client: *mut GhostBridgeClient,
        request: *const GrpcRequest,
        response: *mut GrpcResponse
    ) -> c_int;
    
    // Connection management
    pub fn ghostbridge_connect(client: *mut GhostBridgeClient) -> c_int;
    pub fn ghostbridge_disconnect(client: *mut GhostBridgeClient) -> c_int;
    pub fn ghostbridge_is_connected(client: *const GhostBridgeClient) -> c_int;
}

// Safe Rust wrapper
pub struct GhostBridge {
    client: *mut GhostBridgeClient,
}

impl GhostBridge {
    pub fn new(server_addr: &str, port: u16) -> Result<Self, i32> {
        let c_addr = CString::new(server_addr).unwrap();
        
        let config = GhostBridgeConfig {
            server_addr: c_addr.as_ptr(),
            server_port: port,
            max_streams: 100,
            idle_timeout_ms: 30000,
        };
        
        let client = unsafe { ghostbridge_client_create(&config) };
        
        if client.is_null() {
            Err(-1)
        } else {
            Ok(GhostBridge { client })
        }
    }
    
    pub fn connect(&mut self) -> Result<(), i32> {
        let result = unsafe { ghostbridge_connect(self.client) };
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
    
    pub fn call(&mut self, method: &str, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let c_method = CString::new(method).unwrap();
        
        let request = GrpcRequest {
            method: c_method.as_ptr(),
            payload: payload.as_ptr(),
            payload_len: payload.len(),
        };
        
        let mut response = GrpcResponse {
            status_code: 0,
            payload: std::ptr::null_mut(),
            payload_len: 0,
        };
        
        let result = unsafe { ghostbridge_unary_call(self.client, &request, &mut response) };
        
        if result == 0 && response.status_code == 0 {
            let data = unsafe {
                std::slice::from_raw_parts(response.payload, response.payload_len).to_vec()
            };
            
            // Free response payload
            unsafe { libc::free(response.payload as *mut c_void) };
            
            Ok(data)
        } else {
            Err(result)
        }
    }
}

impl Drop for GhostBridge {
    fn drop(&mut self) {
        unsafe {
            ghostbridge_client_destroy(self.client);
        }
    }
}
```

### 6. Usage Example

```rust
use crate::ffi::{zcrypto::ZCrypto, ghostbridge::GhostBridge};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate identity
    let keypair = ZCrypto::generate_ed25519_keypair()?;
    println!("Generated identity with public key: {:?}", keypair.public_key);
    
    // Sign a message
    let message = b"Hello, Shroud!";
    let signature = ZCrypto::sign_ed25519(message, &keypair.private_key)?;
    
    // Verify signature
    let is_valid = ZCrypto::verify_ed25519(&signature, message, &keypair.public_key);
    println!("Signature valid: {}", is_valid);
    
    // Connect to GhostBridge service
    let mut bridge = GhostBridge::new("localhost", 50051)?;
    bridge.connect()?;
    
    // Make RPC call
    let request_data = b"{'action': 'get_balance'}";
    let response = bridge.call("/wallet/balance", request_data)?;
    println!("Response: {:?}", String::from_utf8_lossy(&response));
    
    Ok(())
}
```

## Zig Integration

### Direct Module Import

```zig
const std = @import("std");
const shroud = @import("shroud");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Use Shroud directly
    const identity = try shroud.sigil.realid_generate_from_passphrase("secure_passphrase");
    const signature = try shroud.sigil.realid_sign("Hello!", identity.private_key);
    
    std.debug.print("Signature: {}\n", .{std.fmt.fmtSliceHexLower(&signature.bytes)});
}
```

### Using zig fetch

```bash
# Add Shroud as a dependency
zig fetch --save https://github.com/yourusername/shroud/archive/refs/tags/v1.0.0.tar.gz
```

Then in `build.zig.zon`:

```zig
.{
    .dependencies = .{
        .shroud = .{
            .url = "https://github.com/yourusername/shroud/archive/refs/tags/v1.0.0.tar.gz",
            .hash = "...",
        },
    },
}
```

## Error Codes

### ZCrypto Error Codes
- `0`: Success
- `-1`: Invalid parameter
- `-2`: Crypto operation failed
- `-3`: Unsupported algorithm
- `-4`: Out of memory

### GhostBridge Error Codes
- `0`: Success
- `-1`: Connection failed
- `-2`: Invalid configuration
- `-3`: RPC failed
- `-4`: Timeout
- `-5`: Stream error

### ZQUIC Error Codes
- `0`: Success
- `-1`: Network error
- `-2`: Protocol error
- `-3`: Certificate error
- `-4`: Connection closed

## Thread Safety

All FFI functions are thread-safe with the following considerations:

1. **ZCrypto**: All functions are stateless and thread-safe
2. **GhostBridge**: Client instances are NOT thread-safe; use one client per thread or add synchronization
3. **ZQUIC**: Connection objects require external synchronization for concurrent access

## Memory Management

### Ownership Rules

1. **Input parameters**: Caller retains ownership
2. **Output parameters**: Caller owns allocated memory
3. **Return values**: Check documentation for each function

### Cleanup Functions

```c
// Free allocated response data
void ghostbridge_free_response(GrpcResponse* response);

// Free allocated strings
void shroud_free_string(char* str);
```

## Performance Considerations

1. **Batch Operations**: Use batch APIs when available to reduce FFI overhead
2. **Buffer Reuse**: Reuse buffers for repeated operations
3. **Connection Pooling**: Maintain persistent connections for GhostBridge
4. **Async Operations**: Use async variants for I/O-bound operations

## Migration Guide

### From OpenSSL to ZCrypto

```rust
// Before (OpenSSL)
use openssl::sign::{Signer, Verifier};
use openssl::pkey::{PKey, Private};
use openssl::hash::MessageDigest;

// After (ZCrypto)
use crate::ffi::zcrypto::ZCrypto;

// Signing
let signature = ZCrypto::sign_ed25519(message, &private_key)?;

// Verification
let is_valid = ZCrypto::verify_ed25519(&signature, message, &public_key);
```

### From gRPC to GhostBridge

```rust
// Before (tonic/gRPC)
let mut client = WalletClient::connect("http://localhost:50051").await?;
let response = client.get_balance(request).await?;

// After (GhostBridge)
let mut bridge = GhostBridge::new("localhost", 50051)?;
bridge.connect()?;
let response = bridge.call("/wallet/balance", &request_bytes)?;
```

## Troubleshooting

### Common Issues

1. **Undefined symbols**: Ensure all required libraries are linked
2. **Version mismatch**: Verify Zig version compatibility
3. **Memory leaks**: Always free allocated memory using provided cleanup functions
4. **Connection failures**: Check firewall settings and server availability

### Debug Build

```bash
# Build with debug symbols
zig build ffi -Doptimize=Debug

# Enable verbose FFI logging
export SHROUD_FFI_DEBUG=1
```

## Examples

Full working examples are available in the `examples/ffi/` directory:

- `rust-basic/` - Basic Rust integration
- `rust-wallet/` - Cryptocurrency wallet using Shroud
- `rust-bridge/` - GhostBridge RPC client
- `zig-direct/` - Direct Zig integration

## Support

For issues and questions:
- GitHub Issues: [shroud/issues](https://github.com/yourusername/shroud/issues)
- Documentation: [shroud-docs.io](https://shroud-docs.io)
- Discord: [Join our server](https://discord.gg/shroud)
