# GCC Library Integration Guide

> Complete guide for linking Shroud libraries with GCC-based projects (Rust, C, C++)

## Overview

This guide covers how to integrate Shroud's FFI libraries into projects using GCC toolchain, specifically targeting Rust crypto projects that need to avoid git dependencies and use pre-built static libraries.

## Library Architecture

### Core Libraries
- `libzcrypto.a` - Cryptographic operations (Ed25519, Blake3, etc.)
- `libzquic.a` - QUIC protocol implementation
- `libghostbridge.a` - gRPC-over-QUIC transport

### Dependencies
- `libc` - Standard C library
- `libpthread` - Threading support
- `libm` - Math library (for some crypto operations)

## Building Libraries

### 1. Build Static Libraries

```bash
# Build all FFI libraries
zig build ffi

# Output: zig-out/lib/
# - libzcrypto.a
# - libzquic.a  
# - libghostbridge.a
```

### 2. Extract Headers

```bash
# Generate C headers
zig build headers

# Output: zig-out/include/
# - zcrypto.h
# - zquic.h
# - ghostbridge.h
```

## Rust Integration with GCC

### 1. Project Structure

```
rust-crypto-project/
├── Cargo.toml
├── build.rs
├── deps/
│   ├── lib/
│   │   ├── libzcrypto.a
│   │   ├── libzquic.a
│   │   └── libghostbridge.a
│   └── include/
│       ├── zcrypto.h
│       ├── zquic.h
│       └── ghostbridge.h
└── src/
    └── main.rs
```

### 2. Cargo.toml

```toml
[package]
name = "crypto-project"
version = "0.1.0"
edition = "2021"

[dependencies]
libc = "0.2"

[build-dependencies]
cc = "1.0"
```

### 3. build.rs

```rust
use std::env;
use std::path::PathBuf;

fn main() {
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_dir = PathBuf::from(&project_dir).join("deps").join("lib");
    
    // Add library search path
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    
    // Link Shroud static libraries
    println!("cargo:rustc-link-lib=static=zcrypto");
    println!("cargo:rustc-link-lib=static=zquic");
    println!("cargo:rustc-link-lib=static=ghostbridge");
    
    // Link system libraries
    println!("cargo:rustc-link-lib=c");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=m");
    
    // For Linux systems
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dl");
    }
    
    // For macOS systems
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
    
    // For Windows systems
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=userenv");
    }
}
```

### 4. FFI Wrapper (src/shroud.rs)

```rust
use libc::{c_char, c_int, c_void, size_t};
use std::ffi::{CStr, CString};

// ZCrypto FFI
#[repr(C)]
pub struct ZCryptoKeypair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 64],
}

#[repr(C)]
pub struct ZCryptoSignature {
    pub bytes: [u8; 64],
}

extern "C" {
    // Crypto operations
    fn zcrypto_ed25519_generate_keypair() -> ZCryptoKeypair;
    fn zcrypto_ed25519_sign(
        message: *const u8,
        message_len: size_t,
        private_key: *const u8,
        signature: *mut ZCryptoSignature,
    ) -> c_int;
    fn zcrypto_ed25519_verify(
        signature: *const ZCryptoSignature,
        message: *const u8,
        message_len: size_t,
        public_key: *const u8,
    ) -> c_int;
    fn zcrypto_blake3_hash(
        input: *const u8,
        input_len: size_t,
        output: *mut u8,
    ) -> c_int;
}

// GhostBridge FFI
#[repr(C)]
pub struct GhostBridgeClient {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct GhostBridgeConfig {
    pub server_addr: *const c_char,
    pub server_port: u16,
    pub timeout_ms: u32,
}

extern "C" {
    fn ghostbridge_client_new(config: *const GhostBridgeConfig) -> *mut GhostBridgeClient;
    fn ghostbridge_client_free(client: *mut GhostBridgeClient);
    fn ghostbridge_client_connect(client: *mut GhostBridgeClient) -> c_int;
    fn ghostbridge_client_call(
        client: *mut GhostBridgeClient,
        method: *const c_char,
        request: *const u8,
        request_len: size_t,
        response: *mut *mut u8,
        response_len: *mut size_t,
    ) -> c_int;
    fn ghostbridge_free_response(response: *mut u8);
}

// Safe Rust wrappers
pub struct ShroudCrypto;

impl ShroudCrypto {
    pub fn generate_keypair() -> ZCryptoKeypair {
        unsafe { zcrypto_ed25519_generate_keypair() }
    }
    
    pub fn sign(message: &[u8], private_key: &[u8; 64]) -> Result<ZCryptoSignature, i32> {
        let mut signature = ZCryptoSignature { bytes: [0; 64] };
        
        let result = unsafe {
            zcrypto_ed25519_sign(
                message.as_ptr(),
                message.len(),
                private_key.as_ptr(),
                &mut signature,
            )
        };
        
        if result == 0 {
            Ok(signature)
        } else {
            Err(result)
        }
    }
    
    pub fn verify(signature: &ZCryptoSignature, message: &[u8], public_key: &[u8; 32]) -> bool {
        let result = unsafe {
            zcrypto_ed25519_verify(
                signature,
                message.as_ptr(),
                message.len(),
                public_key.as_ptr(),
            )
        };
        
        result == 1
    }
    
    pub fn blake3_hash(input: &[u8]) -> Result<[u8; 32], i32> {
        let mut output = [0u8; 32];
        
        let result = unsafe {
            zcrypto_blake3_hash(input.as_ptr(), input.len(), output.as_mut_ptr())
        };
        
        if result == 0 {
            Ok(output)
        } else {
            Err(result)
        }
    }
}

pub struct GhostBridge {
    client: *mut GhostBridgeClient,
}

impl GhostBridge {
    pub fn new(server_addr: &str, port: u16) -> Result<Self, i32> {
        let c_addr = CString::new(server_addr).unwrap();
        
        let config = GhostBridgeConfig {
            server_addr: c_addr.as_ptr(),
            server_port: port,
            timeout_ms: 10000,
        };
        
        let client = unsafe { ghostbridge_client_new(&config) };
        
        if client.is_null() {
            Err(-1)
        } else {
            Ok(GhostBridge { client })
        }
    }
    
    pub fn connect(&mut self) -> Result<(), i32> {
        let result = unsafe { ghostbridge_client_connect(self.client) };
        
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
    
    pub fn call(&mut self, method: &str, request: &[u8]) -> Result<Vec<u8>, i32> {
        let c_method = CString::new(method).unwrap();
        let mut response_ptr: *mut u8 = std::ptr::null_mut();
        let mut response_len: size_t = 0;
        
        let result = unsafe {
            ghostbridge_client_call(
                self.client,
                c_method.as_ptr(),
                request.as_ptr(),
                request.len(),
                &mut response_ptr,
                &mut response_len,
            )
        };
        
        if result == 0 {
            let response = unsafe {
                std::slice::from_raw_parts(response_ptr, response_len).to_vec()
            };
            
            unsafe { ghostbridge_free_response(response_ptr) };
            
            Ok(response)
        } else {
            Err(result)
        }
    }
}

impl Drop for GhostBridge {
    fn drop(&mut self) {
        unsafe {
            ghostbridge_client_free(self.client);
        }
    }
}
```

### 5. Usage Example

```rust
mod shroud;
use shroud::{ShroudCrypto, GhostBridge};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate cryptographic identity
    let keypair = ShroudCrypto::generate_keypair();
    println!("Generated keypair with public key: {:?}", keypair.public_key);
    
    // Sign a message
    let message = b"Hello, Shroud!";
    let signature = ShroudCrypto::sign(message, &keypair.private_key)?;
    println!("Message signed successfully");
    
    // Verify signature
    let is_valid = ShroudCrypto::verify(&signature, message, &keypair.public_key);
    println!("Signature verification: {}", is_valid);
    
    // Hash data
    let hash = ShroudCrypto::blake3_hash(message)?;
    println!("Blake3 hash: {:?}", hash);
    
    // Connect to GhostBridge service
    let mut bridge = GhostBridge::new("localhost", 50051)?;
    bridge.connect()?;
    println!("Connected to GhostBridge");
    
    // Make RPC call
    let request = b"{'method': 'get_balance', 'params': {}}";
    let response = bridge.call("/wallet/balance", request)?;
    println!("RPC response: {:?}", String::from_utf8_lossy(&response));
    
    Ok(())
}
```

## C/C++ Integration

### 1. CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.10)
project(crypto_project)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Find Shroud libraries
find_library(ZCRYPTO_LIB zcrypto PATHS ${CMAKE_SOURCE_DIR}/deps/lib)
find_library(ZQUIC_LIB zquic PATHS ${CMAKE_SOURCE_DIR}/deps/lib)
find_library(GHOSTBRIDGE_LIB ghostbridge PATHS ${CMAKE_SOURCE_DIR}/deps/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/deps/include)

# Create executable
add_executable(crypto_project main.c)

# Link libraries
target_link_libraries(crypto_project 
    ${ZCRYPTO_LIB}
    ${ZQUIC_LIB}
    ${GHOSTBRIDGE_LIB}
    pthread
    m
)

# Platform-specific libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(crypto_project dl)
endif()

if(APPLE)
    target_link_libraries(crypto_project "-framework Security")
    target_link_libraries(crypto_project "-framework CoreFoundation")
endif()

if(WIN32)
    target_link_libraries(crypto_project ws2_32 advapi32 userenv)
endif()
```

### 2. C Usage Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zcrypto.h"
#include "ghostbridge.h"

int main() {
    // Generate cryptographic identity
    ZCryptoKeypair keypair = zcrypto_ed25519_generate_keypair();
    printf("Generated keypair\n");
    
    // Sign a message
    const char* message = "Hello, Shroud!";
    ZCryptoSignature signature;
    
    int result = zcrypto_ed25519_sign(
        (const uint8_t*)message,
        strlen(message),
        keypair.private_key,
        &signature
    );
    
    if (result == 0) {
        printf("Message signed successfully\n");
    } else {
        printf("Signing failed: %d\n", result);
        return 1;
    }
    
    // Verify signature
    int is_valid = zcrypto_ed25519_verify(
        &signature,
        (const uint8_t*)message,
        strlen(message),
        keypair.public_key
    );
    
    printf("Signature verification: %s\n", is_valid ? "valid" : "invalid");
    
    // Hash data
    uint8_t hash[32];
    result = zcrypto_blake3_hash(
        (const uint8_t*)message,
        strlen(message),
        hash
    );
    
    if (result == 0) {
        printf("Blake3 hash computed successfully\n");
    }
    
    // Connect to GhostBridge service
    GhostBridgeConfig config = {
        .server_addr = "localhost",
        .server_port = 50051,
        .timeout_ms = 10000
    };
    
    GhostBridgeClient* client = ghostbridge_client_new(&config);
    if (!client) {
        printf("Failed to create GhostBridge client\n");
        return 1;
    }
    
    result = ghostbridge_client_connect(client);
    if (result == 0) {
        printf("Connected to GhostBridge\n");
        
        // Make RPC call
        const char* request = "{\"method\": \"get_balance\", \"params\": {}}";
        uint8_t* response;
        size_t response_len;
        
        result = ghostbridge_client_call(
            client,
            "/wallet/balance",
            (const uint8_t*)request,
            strlen(request),
            &response,
            &response_len
        );
        
        if (result == 0) {
            printf("RPC response: %.*s\n", (int)response_len, response);
            ghostbridge_free_response(response);
        }
    }
    
    ghostbridge_client_free(client);
    return 0;
}
```

## Library Distribution

### 1. Creating Distribution Package

```bash
#!/bin/bash
# create_dist.sh

VERSION="1.0.0"
DIST_DIR="shroud-libs-${VERSION}"

mkdir -p "${DIST_DIR}/lib"
mkdir -p "${DIST_DIR}/include"
mkdir -p "${DIST_DIR}/docs"

# Build libraries
zig build ffi
zig build headers

# Copy libraries
cp zig-out/lib/libzcrypto.a "${DIST_DIR}/lib/"
cp zig-out/lib/libzquic.a "${DIST_DIR}/lib/"
cp zig-out/lib/libghostbridge.a "${DIST_DIR}/lib/"

# Copy headers
cp zig-out/include/*.h "${DIST_DIR}/include/"

# Copy documentation
cp FFI_DOCS.md "${DIST_DIR}/docs/"
cp GCC-LIB.md "${DIST_DIR}/docs/"

# Create manifest
cat > "${DIST_DIR}/MANIFEST.json" << EOF
{
  "version": "${VERSION}",
  "libraries": [
    "lib/libzcrypto.a",
    "lib/libzquic.a", 
    "lib/libghostbridge.a"
  ],
  "headers": [
    "include/zcrypto.h",
    "include/zquic.h",
    "include/ghostbridge.h"
  ],
  "docs": [
    "docs/FFI_DOCS.md",
    "docs/GCC-LIB.md"
  ]
}
EOF

# Create tarball
tar -czf "${DIST_DIR}.tar.gz" "${DIST_DIR}"
echo "Created distribution: ${DIST_DIR}.tar.gz"
```

### 2. Installation Script

```bash
#!/bin/bash
# install.sh

set -e

INSTALL_DIR="${1:-/usr/local}"
LIB_DIR="${INSTALL_DIR}/lib"
INCLUDE_DIR="${INSTALL_DIR}/include"

echo "Installing Shroud libraries to ${INSTALL_DIR}"

# Create directories
mkdir -p "${LIB_DIR}"
mkdir -p "${INCLUDE_DIR}"

# Install libraries
cp lib/libzcrypto.a "${LIB_DIR}/"
cp lib/libzquic.a "${LIB_DIR}/"
cp lib/libghostbridge.a "${LIB_DIR}/"

# Install headers
cp include/*.h "${INCLUDE_DIR}/"

# Update library cache (Linux)
if command -v ldconfig > /dev/null; then
    ldconfig
fi

echo "Installation complete"
echo "Libraries installed to: ${LIB_DIR}"
echo "Headers installed to: ${INCLUDE_DIR}"
```

## Cross-Compilation

### 1. Building for Different Targets

```bash
# Linux x86_64
zig build ffi -Dtarget=x86_64-linux-gnu

# Linux ARM64
zig build ffi -Dtarget=aarch64-linux-gnu

# macOS x86_64
zig build ffi -Dtarget=x86_64-macos

# macOS ARM64 (Apple Silicon)
zig build ffi -Dtarget=aarch64-macos

# Windows x86_64
zig build ffi -Dtarget=x86_64-windows-gnu
```

### 2. Multi-Target Build Script

```bash
#!/bin/bash
# build_all_targets.sh

TARGETS=(
    "x86_64-linux-gnu"
    "aarch64-linux-gnu"
    "x86_64-macos"
    "aarch64-macos"
    "x86_64-windows-gnu"
)

for target in "${TARGETS[@]}"; do
    echo "Building for ${target}..."
    zig build ffi -Dtarget="${target}"
    
    # Create target-specific directory
    mkdir -p "dist/${target}"
    cp -r zig-out/lib "dist/${target}/"
    cp -r zig-out/include "dist/${target}/"
done

echo "All targets built successfully"
```

## Troubleshooting

### Common Linking Issues

1. **Undefined symbols**: Ensure all required system libraries are linked
2. **Architecture mismatch**: Verify target architecture matches your system
3. **Missing dependencies**: Check for required system libraries (pthread, m, etc.)

### Debug Build

```bash
# Build with debug symbols
zig build ffi -Doptimize=Debug

# Check symbols in library
nm -D libzcrypto.a | grep zcrypto_ed25519
```

### Library Verification

```bash
# Check library dependencies
ldd libzcrypto.so

# Verify symbols are exported
readelf -Ws libzcrypto.a | grep GLOBAL
```

## Integration Examples

Complete working examples are available in the repository:

- `examples/rust-wallet/` - Rust cryptocurrency wallet
- `examples/c-client/` - C client using GhostBridge
- `examples/cpp-crypto/` - C++ cryptographic operations

## Performance Notes

1. **Static linking**: Reduces runtime dependencies but increases binary size
2. **Symbol visibility**: Only required symbols are exported to minimize attack surface
3. **Thread safety**: All FFI functions are thread-safe but may require external synchronization for optimal performance

## License

Shroud libraries are provided under the MIT License. See LICENSE file for details.