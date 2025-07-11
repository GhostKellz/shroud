# Shroud Crypto API for ZQLite Integration

## Overview

This document outlines how to integrate Shroud's **GhostCipher** crypto modules into ZQLite (SQLite clone) for secure database encryption. The GhostCipher module provides a production-ready cryptographic framework with both native Zig APIs and C-compatible FFI interfaces.

## Architecture

```
ZQLite Database
├── Page Encryption (AES-256-GCM)
├── Key Derivation (Argon2id/HKDF)
├── Integrity Verification (HMAC-SHA256)
└── Secure Memory Management
```

## Core Crypto Module: GhostCipher

**Location**: `/ghostcipher/zcrypto/`  
**Version**: 0.4.0 (Production Ready)  
**Root Module**: `ghostcipher/zcrypto/root.zig`

## Quick Start Integration

### 1. C FFI Interface (Recommended for SQLite)

Include the FFI header:
```c
#include "ghostcipher/zcrypto/ffi.h"
```

#### Database Page Encryption
```c
// Encrypt a database page
CryptoResult encrypt_page(const uint8_t* page_data, uint32_t page_size,
                         const uint8_t* key, uint8_t* encrypted_output) {
    uint8_t nonce[12];
    zcrypto_generate_nonce(nonce, 12);
    
    return zcrypto_aes256_gcm_encrypt(
        key,           // 32-byte key
        nonce,         // 12-byte nonce
        NULL, 0,       // No additional authenticated data
        page_data, page_size,
        encrypted_output, page_size + 16 // +16 for auth tag
    );
}

// Decrypt a database page
CryptoResult decrypt_page(const uint8_t* encrypted_data, uint32_t encrypted_size,
                         const uint8_t* key, uint8_t* decrypted_output) {
    return zcrypto_aes256_gcm_decrypt(
        key,           // 32-byte key
        encrypted_data, // nonce is first 12 bytes
        NULL, 0,       // No additional authenticated data
        encrypted_data + 12, encrypted_size - 28, // Skip nonce, subtract nonce+tag
        decrypted_output, encrypted_size - 28
    );
}
```

#### Key Derivation from Password
```c
// Derive database key from user password
CryptoResult derive_database_key(const char* password, const uint8_t* salt,
                                uint8_t* key_output) {
    return zcrypto_argon2id(
        (const uint8_t*)password, strlen(password),
        salt, 16,        // 16-byte salt
        key_output, 32   // 32-byte key output
    );
}
```

#### Database Integrity Verification
```c
// Generate HMAC for database integrity
CryptoResult generate_db_hmac(const uint8_t* db_data, uint32_t db_size,
                             const uint8_t* key, uint8_t* hmac_output) {
    return zcrypto_hmac_sha256(db_data, db_size, key, 32, hmac_output);
}

// Verify database integrity
bool verify_db_integrity(const uint8_t* db_data, uint32_t db_size,
                        const uint8_t* key, const uint8_t* expected_hmac) {
    uint8_t computed_hmac[32];
    if (zcrypto_hmac_sha256(db_data, db_size, key, 32, computed_hmac) != CRYPTO_OK) {
        return false;
    }
    return zcrypto_secure_memcmp(computed_hmac, expected_hmac, 32) == 0;
}
```

### 2. Native Zig Interface (For Zig-based SQLite)

```zig
const zcrypto = @import("ghostcipher/zcrypto/root.zig");
const std = @import("std");

// Database encryption context
pub const DatabaseCrypto = struct {
    master_key: [32]u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, password: []const u8, salt: [16]u8) !DatabaseCrypto {
        var master_key: [32]u8 = undefined;
        _ = try zcrypto.kdf.argon2id(allocator, password, &salt, 32);
        
        return DatabaseCrypto{
            .master_key = master_key,
            .allocator = allocator,
        };
    }
    
    pub fn encryptPage(self: *DatabaseCrypto, page_data: []const u8) ![]u8 {
        return try zcrypto.sym.encryptAesGcm(self.allocator, page_data, &self.master_key);
    }
    
    pub fn decryptPage(self: *DatabaseCrypto, encrypted_data: []const u8) ![]u8 {
        return try zcrypto.sym.decryptAesGcm(self.allocator, encrypted_data, &self.master_key);
    }
    
    pub fn generateIntegrityHash(self: *DatabaseCrypto, data: []const u8) [32]u8 {
        return zcrypto.auth.hmac.sha256(data, &self.master_key);
    }
    
    pub fn deinit(self: *DatabaseCrypto) void {
        zcrypto.secureZero(&self.master_key);
    }
};
```

## Integration Patterns

### 1. Page-Level Encryption
```c
// SQLite page callback integration
static int crypto_page_cipher(void *pCtx, void *pData, Pgno pgno, int flags) {
    DatabaseCrypto *crypto = (DatabaseCrypto*)pCtx;
    
    if (flags & SQLITE_ENCRYPT) {
        return encrypt_page(pData, sqlite3_page_size(), crypto->key, pData);
    } else if (flags & SQLITE_DECRYPT) {
        return decrypt_page(pData, sqlite3_page_size(), crypto->key, pData);
    }
    
    return SQLITE_OK;
}
```

### 2. Key Management
```c
// Database key derivation and storage
typedef struct {
    uint8_t master_key[32];
    uint8_t salt[16];
    uint8_t integrity_key[32];
} DatabaseKeys;

int init_database_keys(DatabaseKeys *keys, const char *password) {
    // Generate random salt
    zcrypto_generate_salt(keys->salt, 16);
    
    // Derive master key from password
    if (derive_database_key(password, keys->salt, keys->master_key) != CRYPTO_OK) {
        return -1;
    }
    
    // Derive integrity key using HKDF
    if (zcrypto_hkdf_sha256(keys->master_key, 32, keys->salt, 16, 
                           "integrity", 9, keys->integrity_key, 32) != CRYPTO_OK) {
        return -1;
    }
    
    return 0;
}
```

### 3. Secure Memory Management
```c
// Clean up crypto context
void cleanup_crypto_context(DatabaseCrypto *crypto) {
    zcrypto_secure_zero(&crypto->master_key, sizeof(crypto->master_key));
    zcrypto_secure_zero(&crypto->integrity_key, sizeof(crypto->integrity_key));
}
```

## Available Crypto Primitives

### Symmetric Encryption
- **AES-128/256-GCM**: Authenticated encryption (recommended)
- **ChaCha20-Poly1305**: Alternative authenticated encryption
- **XSalsa20**: Stream cipher for large data

### Hash Functions
- **SHA-256/SHA-512**: Standard cryptographic hashing
- **BLAKE2b/BLAKE3**: High-performance alternatives
- **SHA-3**: NIST post-quantum standard

### Key Derivation
- **Argon2id**: Password-based key derivation (recommended)
- **PBKDF2**: Legacy password stretching
- **HKDF**: Key derivation from high-entropy sources

### Message Authentication
- **HMAC-SHA256**: Standard MAC (recommended)
- **HMAC-SHA512**: Higher security MAC
- **HMAC-BLAKE2s**: High-performance MAC

### Secure Random
- **OS Random**: System entropy source
- **Key Generation**: Cryptographically secure key generation
- **Nonce Generation**: Unique value generation

## Build Integration

### CMake Integration
```cmake
# Add ghostcipher to your build
add_subdirectory(ghostcipher)
target_link_libraries(zqlite PRIVATE ghostcipher)
target_include_directories(zqlite PRIVATE ghostcipher/zcrypto)
```

### Zig Build Integration
```zig
// In build.zig
const zcrypto = b.dependency("ghostcipher", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
```

## Security Considerations

### 1. Key Management
- Use Argon2id for password-based key derivation
- Store salts securely with encrypted database
- Implement proper key rotation mechanisms
- Use HKDF for deriving multiple keys from master key

### 2. Memory Security
- Always use `zcrypto_secure_zero()` to clear sensitive data
- Use `zcrypto_secure_memcmp()` for constant-time comparisons
- Implement secure memory allocation for keys when possible

### 3. Encryption Best Practices
- Use AES-256-GCM for authenticated encryption
- Generate unique nonces for each encryption operation
- Implement proper IV/nonce management
- Use additional authenticated data (AAD) for metadata

### 4. Integrity Protection
- Use HMAC-SHA256 for database integrity verification
- Implement per-page integrity checks
- Store integrity hashes securely

## Performance Optimization

### 1. Batch Operations
```c
// Encrypt multiple pages in batch
int encrypt_pages_batch(const uint8_t** pages, uint32_t page_count,
                       const uint8_t* key, uint8_t** encrypted_outputs) {
    // Use vectorized operations when available
    for (uint32_t i = 0; i < page_count; i++) {
        if (encrypt_page(pages[i], PAGE_SIZE, key, encrypted_outputs[i]) != CRYPTO_OK) {
            return -1;
        }
    }
    return 0;
}
```

### 2. Memory Pools
```c
// Use memory pools for crypto operations
typedef struct {
    uint8_t *buffer_pool;
    uint32_t buffer_size;
    uint32_t buffer_count;
} CryptoBufferPool;

CryptoBufferPool* init_crypto_pool(uint32_t buffer_size, uint32_t buffer_count);
uint8_t* get_crypto_buffer(CryptoBufferPool *pool);
void return_crypto_buffer(CryptoBufferPool *pool, uint8_t *buffer);
```

## Example: Complete ZQLite Integration

```c
#include "ghostcipher/zcrypto/ffi.h"
#include "sqlite3.h"

// ZQLite crypto extension
typedef struct {
    sqlite3 *db;
    uint8_t master_key[32];
    uint8_t integrity_key[32];
    uint8_t salt[16];
} ZQLiteCrypto;

// Initialize encrypted database
int zqlite_open_encrypted(const char *filename, const char *password, 
                         sqlite3 **ppDb) {
    ZQLiteCrypto *crypto = malloc(sizeof(ZQLiteCrypto));
    
    // Initialize crypto context
    if (init_database_keys(crypto, password) != 0) {
        free(crypto);
        return SQLITE_ERROR;
    }
    
    // Open database with encryption
    int rc = sqlite3_open(filename, ppDb);
    if (rc != SQLITE_OK) {
        cleanup_crypto_context(crypto);
        free(crypto);
        return rc;
    }
    
    // Set up page encryption
    sqlite3_set_authorizer(*ppDb, crypto_page_cipher, crypto);
    
    return SQLITE_OK;
}

// Cleanup
void zqlite_close_encrypted(sqlite3 *db) {
    ZQLiteCrypto *crypto = sqlite3_get_auxdata(db, 0);
    if (crypto) {
        cleanup_crypto_context(crypto);
        free(crypto);
    }
    sqlite3_close(db);
}
```

## Testing

### Unit Tests
```c
// Test encryption/decryption roundtrip
void test_page_encryption() {
    uint8_t key[32], page_data[4096], encrypted[4096 + 16], decrypted[4096];
    
    zcrypto_generate_key(key, 32);
    memset(page_data, 0xAA, sizeof(page_data));
    
    assert(encrypt_page(page_data, 4096, key, encrypted) == CRYPTO_OK);
    assert(decrypt_page(encrypted, 4096 + 16, key, decrypted) == CRYPTO_OK);
    assert(memcmp(page_data, decrypted, 4096) == 0);
}
```

### Integration Tests
```c
// Test full database encryption workflow
void test_database_encryption() {
    sqlite3 *db;
    assert(zqlite_open_encrypted("test.db", "password123", &db) == SQLITE_OK);
    
    // Test database operations
    assert(sqlite3_exec(db, "CREATE TABLE test (id INTEGER, data TEXT)", 
                       NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_exec(db, "INSERT INTO test VALUES (1, 'encrypted data')", 
                       NULL, NULL, NULL) == SQLITE_OK);
    
    zqlite_close_encrypted(db);
}
```

## Error Handling

All crypto operations return `CryptoResult` enum:
- `CRYPTO_OK`: Operation successful
- `CRYPTO_ERROR_INVALID_INPUT`: Invalid parameters
- `CRYPTO_ERROR_BUFFER_TOO_SMALL`: Output buffer insufficient
- `CRYPTO_ERROR_AUTHENTICATION_FAILED`: Decryption/verification failed
- `CRYPTO_ERROR_MEMORY_ALLOCATION`: Memory allocation failed

## Conclusion

The Shroud GhostCipher crypto module provides a comprehensive, production-ready cryptographic framework perfect for ZQLite database encryption. Its modular design, C-compatible FFI, and extensive crypto primitives make it ideal for secure SQLite database implementations.

Key benefits:
- **Production-ready**: Version 0.4.0 with full test coverage
- **High-performance**: Optimized implementations with hardware acceleration
- **Memory-safe**: Zig's memory safety with secure cleanup
- **Comprehensive**: Complete crypto suite for database encryption
- **Easy integration**: Both C FFI and native Zig APIs available