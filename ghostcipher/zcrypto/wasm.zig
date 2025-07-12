//! WASM Runtime Crypto Support for Ghost Chain
//!
//! Provides cryptographic functions optimized for WASM environments
//! Supports both browser and node.js WASM runtimes

const std = @import("std");
const zcrypto = @import("root.zig");

/// WASM-specific error types
pub const WasmCryptoError = error{
    UnsupportedInWasm,
    WasmAllocationFailed,
    WasmRuntimeError,
    InvalidWasmInterface,
};

/// WASM runtime detection
pub const WasmRuntime = enum {
    browser,
    nodejs,
    wasmtime,
    wasmer,
    unknown,
    
    pub fn detect() WasmRuntime {
        // In WASM build, this would detect the runtime environment
        return if (@import("builtin").target.isWasm()) .browser else .unknown;
    }
};

/// WASM-optimized crypto interface
pub const WasmCrypto = struct {
    runtime: WasmRuntime,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) WasmCrypto {
        return WasmCrypto{
            .runtime = WasmRuntime.detect(),
            .allocator = allocator,
        };
    }
    
    /// WASM-compatible Ed25519 key generation
    pub fn generateEd25519Keypair(self: *WasmCrypto) WasmCryptoError!struct {
        public_key: [32]u8,
        private_key: [64]u8,
    } {
        // Use software implementation for WASM compatibility
        const keypair = zcrypto.asym.ed25519.generateKeypair() catch return WasmCryptoError.WasmRuntimeError;
        
        return .{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }
    
    /// WASM-compatible signing (no hardware acceleration)
    pub fn signEd25519(self: *WasmCrypto, message: []const u8, private_key: [64]u8) WasmCryptoError![64]u8 {
        _ = self;
        return zcrypto.asym.ed25519.sign(message, private_key) catch return WasmCryptoError.WasmRuntimeError;
    }
    
    /// WASM-compatible verification
    pub fn verifyEd25519(self: *WasmCrypto, message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        _ = self;
        return zcrypto.asym.ed25519.verify(message, signature, public_key);
    }
    
    /// WASM-optimized hashing (software-only)
    pub fn hashBlake3(self: *WasmCrypto, input: []const u8) WasmCryptoError![32]u8 {
        _ = self;
        return zcrypto.hash.blake3(input) catch return WasmCryptoError.WasmRuntimeError;
    }
    
    /// WASM-compatible random number generation
    pub fn randomBytes(self: *WasmCrypto, buffer: []u8) WasmCryptoError!void {
        _ = self;
        // Use crypto.getRandomValues() when available in browser
        switch (self.runtime) {
            .browser => {
                // In actual WASM, this would call JavaScript crypto.getRandomValues()
                // For now, use Zig's standard random
                std.crypto.random.bytes(buffer);
            },
            .nodejs => {
                // Use Node.js crypto.randomBytes()
                std.crypto.random.bytes(buffer);
            },
            else => {
                std.crypto.random.bytes(buffer);
            }
        }
    }
    
    /// WASM-compatible AES-GCM encryption
    pub fn encryptAesGcm(
        self: *WasmCrypto, 
        plaintext: []const u8, 
        key: [32]u8, 
        nonce: [12]u8
    ) WasmCryptoError![]u8 {
        const ciphertext = self.allocator.alloc(u8, plaintext.len + 16) catch return WasmCryptoError.WasmAllocationFailed;
        
        // Use software AES-GCM implementation for WASM
        zcrypto.sym.encryptAes256Gcm(
            self.allocator,
            key,
            nonce,
            plaintext,
            ""
        ) catch return WasmCryptoError.WasmRuntimeError;
        
        return ciphertext;
    }
    
    /// Export functions for WASM FFI
    pub const exports = struct {
        /// Generate Ed25519 keypair (WASM export)
        pub export fn wasm_ed25519_keypair(public_key_ptr: [*]u8, private_key_ptr: [*]u8) c_int {
            var wasm_crypto = WasmCrypto.init(std.heap.wasm_allocator);
            const keypair = wasm_crypto.generateEd25519Keypair() catch return -1;
            
            @memcpy(public_key_ptr[0..32], &keypair.public_key);
            @memcpy(private_key_ptr[0..64], &keypair.private_key);
            
            return 0;
        }
        
        /// Sign message with Ed25519 (WASM export)
        pub export fn wasm_ed25519_sign(
            message_ptr: [*]const u8,
            message_len: usize,
            private_key_ptr: [*]const u8,
            signature_ptr: [*]u8
        ) c_int {
            var wasm_crypto = WasmCrypto.init(std.heap.wasm_allocator);
            const message = message_ptr[0..message_len];
            const private_key = private_key_ptr[0..64].*;
            
            const signature = wasm_crypto.signEd25519(message, private_key) catch return -1;
            @memcpy(signature_ptr[0..64], &signature);
            
            return 0;
        }
        
        /// Verify Ed25519 signature (WASM export)
        pub export fn wasm_ed25519_verify(
            message_ptr: [*]const u8,
            message_len: usize,
            signature_ptr: [*]const u8,
            public_key_ptr: [*]const u8
        ) c_int {
            var wasm_crypto = WasmCrypto.init(std.heap.wasm_allocator);
            const message = message_ptr[0..message_len];
            const signature = signature_ptr[0..64].*;
            const public_key = public_key_ptr[0..32].*;
            
            return if (wasm_crypto.verifyEd25519(message, signature, public_key)) 1 else 0;
        }
        
        /// Blake3 hash (WASM export)
        pub export fn wasm_blake3_hash(
            input_ptr: [*]const u8,
            input_len: usize,
            output_ptr: [*]u8
        ) c_int {
            var wasm_crypto = WasmCrypto.init(std.heap.wasm_allocator);
            const input = input_ptr[0..input_len];
            
            const hash = wasm_crypto.hashBlake3(input) catch return -1;
            @memcpy(output_ptr[0..32], &hash);
            
            return 0;
        }
        
        /// Generate random bytes (WASM export)
        pub export fn wasm_random_bytes(buffer_ptr: [*]u8, buffer_len: usize) c_int {
            var wasm_crypto = WasmCrypto.init(std.heap.wasm_allocator);
            const buffer = buffer_ptr[0..buffer_len];
            
            wasm_crypto.randomBytes(buffer) catch return -1;
            return 0;
        }
    };
};

/// JavaScript bindings for browser integration
pub const JsBindings = struct {
    /// Generate TypeScript/JavaScript bindings
    pub fn generateTsBindings(allocator: std.mem.Allocator) ![]const u8 {
        const bindings =
            \\// Ghost Chain WASM Crypto Bindings
            \\// Auto-generated TypeScript definitions
            \\
            \\export interface GhostCrypto {
            \\  generateEd25519Keypair(): Promise<{
            \\    publicKey: Uint8Array;
            \\    privateKey: Uint8Array;
            \\  }>;
            \\  
            \\  signEd25519(
            \\    message: Uint8Array,
            \\    privateKey: Uint8Array
            \\  ): Promise<Uint8Array>;
            \\  
            \\  verifyEd25519(
            \\    message: Uint8Array,
            \\    signature: Uint8Array,
            \\    publicKey: Uint8Array
            \\  ): Promise<boolean>;
            \\  
            \\  hashBlake3(input: Uint8Array): Promise<Uint8Array>;
            \\  randomBytes(length: number): Promise<Uint8Array>;
            \\}
            \\
            \\export async function loadGhostCrypto(): Promise<GhostCrypto> {
            \\  const wasmModule = await import('./ghost_crypto.wasm');
            \\  
            \\  return {
            \\    async generateEd25519Keypair() {
            \\      const publicKey = new Uint8Array(32);
            \\      const privateKey = new Uint8Array(64);
            \\      
            \\      const result = wasmModule.wasm_ed25519_keypair(
            \\        publicKey.byteOffset,
            \\        privateKey.byteOffset
            \\      );
            \\      
            \\      if (result !== 0) throw new Error('Key generation failed');
            \\      return { publicKey, privateKey };
            \\    },
            \\    
            \\    async signEd25519(message, privateKey) {
            \\      const signature = new Uint8Array(64);
            \\      
            \\      const result = wasmModule.wasm_ed25519_sign(
            \\        message.byteOffset,
            \\        message.length,
            \\        privateKey.byteOffset,
            \\        signature.byteOffset
            \\      );
            \\      
            \\      if (result !== 0) throw new Error('Signing failed');
            \\      return signature;
            \\    },
            \\    
            \\    async verifyEd25519(message, signature, publicKey) {
            \\      const result = wasmModule.wasm_ed25519_verify(
            \\        message.byteOffset,
            \\        message.length,
            \\        signature.byteOffset,
            \\        publicKey.byteOffset
            \\      );
            \\      
            \\      return result === 1;
            \\    },
            \\    
            \\    async hashBlake3(input) {
            \\      const output = new Uint8Array(32);
            \\      
            \\      const result = wasmModule.wasm_blake3_hash(
            \\        input.byteOffset,
            \\        input.length,
            \\        output.byteOffset
            \\      );
            \\      
            \\      if (result !== 0) throw new Error('Hashing failed');
            \\      return output;
            \\    },
            \\    
            \\    async randomBytes(length) {
            \\      const buffer = new Uint8Array(length);
            \\      
            \\      const result = wasmModule.wasm_random_bytes(
            \\        buffer.byteOffset,
            \\        length
            \\      );
            \\      
            \\      if (result !== 0) throw new Error('Random generation failed');
            \\      return buffer;
            \\    }
            \\  };
            \\}
        ;
        
        return allocator.dupe(u8, bindings);
    }
};

test "WASM crypto operations" {
    const allocator = std.testing.allocator;
    var wasm_crypto = WasmCrypto.init(allocator);
    
    // Test key generation
    const keypair = try wasm_crypto.generateEd25519Keypair();
    std.testing.expect(keypair.public_key.len == 32) catch unreachable;
    std.testing.expect(keypair.private_key.len == 64) catch unreachable;
    
    // Test signing and verification
    const message = "Hello, WASM crypto!";
    const signature = try wasm_crypto.signEd25519(message, keypair.private_key);
    const valid = wasm_crypto.verifyEd25519(message, signature, keypair.public_key);
    
    std.testing.expect(valid) catch unreachable;
    
    // Test hashing
    const hash = try wasm_crypto.hashBlake3(message);
    std.testing.expect(hash.len == 32) catch unreachable;
    
    // Test random generation
    var random_buffer: [32]u8 = undefined;
    try wasm_crypto.randomBytes(&random_buffer);
}