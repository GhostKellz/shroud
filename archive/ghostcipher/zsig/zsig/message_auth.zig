//! Universal Message Authentication & Integrity System
//! Core validation system for all GhostChain modules (ghostd, walletd, realid, CNS, ZVM)

const std = @import("std");
const backend = @import("backend.zig");
const key = @import("key.zig");
const sign = @import("sign.zig");

/// Signed message with timestamp and context
pub const SignedMessage = struct {
    message: []const u8,
    signature: [64]u8,
    timestamp: i64,
    context: []const u8,
    public_key: [32]u8,
    
    pub fn encode(self: SignedMessage, allocator: std.mem.Allocator) ![]u8 {
        // Create a JSON-like structure for the signed message
        return std.fmt.allocPrint(allocator,
            \\{{"message":"{s}","signature":"{s}","timestamp":{},"context":"{s}","public_key":"{s}"}}
        , .{
            std.base64.standard.Encoder.encode(allocator, self.message) catch return error.EncodingError,
            std.base64.standard.Encoder.encode(allocator, &self.signature) catch return error.EncodingError,
            self.timestamp,
            self.context,
            std.fmt.fmtSliceHexLower(&self.public_key),
        });
    }
    
    pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !SignedMessage {
        // TODO: Implement proper JSON parsing for signed message
        _ = allocator;
        _ = encoded;
        return error.NotImplemented;
    }
};

/// Universal Message Authentication System
pub const MessageAuth = struct {
    /// Create a cryptographic digest of a message with context
    pub fn createDigest(message: []const u8, context: []const u8) [32]u8 {
        var hasher = std.crypto.hash.Blake3.init(.{});
        
        // Add context for domain separation
        hasher.update("GHOSTCHAIN_MSG_AUTH_V1:");
        hasher.update(context);
        hasher.update(":");
        
        // Add the actual message
        hasher.update(message);
        
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return digest;
    }
    
    /// Validate a message against its digest with context
    pub fn validateMessage(message: []const u8, digest: [32]u8, context: []const u8) bool {
        const computed_digest = createDigest(message, context);
        return std.crypto.utils.timingSafeEql([32]u8, digest, computed_digest);
    }
    
    /// Create a cryptographically signed message with timestamp
    pub fn signedMessage(message: []const u8, keypair: key.Keypair, timestamp: i64, context: []const u8, allocator: std.mem.Allocator) !SignedMessage {
        // Create the signing payload with timestamp and context
        const signing_input = try std.fmt.allocPrint(allocator, "{}:{}:{s}", .{ timestamp, context, message });
        defer allocator.free(signing_input);
        
        // Sign the payload
        const signature = try keypair.sign(signing_input);
        
        // Store message content (caller owns the memory)
        const message_copy = try allocator.dupe(u8, message);
        const context_copy = try allocator.dupe(u8, context);
        
        return SignedMessage{
            .message = message_copy,
            .signature = signature,
            .timestamp = timestamp,
            .context = context_copy,
            .public_key = keypair.publicKey(),
        };
    }
    
    /// Verify a signed message and check timestamp validity
    pub fn verifyTimestamp(signed_msg: SignedMessage, max_age_seconds: i64) !bool {
        const current_time = std.time.timestamp();
        const age = current_time - signed_msg.timestamp;
        
        // Check if message is too old
        if (age > max_age_seconds) {
            return false;
        }
        
        // Check if message is from the future (clock skew tolerance of 60 seconds)
        if (age < -60) {
            return false;
        }
        
        return true;
    }
    
    /// Verify the cryptographic signature of a signed message
    pub fn verifySignature(signed_msg: SignedMessage, allocator: std.mem.Allocator) !bool {
        // Reconstruct the signing input
        const signing_input = try std.fmt.allocPrint(allocator, "{}:{}:{s}", .{ 
            signed_msg.timestamp, 
            signed_msg.context, 
            signed_msg.message 
        });
        defer allocator.free(signing_input);
        
        // Verify the signature
        return backend.verify(signing_input, signed_msg.signature, signed_msg.public_key, .ed25519);
    }
    
    /// Complete verification: signature + timestamp
    pub fn verifySignedMessage(signed_msg: SignedMessage, max_age_seconds: i64, allocator: std.mem.Allocator) !bool {
        // Check timestamp first (faster)
        if (!try verifyTimestamp(signed_msg, max_age_seconds)) {
            return false;
        }
        
        // Then verify signature
        return verifySignature(signed_msg, allocator);
    }
    
    /// Create a batch digest for multiple messages (for performance)
    pub fn batchDigest(messages: []const []const u8, context: []const u8, allocator: std.mem.Allocator) ![][32]u8 {
        const digests = try allocator.alloc([32]u8, messages.len);
        
        for (messages, 0..) |message, i| {
            digests[i] = createDigest(message, context);
        }
        
        return digests;
    }
    
    /// Verify multiple messages efficiently
    pub fn batchValidate(messages: []const []const u8, digests: []const [32]u8, context: []const u8) ![]bool {
        if (messages.len != digests.len) return error.LengthMismatch;
        
        var results = try std.heap.page_allocator.alloc(bool, messages.len);
        
        for (messages, digests, 0..) |message, digest, i| {
            results[i] = validateMessage(message, digest, context);
        }
        
        return results;
    }
};

// Context constants for different GhostChain modules
pub const Context = struct {
    pub const GHOSTD_CONSENSUS = "ghostd.consensus.v1";
    pub const GHOSTD_PEER_MSG = "ghostd.peer.message.v1";
    pub const WALLETD_TRANSACTION = "walletd.transaction.v1";
    pub const WALLETD_BALANCE = "walletd.balance.v1";
    pub const REALID_IDENTITY = "realid.identity.v1";
    pub const REALID_VERIFICATION = "realid.verification.v1";
    pub const CNS_DOMAIN = "cns.domain.v1";
    pub const CNS_RECORD = "cns.record.v1";
    pub const ZVM_BYTECODE = "zvm.bytecode.v1";
    pub const ZVM_STATE = "zvm.state.v1";
};

test "message digest creation and validation" {
    const testing = std.testing;
    
    const message = "Hello, GhostChain!";
    const context = Context.GHOSTD_PEER_MSG;
    
    // Create digest
    const digest = MessageAuth.createDigest(message, context);
    
    // Validate digest
    const is_valid = MessageAuth.validateMessage(message, digest, context);
    try testing.expect(is_valid);
    
    // Test with wrong context
    const wrong_context = Context.WALLETD_TRANSACTION;
    const is_invalid = MessageAuth.validateMessage(message, digest, wrong_context);
    try testing.expect(!is_invalid);
}

test "signed message creation and verification" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Generate keypair
    const keypair = try key.Keypair.generate(allocator);
    
    const message = "Transaction: Alice -> Bob, 100 GHT";
    const context = Context.WALLETD_TRANSACTION;
    const timestamp = std.time.timestamp();
    
    // Create signed message
    const signed_msg = try MessageAuth.signedMessage(message, keypair, timestamp, context, allocator);
    defer {
        allocator.free(signed_msg.message);
        allocator.free(signed_msg.context);
    }
    
    // Verify signature
    const sig_valid = try MessageAuth.verifySignature(signed_msg, allocator);
    try testing.expect(sig_valid);
    
    // Verify timestamp (should be valid for 1 hour)
    const time_valid = try MessageAuth.verifyTimestamp(signed_msg, 3600);
    try testing.expect(time_valid);
    
    // Complete verification
    const fully_valid = try MessageAuth.verifySignedMessage(signed_msg, 3600, allocator);
    try testing.expect(fully_valid);
}

test "batch digest operations" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const messages = [_][]const u8{
        "Message 1",
        "Message 2", 
        "Message 3"
    };
    
    const context = Context.CNS_RECORD;
    
    // Create batch digests
    const digests = try MessageAuth.batchDigest(&messages, context, allocator);
    defer allocator.free(digests);
    
    // Verify batch
    const results = try MessageAuth.batchValidate(&messages, digests, context);
    defer std.heap.page_allocator.free(results);
    
    // All should be valid
    for (results) |result| {
        try testing.expect(result);
    }
}
