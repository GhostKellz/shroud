//! IPv6 QID (QUIC Identity) System
//! Stateless IPv6 addresses derived from public keys for privacy-preserving networking

const std = @import("std");

/// IPv6 QID - Cryptographically derived IPv6 address for identity
pub const QID = struct {
    bytes: [16]u8,

    /// Generate QID from a public key (Ed25519 32-byte key)
    pub fn fromPublicKey(pubkey: []const u8) QID {
        std.debug.assert(pubkey.len >= 32);

        // IPv6 prefix for SHROUD QIDs (RFC 4193 Unique Local IPv6 Unicast Addresses)
        const SHROUD_IPV6_PREFIX = [_]u8{ 0xfd, 0x00 }; // fd00::/8 prefix

        // Hash the public key with SHROUD-specific salt using SHA-256
        const salt_prefix = "SHROUD-QID-v1";
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(salt_prefix);
        hasher.update(pubkey[0..32]);
        const hash = hasher.finalResult();

        // Create IPv6 address from hash
        var qid_bytes: [16]u8 = undefined;

        // Set the ULA prefix (fd00::/8)
        qid_bytes[0] = SHROUD_IPV6_PREFIX[0];
        qid_bytes[1] = SHROUD_IPV6_PREFIX[1];

        // Use first 14 bytes of hash for the rest of the address
        @memcpy(qid_bytes[2..16], hash[0..14]);

        return QID{ .bytes = qid_bytes };
    }

    /// Generate QID from DID document (extracts public key)
    pub fn fromDIDDocument(did_doc: anytype) !QID {
        // For now, assume DID document has a publicKey field
        // This will be refined when we have proper DID structure
        if (@hasField(@TypeOf(did_doc), "publicKey")) {
            return fromPublicKey(did_doc.publicKey);
        }
        return error.InvalidDIDDocument;
    }

    /// Convert QID to string representation (IPv6 format)
    pub fn toString(self: QID, buffer: []u8) ![]u8 {
        if (buffer.len < 39) { // IPv6 addresses can be up to 39 characters
            return error.BufferTooSmall;
        }

        const bytes = self.bytes;
        return std.fmt.bufPrint(buffer, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        });
    }

    /// Parse QID from string representation
    pub fn fromString(qid_str: []const u8) !QID {
        if (qid_str.len < 15) { // Minimum IPv6 length
            return error.InvalidFormat;
        }

        var qid = QID{ .bytes = undefined };

        // Simple parsing - split by colons and parse hex
        var parts = std.mem.splitScalar(u8, qid_str, ':');
        var byte_index: usize = 0;

        while (parts.next()) |part| {
            if (byte_index >= 16) return error.InvalidFormat;
            if (part.len != 4) return error.InvalidFormat;

            const high_byte = std.fmt.parseInt(u8, part[0..2], 16) catch return error.InvalidFormat;
            const low_byte = std.fmt.parseInt(u8, part[2..4], 16) catch return error.InvalidFormat;

            qid.bytes[byte_index] = high_byte;
            qid.bytes[byte_index + 1] = low_byte;
            byte_index += 2;
        }

        if (byte_index != 16) return error.InvalidFormat;
        return qid;
    }

    /// Check if QID is valid (has SHROUD prefix)
    pub fn isValid(self: QID) bool {
        return self.bytes[0] == 0xfd and self.bytes[1] == 0x00;
    }

    /// Check if two QIDs are equal
    pub fn eql(self: QID, other: QID) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Get the raw bytes
    pub fn toBytes(self: QID) [16]u8 {
        return self.bytes;
    }
};

/// QID-related errors
pub const QIDError = error{
    InvalidFormat,
    BufferTooSmall,
    InvalidDIDDocument,
};

test "QID generation from public key" {
    const test_pubkey = [_]u8{1} ** 32; // Test public key
    const qid = QID.fromPublicKey(&test_pubkey);

    // Should have SHROUD prefix
    try std.testing.expect(qid.isValid());
    try std.testing.expectEqual(@as(u8, 0xfd), qid.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x00), qid.bytes[1]);
}

test "QID string conversion" {
    const test_pubkey = [_]u8{1} ** 32;
    const qid = QID.fromPublicKey(&test_pubkey);

    var buffer: [40]u8 = undefined;
    const qid_str = try qid.toString(&buffer);

    // Should start with fd00
    try std.testing.expect(std.mem.startsWith(u8, qid_str, "fd00"));

    // Should be able to parse back
    const parsed_qid = try QID.fromString(qid_str);
    try std.testing.expect(qid.eql(parsed_qid));
}

test "QID deterministic generation" {
    const test_pubkey = [_]u8{42} ** 32;

    const qid1 = QID.fromPublicKey(&test_pubkey);
    const qid2 = QID.fromPublicKey(&test_pubkey);

    // Same public key should generate same QID
    try std.testing.expect(qid1.eql(qid2));
}
