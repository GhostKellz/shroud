//! QID (IPv6-based identity) module for GhostWallet
//! Generates and manages QID identities derived from RealID public keys

const std = @import("std");
const sigil = @import("sigil");

pub const QIDError = error{
    InvalidPublicKey,
    InvalidQIDFormat,
    ConversionFailed,
};

/// QID structure - 128-bit IPv6 address derived from public key
pub const QID = struct {
    bytes: [16]u8,

    const Self = @This();

    /// Generate QID from RealID public key
    pub fn fromPublicKey(public_key: [32]u8) Self {
        const realid_qid = sigil.realid_qid_from_pubkey(.{ .bytes = public_key });
        return Self{ .bytes = realid_qid.bytes };
    }

    /// Generate QID from passphrase (convenience method)
    pub fn fromPassphrase(passphrase: []const u8) !Self {
        const keypair = try sigil.realid_generate_from_passphrase(passphrase);
        return Self.fromPublicKey(keypair.public_key.bytes);
    }

    /// Generate device-bound QID
    pub fn fromPassphraseWithDevice(allocator: std.mem.Allocator, passphrase: []const u8) !Self {
        const device_fp = try sigil.generate_device_fingerprint(allocator);
        const keypair = try sigil.realid_generate_from_passphrase_with_device(passphrase, device_fp);
        return Self.fromPublicKey(keypair.public_key.bytes);
    }

    /// Convert QID to IPv6 string representation
    pub fn toString(self: Self, buffer: []u8) ![]u8 {
        if (buffer.len < 39) return QIDError.ConversionFailed; // IPv6 max length

        return std.fmt.bufPrint(buffer, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            self.bytes[0],  self.bytes[1],  self.bytes[2],  self.bytes[3],
            self.bytes[4],  self.bytes[5],  self.bytes[6],  self.bytes[7],
            self.bytes[8],  self.bytes[9],  self.bytes[10], self.bytes[11],
            self.bytes[12], self.bytes[13], self.bytes[14], self.bytes[15],
        });
    }

    /// Parse QID from IPv6 string
    pub fn fromString(qid_str: []const u8) !Self {
        // Simple parsing - in production would be more robust
        if (qid_str.len < 32) return QIDError.InvalidQIDFormat;

        var qid = Self{ .bytes = std.mem.zeroes([16]u8) };
        var byte_index: usize = 0;
        var i: usize = 0;

        while (i < qid_str.len and byte_index < 16) : (i += 1) {
            const char = qid_str[i];
            if (char == ':') continue;

            if (std.ascii.isHex(char)) {
                const hex_val = try std.fmt.charToDigit(char, 16);
                if (i + 1 < qid_str.len and std.ascii.isHex(qid_str[i + 1])) {
                    const hex_val2 = try std.fmt.charToDigit(qid_str[i + 1], 16);
                    qid.bytes[byte_index] = @as(u8, hex_val) * 16 + @as(u8, hex_val2);
                    byte_index += 1;
                    i += 1; // Skip next character
                }
            }
        }

        return qid;
    }

    /// Get QID as network address for networking operations
    pub fn toNetworkAddress(self: Self, port: u16) std.net.Address {
        return std.net.Address.initIp6(self.bytes, port, 0, 0);
    }

    /// Check if QID is valid (non-zero)
    pub fn isValid(self: Self) bool {
        for (self.bytes) |byte| {
            if (byte != 0) return true;
        }
        return false;
    }

    /// Get QID prefix for network routing
    pub fn getPrefix(self: Self, prefix_length: u8) [16]u8 {
        var prefix = self.bytes;
        const bytes_to_clear = (128 - prefix_length) / 8;
        const bits_to_clear = (128 - prefix_length) % 8;

        // Clear full bytes
        if (bytes_to_clear > 0) {
            std.mem.set(u8, prefix[16 - bytes_to_clear ..], 0);
        }

        // Clear partial bits
        if (bits_to_clear > 0 and 16 - bytes_to_clear > 0) {
            const mask = (@as(u8, 0xFF) << @as(u3, @intCast(bits_to_clear)));
            prefix[16 - bytes_to_clear - 1] &= mask;
        }

        return prefix;
    }

    /// Compare QIDs for equality
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Format QID for printing
    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            self.bytes[0],  self.bytes[1],  self.bytes[2],  self.bytes[3],
            self.bytes[4],  self.bytes[5],  self.bytes[6],  self.bytes[7],
            self.bytes[8],  self.bytes[9],  self.bytes[10], self.bytes[11],
            self.bytes[12], self.bytes[13], self.bytes[14], self.bytes[15],
        });
    }
};

test "QID generation from public key" {
    const test_pubkey = [32]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    const qid = QID.fromPublicKey(test_pubkey);
    try std.testing.expect(qid.isValid());
}

test "QID string conversion" {
    const test_pubkey = [32]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    const qid = QID.fromPublicKey(test_pubkey);

    var buffer: [64]u8 = undefined;
    const qid_string = try qid.toString(&buffer);

    try std.testing.expect(qid_string.len > 0);

    // Test round-trip
    const parsed_qid = try QID.fromString(qid_string);
    try std.testing.expect(qid.eql(parsed_qid));
}

test "QID network address" {
    var test_pubkey = [_]u8{0} ** 32;
    test_pubkey[0] = 0x42;

    const qid = QID.fromPublicKey(test_pubkey);
    const addr = qid.toNetworkAddress(8080);

    try std.testing.expect(addr.getPort() == 8080);
}
