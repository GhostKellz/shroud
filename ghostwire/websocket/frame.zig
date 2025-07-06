//! WebSocket frame parsing and encoding (RFC 6455)
//! Complete implementation with all frame types and extensions

const std = @import("std");

pub const WebSocketOpcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    
    // Reserved opcodes for future use
    _reserved_3 = 0x3,
    _reserved_4 = 0x4,
    _reserved_5 = 0x5,
    _reserved_6 = 0x6,
    _reserved_7 = 0x7,
    _reserved_B = 0xB,
    _reserved_C = 0xC,
    _reserved_D = 0xD,
    _reserved_E = 0xE,
    _reserved_F = 0xF,

    pub fn isControl(self: WebSocketOpcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    pub fn isData(self: WebSocketOpcode) bool {
        return @intFromEnum(self) <= 0x2;
    }

    pub fn isReserved(self: WebSocketOpcode) bool {
        return switch (self) {
            ._reserved_3, ._reserved_4, ._reserved_5, ._reserved_6, ._reserved_7,
            ._reserved_B, ._reserved_C, ._reserved_D, ._reserved_E, ._reserved_F => true,
            else => false,
        };
    }
};

pub const WebSocketCloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status_received = 1005,
    abnormal_closure = 1006,
    invalid_frame_payload_data = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_server_error = 1011,
    service_restart = 1012,
    try_again_later = 1013,
    bad_gateway = 1014,
    tls_handshake = 1015,

    pub fn toString(self: WebSocketCloseCode) []const u8 {
        return switch (self) {
            .normal => "Normal Closure",
            .going_away => "Going Away",
            .protocol_error => "Protocol Error",
            .unsupported_data => "Unsupported Data",
            .no_status_received => "No Status Received",
            .abnormal_closure => "Abnormal Closure",
            .invalid_frame_payload_data => "Invalid Frame Payload Data",
            .policy_violation => "Policy Violation",
            .message_too_big => "Message Too Big",
            .mandatory_extension => "Mandatory Extension",
            .internal_server_error => "Internal Server Error",
            .service_restart => "Service Restart",
            .try_again_later => "Try Again Later",
            .bad_gateway => "Bad Gateway",
            .tls_handshake => "TLS Handshake",
        };
    }
};

pub const WebSocketFrame = struct {
    fin: bool,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: WebSocketOpcode,
    masked: bool,
    payload_length: u64,
    masking_key: ?[4]u8 = null,
    payload: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, opcode: WebSocketOpcode, payload: []const u8, fin: bool) !Self {
        return Self{
            .fin = fin,
            .opcode = opcode,
            .masked = false,
            .payload_length = payload.len,
            .payload = try allocator.dupe(u8, payload),
            .allocator = allocator,
        };
    }

    pub fn initMasked(allocator: std.mem.Allocator, opcode: WebSocketOpcode, payload: []const u8, fin: bool, masking_key: [4]u8) !Self {
        const masked_payload = try allocator.dupe(u8, payload);
        
        // Apply masking
        for (masked_payload, 0..) |*byte, i| {
            byte.* ^= masking_key[i % 4];
        }

        return Self{
            .fin = fin,
            .opcode = opcode,
            .masked = true,
            .payload_length = payload.len,
            .masking_key = masking_key,
            .payload = masked_payload,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.payload);
    }

    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var frame_size: usize = 2; // Minimum header size

        // Calculate payload length encoding size
        if (self.payload_length <= 125) {
            // Single byte length
        } else if (self.payload_length <= 65535) {
            frame_size += 2; // Extended 16-bit length
        } else {
            frame_size += 8; // Extended 64-bit length
        }

        // Add masking key size if masked
        if (self.masked) {
            frame_size += 4;
        }

        // Add payload size
        frame_size += self.payload.len;

        var frame = try allocator.alloc(u8, frame_size);
        var offset: usize = 0;

        // First byte: FIN + RSV + Opcode
        frame[0] = 0;
        if (self.fin) frame[0] |= 0x80;
        if (self.rsv1) frame[0] |= 0x40;
        if (self.rsv2) frame[0] |= 0x20;
        if (self.rsv3) frame[0] |= 0x10;
        frame[0] |= @intFromEnum(self.opcode);
        offset += 1;

        // Second byte: MASK + Payload length
        frame[1] = 0;
        if (self.masked) frame[1] |= 0x80;

        if (self.payload_length <= 125) {
            frame[1] |= @intCast(self.payload_length);
            offset += 1;
        } else if (self.payload_length <= 65535) {
            frame[1] |= 126;
            std.mem.writeInt(u16, frame[2..4], @intCast(self.payload_length), .big);
            offset += 3;
        } else {
            frame[1] |= 127;
            std.mem.writeInt(u64, frame[2..10], self.payload_length, .big);
            offset += 9;
        }

        // Masking key
        if (self.masked and self.masking_key != null) {
            @memcpy(frame[offset..offset + 4], &self.masking_key.?);
            offset += 4;
        }

        // Payload
        @memcpy(frame[offset..], self.payload);

        return frame;
    }

    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !Self {
        if (data.len < 2) return error.IncompleteFrame;

        var offset: usize = 0;

        // Parse first byte
        const first_byte = data[0];
        const fin = (first_byte & 0x80) != 0;
        const rsv1 = (first_byte & 0x40) != 0;
        const rsv2 = (first_byte & 0x20) != 0;
        const rsv3 = (first_byte & 0x10) != 0;
        const opcode: WebSocketOpcode = @enumFromInt(first_byte & 0x0F);
        offset += 1;

        // Parse second byte
        const second_byte = data[1];
        const masked = (second_byte & 0x80) != 0;
        var payload_length: u64 = second_byte & 0x7F;
        offset += 1;

        // Parse extended payload length
        if (payload_length == 126) {
            if (data.len < offset + 2) return error.IncompleteFrame;
            payload_length = std.mem.readInt(u16, data[offset..offset + 2], .big);
            offset += 2;
        } else if (payload_length == 127) {
            if (data.len < offset + 8) return error.IncompleteFrame;
            payload_length = std.mem.readInt(u64, data[offset..offset + 8], .big);
            offset += 8;
        }

        // Parse masking key
        var masking_key: ?[4]u8 = null;
        if (masked) {
            if (data.len < offset + 4) return error.IncompleteFrame;
            masking_key = data[offset..offset + 4][0..4].*;
            offset += 4;
        }

        // Check if we have complete payload
        if (data.len < offset + payload_length) return error.IncompleteFrame;

        // Extract and unmask payload
        const payload = try allocator.alloc(u8, payload_length);
        @memcpy(payload, data[offset..offset + payload_length]);

        if (masked and masking_key != null) {
            for (payload, 0..) |*byte, i| {
                byte.* ^= masking_key.?[i % 4];
            }
        }

        return Self{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .payload_length = payload_length,
            .masking_key = masking_key,
            .payload = payload,
            .allocator = allocator,
        };
    }

    pub fn getFrameSize(data: []const u8) !usize {
        if (data.len < 2) return error.IncompleteFrame;

        var size: usize = 2;
        
        // Check payload length encoding
        const payload_len_indicator = data[1] & 0x7F;
        if (payload_len_indicator == 126) {
            if (data.len < 4) return error.IncompleteFrame;
            size += 2;
            const payload_length = std.mem.readInt(u16, data[2..4], .big);
            size += payload_length;
        } else if (payload_len_indicator == 127) {
            if (data.len < 10) return error.IncompleteFrame;
            size += 8;
            const payload_length = std.mem.readInt(u64, data[2..10], .big);
            size += payload_length;
        } else {
            size += payload_len_indicator;
        }

        // Add masking key size
        if ((data[1] & 0x80) != 0) {
            size += 4;
        }

        return size;
    }

    pub fn createTextFrame(allocator: std.mem.Allocator, text: []const u8, fin: bool) !Self {
        return Self.init(allocator, .text, text, fin);
    }

    pub fn createBinaryFrame(allocator: std.mem.Allocator, data: []const u8, fin: bool) !Self {
        return Self.init(allocator, .binary, data, fin);
    }

    pub fn createCloseFrame(allocator: std.mem.Allocator, code: WebSocketCloseCode, reason: []const u8) !Self {
        var close_payload = try allocator.alloc(u8, 2 + reason.len);
        std.mem.writeInt(u16, close_payload[0..2], @intFromEnum(code), .big);
        @memcpy(close_payload[2..], reason);
        
        return Self{
            .fin = true,
            .opcode = .close,
            .masked = false,
            .payload_length = close_payload.len,
            .payload = close_payload,
            .allocator = allocator,
        };
    }

    pub fn createPingFrame(allocator: std.mem.Allocator, data: []const u8) !Self {
        return Self.init(allocator, .ping, data, true);
    }

    pub fn createPongFrame(allocator: std.mem.Allocator, data: []const u8) !Self {
        return Self.init(allocator, .pong, data, true);
    }

    pub fn parseCloseFrame(self: Self) ?struct { code: WebSocketCloseCode, reason: []const u8 } {
        if (self.opcode != .close or self.payload.len < 2) return null;
        
        const code: WebSocketCloseCode = @enumFromInt(std.mem.readInt(u16, self.payload[0..2], .big));
        const reason = self.payload[2..];
        
        return .{ .code = code, .reason = reason };
    }

    pub fn isControlFrame(self: Self) bool {
        return self.opcode.isControl();
    }

    pub fn isDataFrame(self: Self) bool {
        return self.opcode.isData();
    }

    pub fn validate(self: Self) !void {
        // Control frames must not be fragmented
        if (self.isControlFrame() and !self.fin) {
            return error.ControlFrameFragmented;
        }

        // Control frames must have payload <= 125 bytes
        if (self.isControlFrame() and self.payload_length > 125) {
            return error.ControlFramePayloadTooLarge;
        }

        // RSV bits must be 0 unless extension defines them
        if (self.rsv1 or self.rsv2 or self.rsv3) {
            return error.ReservedBitsSet;
        }

        // Close frame payload must be valid UTF-8 if present
        if (self.opcode == .close and self.payload.len > 2) {
            const reason = self.payload[2..];
            if (!std.unicode.utf8ValidateSlice(reason)) {
                return error.InvalidCloseReason;
            }
        }

        // Text frame payload must be valid UTF-8
        if (self.opcode == .text) {
            if (!std.unicode.utf8ValidateSlice(self.payload)) {
                return error.InvalidTextPayload;
            }
        }
    }
};

test "WebSocket frame encoding/decoding" {
    const allocator = std.testing.allocator;
    
    // Test text frame
    const text_data = "Hello, WebSocket!";
    var text_frame = try WebSocketFrame.createTextFrame(allocator, text_data, true);
    defer text_frame.deinit();
    
    const encoded = try text_frame.encode(allocator);
    defer allocator.free(encoded);
    
    var decoded = try WebSocketFrame.decode(allocator, encoded);
    defer decoded.deinit();
    
    try std.testing.expect(decoded.fin == true);
    try std.testing.expect(decoded.opcode == .text);
    try std.testing.expect(std.mem.eql(u8, decoded.payload, text_data));
}

test "WebSocket close frame" {
    const allocator = std.testing.allocator;
    
    var close_frame = try WebSocketFrame.createCloseFrame(allocator, .normal, "Goodbye");
    defer close_frame.deinit();
    
    const close_info = close_frame.parseCloseFrame();
    try std.testing.expect(close_info != null);
    try std.testing.expect(close_info.?.code == .normal);
    try std.testing.expect(std.mem.eql(u8, close_info.?.reason, "Goodbye"));
}

test "WebSocket frame validation" {
    const allocator = std.testing.allocator;
    
    var ping_frame = try WebSocketFrame.createPingFrame(allocator, "ping");
    defer ping_frame.deinit();
    
    try ping_frame.validate();
    try std.testing.expect(ping_frame.isControlFrame());
}