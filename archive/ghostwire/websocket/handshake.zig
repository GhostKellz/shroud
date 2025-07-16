//! WebSocket handshake implementation (RFC 6455)
//! HTTP upgrade negotiation and security validation

const std = @import("std");

pub const WebSocketHandshake = struct {
    key: []const u8,
    version: u8,
    protocol: ?[]const u8,
    extensions: []const []const u8,
    origin: ?[]const u8,
    allocator: std.mem.Allocator,

    const Self = @This();
    const WEBSOCKET_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const WEBSOCKET_VERSION = 13;

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .key = "",
            .version = WEBSOCKET_VERSION,
            .protocol = null,
            .extensions = &[_][]const u8{},
            .origin = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.key);
        if (self.protocol) |protocol| {
            self.allocator.free(protocol);
        }
        for (self.extensions) |ext| {
            self.allocator.free(ext);
        }
        self.allocator.free(self.extensions);
        if (self.origin) |origin| {
            self.allocator.free(origin);
        }
    }

    pub fn generateKey(allocator: std.mem.Allocator) ![]u8 {
        // Generate 16 random bytes and base64 encode them
        var random_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        
        // Base64 encode
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(16));
        _ = encoder.encode(encoded, &random_bytes);
        
        return encoded;
    }

    pub fn createClientRequest(allocator: std.mem.Allocator, host: []const u8, path: []const u8, protocol: ?[]const u8, origin: ?[]const u8) ![]u8 {
        const key = try generateKey(allocator);
        defer allocator.free(key);

        var request = std.ArrayList(u8).init(allocator);
        defer request.deinit();

        // Request line
        try request.writer().print("GET {s} HTTP/1.1\r\n", .{path});
        
        // Required headers
        try request.writer().print("Host: {s}\r\n", .{host});
        try request.appendSlice("Upgrade: websocket\r\n");
        try request.appendSlice("Connection: Upgrade\r\n");
        try request.writer().print("Sec-WebSocket-Key: {s}\r\n", .{key});
        try request.writer().print("Sec-WebSocket-Version: {}\r\n", .{WEBSOCKET_VERSION});

        // Optional headers
        if (protocol) |proto| {
            try request.writer().print("Sec-WebSocket-Protocol: {s}\r\n", .{proto});
        }

        if (origin) |orig| {
            try request.writer().print("Origin: {s}\r\n", .{orig});
        }

        // User-Agent
        try request.appendSlice("User-Agent: Shroud-WebSocket/1.0\r\n");

        // End headers
        try request.appendSlice("\r\n");

        return request.toOwnedSlice();
    }

    pub fn parseClientRequest(allocator: std.mem.Allocator, request: []const u8) !Self {
        var handshake = Self.init(allocator);
        var lines = std.mem.splitSequence(u8, request, "\r\n");

        // Skip request line
        _ = lines.next();

        while (lines.next()) |line| {
            if (line.len == 0) break; // End of headers

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
            const header_value = std.mem.trim(u8, line[colon_pos + 1..], " \t");

            if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Key")) {
                handshake.key = try allocator.dupe(u8, header_value);
            } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Version")) {
                handshake.version = try std.fmt.parseInt(u8, header_value, 10);
            } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Protocol")) {
                handshake.protocol = try allocator.dupe(u8, header_value);
            } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Extensions")) {
                // Parse extensions (simplified)
                var extensions = std.ArrayList([]const u8).init(allocator);
                var ext_iter = std.mem.splitSequence(u8, header_value, ",");
                while (ext_iter.next()) |ext| {
                    const trimmed = std.mem.trim(u8, ext, " \t");
                    if (trimmed.len > 0) {
                        try extensions.append(try allocator.dupe(u8, trimmed));
                    }
                }
                handshake.extensions = try extensions.toOwnedSlice();
            } else if (std.ascii.eqlIgnoreCase(header_name, "Origin")) {
                handshake.origin = try allocator.dupe(u8, header_value);
            }
        }

        return handshake;
    }

    pub fn validateClientRequest(self: Self) !void {
        // Check WebSocket version
        if (self.version != WEBSOCKET_VERSION) {
            return error.UnsupportedWebSocketVersion;
        }

        // Check key is present and valid length
        if (self.key.len == 0) {
            return error.MissingWebSocketKey;
        }

        // Key should be 24 characters when base64 encoded (16 bytes)
        if (self.key.len != 24) {
            return error.InvalidWebSocketKey;
        }

        // Validate base64 encoding
        var decoded_buffer: [16]u8 = undefined;
        std.base64.standard.Decoder.decode(&decoded_buffer, self.key) catch {
            return error.InvalidWebSocketKey;
        };
    }

    pub fn generateAcceptKey(allocator: std.mem.Allocator, client_key: []const u8) ![]u8 {
        // Concatenate client key with magic string
        const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ client_key, WEBSOCKET_MAGIC_STRING });
        defer allocator.free(combined);

        // SHA-1 hash
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(combined);
        var hash: [20]u8 = undefined;
        sha1.final(&hash);

        // Base64 encode
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(20));
        _ = encoder.encode(encoded, &hash);

        return encoded;
    }

    pub fn createServerResponse(allocator: std.mem.Allocator, client_key: []const u8, protocol: ?[]const u8, extensions: ?[]const u8) ![]u8 {
        const accept_key = try generateAcceptKey(allocator, client_key);
        defer allocator.free(accept_key);

        var response = std.ArrayList(u8).init(allocator);
        defer response.deinit();

        // Status line
        try response.appendSlice("HTTP/1.1 101 Switching Protocols\r\n");
        
        // Required headers
        try response.appendSlice("Upgrade: websocket\r\n");
        try response.appendSlice("Connection: Upgrade\r\n");
        try response.writer().print("Sec-WebSocket-Accept: {s}\r\n", .{accept_key});

        // Optional headers
        if (protocol) |proto| {
            try response.writer().print("Sec-WebSocket-Protocol: {s}\r\n", .{proto});
        }

        if (extensions) |exts| {
            try response.writer().print("Sec-WebSocket-Extensions: {s}\r\n", .{exts});
        }

        // Server header
        try response.appendSlice("Server: Shroud-WebSocket/1.0\r\n");

        // End headers
        try response.appendSlice("\r\n");

        return response.toOwnedSlice();
    }

    pub fn parseServerResponse(allocator: std.mem.Allocator, response: []const u8, expected_key: []const u8) !bool {
        var lines = std.mem.splitSequence(u8, response, "\r\n");

        // Check status line
        const status_line = lines.next() orelse return error.InvalidResponse;
        if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 101")) {
            return error.HandshakeFailed;
        }

        var found_upgrade = false;
        var found_connection = false;
        var accept_key: ?[]const u8 = null;

        while (lines.next()) |line| {
            if (line.len == 0) break; // End of headers

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
            const header_value = std.mem.trim(u8, line[colon_pos + 1..], " \t");

            if (std.ascii.eqlIgnoreCase(header_name, "Upgrade")) {
                found_upgrade = std.ascii.eqlIgnoreCase(header_value, "websocket");
            } else if (std.ascii.eqlIgnoreCase(header_name, "Connection")) {
                found_connection = std.ascii.indexOfIgnoreCase(header_value, "upgrade") != null;
            } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Accept")) {
                accept_key = header_value;
            }
        }

        if (!found_upgrade or !found_connection or accept_key == null) {
            return error.InvalidHandshakeResponse;
        }

        // Validate accept key
        const expected_accept = try generateAcceptKey(allocator, expected_key);
        defer allocator.free(expected_accept);

        if (!std.mem.eql(u8, accept_key.?, expected_accept)) {
            return error.InvalidAcceptKey;
        }

        return true;
    }

    pub fn isWebSocketRequest(request: []const u8) bool {
        var lines = std.mem.splitSequence(u8, request, "\r\n");
        
        // Check if it's an HTTP GET request
        const request_line = lines.next() orelse return false;
        if (!std.mem.startsWith(u8, request_line, "GET ")) return false;

        var has_upgrade = false;
        var has_connection = false;
        var has_websocket_key = false;
        var has_websocket_version = false;

        while (lines.next()) |line| {
            if (line.len == 0) break;

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
            const header_value = std.mem.trim(u8, line[colon_pos + 1..], " \t");

            if (std.ascii.eqlIgnoreCase(header_name, "Upgrade")) {
                has_upgrade = std.ascii.eqlIgnoreCase(header_value, "websocket");
            } else if (std.ascii.eqlIgnoreCase(header_name, "Connection")) {
                has_connection = std.ascii.indexOfIgnoreCase(header_value, "upgrade") != null;
            } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Key")) {
                has_websocket_key = header_value.len > 0;
            } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Version")) {
                has_websocket_version = header_value.len > 0;
            }
        }

        return has_upgrade and has_connection and has_websocket_key and has_websocket_version;
    }
};

pub const WebSocketUpgrade = struct {
    success: bool,
    error_code: ?u16 = null,
    error_message: ?[]const u8 = null,
    selected_protocol: ?[]const u8 = null,
    selected_extensions: ?[]const u8 = null,

    pub fn success_upgrade(protocol: ?[]const u8, extensions: ?[]const u8) WebSocketUpgrade {
        return WebSocketUpgrade{
            .success = true,
            .selected_protocol = protocol,
            .selected_extensions = extensions,
        };
    }

    pub fn failed_upgrade(code: u16, message: []const u8) WebSocketUpgrade {
        return WebSocketUpgrade{
            .success = false,
            .error_code = code,
            .error_message = message,
        };
    }
};

test "WebSocket key generation and validation" {
    const allocator = std.testing.allocator;
    
    const key = try WebSocketHandshake.generateKey(allocator);
    defer allocator.free(key);
    
    try std.testing.expect(key.len == 24); // Base64 encoded 16 bytes
    
    const accept_key = try WebSocketHandshake.generateAcceptKey(allocator, key);
    defer allocator.free(accept_key);
    
    try std.testing.expect(accept_key.len > 0);
}

test "WebSocket request detection" {
    const websocket_request = 
        \\GET /chat HTTP/1.1
        \\Host: example.com
        \\Upgrade: websocket
        \\Connection: Upgrade
        \\Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
        \\Sec-WebSocket-Version: 13
        \\
        \\
    ;
    
    try std.testing.expect(WebSocketHandshake.isWebSocketRequest(websocket_request));
    
    const regular_request = 
        \\GET /index.html HTTP/1.1
        \\Host: example.com
        \\
        \\
    ;
    
    try std.testing.expect(!WebSocketHandshake.isWebSocketRequest(regular_request));
}

test "WebSocket handshake validation" {
    const allocator = std.testing.allocator;
    
    const request = 
        \\GET /chat HTTP/1.1
        \\Host: example.com
        \\Upgrade: websocket
        \\Connection: Upgrade
        \\Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
        \\Sec-WebSocket-Version: 13
        \\
        \\
    ;
    
    var handshake = try WebSocketHandshake.parseClientRequest(allocator, request);
    defer handshake.deinit();
    
    try handshake.validateClientRequest();
    try std.testing.expect(handshake.version == 13);
    try std.testing.expect(std.mem.eql(u8, handshake.key, "dGhlIHNhbXBsZSBub25jZQ=="));
}