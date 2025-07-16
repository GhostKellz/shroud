//! WebSocket client implementation
//! High-performance WebSocket client with reconnection and message handling

const std = @import("std");
const WebSocketFrame = @import("frame.zig").WebSocketFrame;
const WebSocketOpcode = @import("frame.zig").WebSocketOpcode;
const WebSocketCloseCode = @import("frame.zig").WebSocketCloseCode;
const WebSocketHandshake = @import("handshake.zig").WebSocketHandshake;

pub const WebSocketClientConfig = struct {
    connect_timeout_ms: u32 = 10000,
    ping_interval_ms: u32 = 30000,
    pong_timeout_ms: u32 = 10000,
    max_message_size: usize = 1024 * 1024, // 1MB
    auto_reconnect: bool = true,
    reconnect_delay_ms: u32 = 5000,
    max_reconnect_attempts: u32 = 5,
    enable_compression: bool = false,
    protocols: []const []const u8 = &[_][]const u8{},
    headers: ?std.StringHashMap([]const u8) = null,
};

pub const ConnectionState = enum {
    disconnected,
    connecting,
    connected,
    reconnecting,
    closing,
    closed,
};

pub const WebSocketClientEvent = enum {
    connected,
    disconnected,
    message_received,
    error_occurred,
    reconnecting,
};

pub const ClientMessage = struct {
    opcode: WebSocketOpcode,
    data: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, opcode: WebSocketOpcode, data: []const u8) !Self {
        return Self{
            .opcode = opcode,
            .data = try allocator.dupe(u8, data),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }

    pub fn isText(self: Self) bool {
        return self.opcode == .text;
    }

    pub fn isBinary(self: Self) bool {
        return self.opcode == .binary;
    }

    pub fn getText(self: Self) []const u8 {
        return self.data;
    }

    pub fn getBinary(self: Self) []const u8 {
        return self.data;
    }
};

pub const ClientEventHandler = *const fn (WebSocketClientEvent, ?ClientMessage) void;

pub const WebSocketClient = struct {
    allocator: std.mem.Allocator,
    config: WebSocketClientConfig,
    url: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
    state: ConnectionState,
    socket: ?std.net.Stream = null,
    last_ping: i64,
    last_pong: i64,
    reconnect_attempts: u32 = 0,
    event_handler: ?ClientEventHandler = null,
    frame_buffer: std.ArrayList(u8),
    message_queue: std.ArrayList(QueuedMessage),
    running: bool = false,

    const Self = @This();

    const QueuedMessage = struct {
        opcode: WebSocketOpcode,
        data: []const u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *QueuedMessage) void {
            self.allocator.free(self.data);
        }
    };

    pub fn init(allocator: std.mem.Allocator, url: []const u8, config: WebSocketClientConfig) !Self {
        const parsed_url = try parseWebSocketUrl(allocator, url);
        defer allocator.free(parsed_url.host);
        defer allocator.free(parsed_url.path);

        return Self{
            .allocator = allocator,
            .config = config,
            .url = try allocator.dupe(u8, url),
            .host = try allocator.dupe(u8, parsed_url.host),
            .port = parsed_url.port,
            .path = try allocator.dupe(u8, parsed_url.path),
            .state = .disconnected,
            .last_ping = std.time.timestamp(),
            .last_pong = std.time.timestamp(),
            .frame_buffer = std.ArrayList(u8).init(allocator),
            .message_queue = std.ArrayList(QueuedMessage).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.disconnect();
        
        self.allocator.free(self.url);
        self.allocator.free(self.host);
        self.allocator.free(self.path);
        self.frame_buffer.deinit();
        
        for (self.message_queue.items) |*msg| {
            msg.deinit();
        }
        self.message_queue.deinit();
    }

    pub fn setEventHandler(self: *Self, handler: ClientEventHandler) void {
        self.event_handler = handler;
    }

    pub fn connect(self: *Self) !void {
        if (self.state == .connected) return;
        
        self.state = .connecting;
        
        // Connect to server
        const address = try std.net.Address.resolveIp(self.host, self.port);
        self.socket = try std.net.tcpConnectToAddress(address);
        
        // Perform WebSocket handshake
        try self.performHandshake();
        
        self.state = .connected;
        self.reconnect_attempts = 0;
        self.last_ping = std.time.timestamp();
        self.last_pong = std.time.timestamp();
        
        if (self.event_handler) |handler| {
            handler(.connected, null);
        }
        
        // Send any queued messages
        try self.sendQueuedMessages();
    }

    pub fn disconnect(self: *Self) void {
        if (self.socket) |socket| {
            // Send close frame
            const close_frame = WebSocketFrame.createCloseFrame(self.allocator, .normal, "Client disconnect") catch return;
            defer close_frame.deinit();
            
            const encoded = close_frame.encode(self.allocator) catch return;
            defer self.allocator.free(encoded);
            
            _ = socket.writeAll(encoded) catch {};
            socket.close();
            self.socket = null;
        }
        
        self.state = .disconnected;
        
        if (self.event_handler) |handler| {
            handler(.disconnected, null);
        }
    }

    pub fn run(self: *Self) !void {
        self.running = true;
        
        while (self.running) {
            if (self.state == .disconnected and self.config.auto_reconnect) {
                try self.attemptReconnect();
            }
            
            if (self.state == .connected) {
                try self.processMessages();
                
                // Send ping if needed
                if (self.needsPing()) {
                    try self.sendPing("ping");
                }
                
                // Check for pong timeout
                if (self.isPongTimedOut()) {
                    self.disconnect();
                    continue;
                }
            }
            
            std.time.sleep(10 * std.time.ns_per_ms); // 10ms sleep
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
    }

    pub fn sendText(self: *Self, text: []const u8) !void {
        try self.sendMessage(.text, text);
    }

    pub fn sendBinary(self: *Self, data: []const u8) !void {
        try self.sendMessage(.binary, data);
    }

    pub fn sendPing(self: *Self, data: []const u8) !void {
        try self.sendMessage(.ping, data);
        self.last_ping = std.time.timestamp();
    }

    pub fn close(self: *Self, code: WebSocketCloseCode, reason: []const u8) !void {
        if (self.state != .connected) return;
        
        self.state = .closing;
        
        var close_frame = try WebSocketFrame.createCloseFrame(self.allocator, code, reason);
        defer close_frame.deinit();
        
        try self.sendFrame(close_frame);
        
        // Wait for close response or timeout
        std.time.sleep(self.config.pong_timeout_ms * std.time.ns_per_ms);
        
        self.disconnect();
    }

    fn sendMessage(self: *Self, opcode: WebSocketOpcode, data: []const u8) !void {
        if (self.state != .connected) {
            // Queue message for later
            const queued = QueuedMessage{
                .opcode = opcode,
                .data = try self.allocator.dupe(u8, data),
                .allocator = self.allocator,
            };
            try self.message_queue.append(queued);
            return;
        }

        // Generate masking key for client frames
        var masking_key: [4]u8 = undefined;
        std.crypto.random.bytes(&masking_key);
        
        var frame = try WebSocketFrame.initMasked(self.allocator, opcode, data, true, masking_key);
        defer frame.deinit();
        
        try self.sendFrame(frame);
    }

    fn sendFrame(self: *Self, frame: WebSocketFrame) !void {
        if (self.socket == null) return error.NotConnected;
        
        const encoded = try frame.encode(self.allocator);
        defer self.allocator.free(encoded);
        
        _ = try self.socket.?.writeAll(encoded);
    }

    fn performHandshake(self: *Self) !void {
        // Create handshake request
        const request = try WebSocketHandshake.createClientRequest(
            self.allocator,
            self.host,
            self.path,
            if (self.config.protocols.len > 0) self.config.protocols[0] else null,
            null
        );
        defer self.allocator.free(request);
        
        // Send handshake request
        _ = try self.socket.?.writeAll(request);
        
        // Read handshake response
        var response_buffer: [4096]u8 = undefined;
        const bytes_read = try self.socket.?.read(&response_buffer);
        
        if (bytes_read == 0) {
            return error.HandshakeFailed;
        }
        
        const response = response_buffer[0..bytes_read];
        
        // Validate handshake response
        // In a real implementation, we'd extract the key from our request
        const dummy_key = "dGhlIHNhbXBsZSBub25jZQ==";
        _ = try WebSocketHandshake.parseServerResponse(self.allocator, response, dummy_key);
    }

    fn processMessages(self: *Self) !void {
        if (self.socket == null) return;
        
        var buffer: [4096]u8 = undefined;
        const bytes_read = self.socket.?.read(&buffer) catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return err,
            }
        };
        
        if (bytes_read == 0) {
            self.disconnect();
            return;
        }
        
        try self.frame_buffer.appendSlice(buffer[0..bytes_read]);
        
        var offset: usize = 0;
        while (offset < self.frame_buffer.items.len) {
            const remaining = self.frame_buffer.items[offset..];
            
            if (remaining.len < 2) break;
            
            const frame_size = WebSocketFrame.getFrameSize(remaining) catch break;
            
            if (remaining.len < frame_size) break;
            
            var frame = try WebSocketFrame.decode(self.allocator, remaining[0..frame_size]);
            defer frame.deinit();
            
            try self.handleFrame(frame);
            offset += frame_size;
        }
        
        // Remove processed data
        if (offset > 0) {
            const remaining_data = self.frame_buffer.items[offset..];
            const remaining_len = remaining_data.len;
            std.mem.copyForwards(u8, self.frame_buffer.items[0..remaining_len], remaining_data);
            self.frame_buffer.shrinkRetainingCapacity(remaining_len);
        }
    }

    fn handleFrame(self: *Self, frame: WebSocketFrame) !void {
        switch (frame.opcode) {
            .text, .binary => {
                const message = try ClientMessage.init(self.allocator, frame.opcode, frame.payload);
                if (self.event_handler) |handler| {
                    handler(.message_received, message);
                }
            },
            .close => {
                if (frame.parseCloseFrame()) |close_info| {
                    std.log.info("WebSocket closed: {} - {s}", .{ close_info.code, close_info.reason });
                }
                self.disconnect();
            },
            .ping => {
                // Send pong response
                try self.sendMessage(.pong, frame.payload);
            },
            .pong => {
                self.last_pong = std.time.timestamp();
            },
            else => {
                // Ignore unknown opcodes
            },
        }
    }

    fn sendQueuedMessages(self: *Self) !void {
        for (self.message_queue.items) |msg| {
            try self.sendMessage(msg.opcode, msg.data);
        }
        
        for (self.message_queue.items) |*msg| {
            msg.deinit();
        }
        self.message_queue.clearRetainingCapacity();
    }

    fn attemptReconnect(self: *Self) !void {
        if (self.reconnect_attempts >= self.config.max_reconnect_attempts) {
            return;
        }
        
        self.state = .reconnecting;
        self.reconnect_attempts += 1;
        
        if (self.event_handler) |handler| {
            handler(.reconnecting, null);
        }
        
        std.time.sleep(self.config.reconnect_delay_ms * std.time.ns_per_ms);
        
        self.connect() catch |err| {
            if (self.event_handler) |handler| {
                handler(.error_occurred, null);
            }
            return err;
        };
    }

    fn needsPing(self: Self) bool {
        const now = std.time.timestamp();
        return (now - self.last_ping) > (self.config.ping_interval_ms / 1000);
    }

    fn isPongTimedOut(self: Self) bool {
        const now = std.time.timestamp();
        return (now - self.last_pong) > (self.config.pong_timeout_ms / 1000);
    }

    pub fn isConnected(self: Self) bool {
        return self.state == .connected;
    }

    pub fn getState(self: Self) ConnectionState {
        return self.state;
    }
};

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseWebSocketUrl(allocator: std.mem.Allocator, url: []const u8) !ParsedUrl {
    // Simple URL parsing for ws://host:port/path
    var remaining = url;
    
    // Skip protocol
    if (std.mem.startsWith(u8, remaining, "ws://")) {
        remaining = remaining[5..];
    } else if (std.mem.startsWith(u8, remaining, "wss://")) {
        remaining = remaining[6..];
    }
    
    // Find path separator
    const path_start = std.mem.indexOf(u8, remaining, "/") orelse remaining.len;
    const host_port = remaining[0..path_start];
    const path = if (path_start < remaining.len) remaining[path_start..] else "/";
    
    // Split host and port
    if (std.mem.indexOf(u8, host_port, ":")) |colon_pos| {
        const host = host_port[0..colon_pos];
        const port_str = host_port[colon_pos + 1..];
        const port = try std.fmt.parseInt(u16, port_str, 10);
        
        return ParsedUrl{
            .host = try allocator.dupe(u8, host),
            .port = port,
            .path = try allocator.dupe(u8, path),
        };
    } else {
        return ParsedUrl{
            .host = try allocator.dupe(u8, host_port),
            .port = 80, // Default WebSocket port
            .path = try allocator.dupe(u8, path),
        };
    }
}

test "WebSocket client URL parsing" {
    const allocator = std.testing.allocator;
    
    const parsed = try parseWebSocketUrl(allocator, "ws://localhost:8080/chat");
    defer allocator.free(parsed.host);
    defer allocator.free(parsed.path);
    
    try std.testing.expect(std.mem.eql(u8, parsed.host, "localhost"));
    try std.testing.expect(parsed.port == 8080);
    try std.testing.expect(std.mem.eql(u8, parsed.path, "/chat"));
}

test "WebSocket client message creation" {
    const allocator = std.testing.allocator;
    
    var message = try ClientMessage.init(allocator, .text, "Hello WebSocket");
    defer message.deinit();
    
    try std.testing.expect(message.isText());
    try std.testing.expect(std.mem.eql(u8, message.getText(), "Hello WebSocket"));
}