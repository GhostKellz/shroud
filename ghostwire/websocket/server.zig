//! WebSocket server implementation
//! High-performance WebSocket server with connection management and message handling

const std = @import("std");
const WebSocketFrame = @import("frame.zig").WebSocketFrame;
const WebSocketOpcode = @import("frame.zig").WebSocketOpcode;
const WebSocketCloseCode = @import("frame.zig").WebSocketCloseCode;
const WebSocketHandshake = @import("handshake.zig").WebSocketHandshake;
const WebSocketUpgrade = @import("handshake.zig").WebSocketUpgrade;

pub const WebSocketServerConfig = struct {
    address: []const u8 = "0.0.0.0",
    port: u16 = 8080,
    max_connections: u32 = 1000,
    max_message_size: usize = 1024 * 1024, // 1MB
    ping_interval_ms: u32 = 30000,
    pong_timeout_ms: u32 = 10000,
    close_timeout_ms: u32 = 5000,
    enable_compression: bool = false,
    supported_protocols: []const []const u8 = &[_][]const u8{},
    supported_extensions: []const []const u8 = &[_][]const u8{},
};

pub const WebSocketMessage = struct {
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

pub const ConnectionState = enum {
    connecting,
    open,
    closing,
    closed,
};

pub const WebSocketConnection = struct {
    id: u64,
    socket: std.net.Stream,
    state: ConnectionState,
    last_ping: i64,
    last_pong: i64,
    received_close: bool = false,
    sent_close: bool = false,
    protocol: ?[]const u8 = null,
    extensions: ?[]const u8 = null,
    message_buffer: std.ArrayList(u8),
    frame_buffer: std.ArrayList(u8),
    partial_message: ?struct {
        opcode: WebSocketOpcode,
        data: std.ArrayList(u8),
    } = null,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, id: u64, socket: std.net.Stream) Self {
        return Self{
            .id = id,
            .socket = socket,
            .state = .connecting,
            .last_ping = std.time.timestamp(),
            .last_pong = std.time.timestamp(),
            .message_buffer = std.ArrayList(u8).init(allocator),
            .frame_buffer = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.socket.close();
        self.message_buffer.deinit();
        self.frame_buffer.deinit();
        
        if (self.partial_message) |*partial| {
            partial.data.deinit();
        }
        
        if (self.protocol) |protocol| {
            self.allocator.free(protocol);
        }
        
        if (self.extensions) |extensions| {
            self.allocator.free(extensions);
        }
    }

    pub fn sendFrame(self: *Self, frame: WebSocketFrame) !void {
        const encoded = try frame.encode(self.allocator);
        defer self.allocator.free(encoded);
        
        _ = try self.socket.writeAll(encoded);
    }

    pub fn sendText(self: *Self, text: []const u8) !void {
        var frame = try WebSocketFrame.createTextFrame(self.allocator, text, true);
        defer frame.deinit();
        
        try self.sendFrame(frame);
    }

    pub fn sendBinary(self: *Self, data: []const u8) !void {
        var frame = try WebSocketFrame.createBinaryFrame(self.allocator, data, true);
        defer frame.deinit();
        
        try self.sendFrame(frame);
    }

    pub fn sendPing(self: *Self, data: []const u8) !void {
        var frame = try WebSocketFrame.createPingFrame(self.allocator, data);
        defer frame.deinit();
        
        try self.sendFrame(frame);
        self.last_ping = std.time.timestamp();
    }

    pub fn sendPong(self: *Self, data: []const u8) !void {
        var frame = try WebSocketFrame.createPongFrame(self.allocator, data);
        defer frame.deinit();
        
        try self.sendFrame(frame);
    }

    pub fn close(self: *Self, code: WebSocketCloseCode, reason: []const u8) !void {
        if (self.sent_close) return;
        
        var frame = try WebSocketFrame.createCloseFrame(self.allocator, code, reason);
        defer frame.deinit();
        
        try self.sendFrame(frame);
        self.sent_close = true;
        self.state = .closing;
    }

    pub fn readFrames(self: *Self) ![]WebSocketFrame {
        var buffer: [4096]u8 = undefined;
        const bytes_read = try self.socket.read(&buffer);
        
        if (bytes_read == 0) {
            return &[_]WebSocketFrame{};
        }
        
        try self.frame_buffer.appendSlice(buffer[0..bytes_read]);
        
        var frames = std.ArrayList(WebSocketFrame).init(self.allocator);
        defer frames.deinit();
        
        var offset: usize = 0;
        while (offset < self.frame_buffer.items.len) {
            const remaining = self.frame_buffer.items[offset..];
            
            // Check if we have enough data for frame header
            if (remaining.len < 2) break;
            
            // Get complete frame size
            const frame_size = WebSocketFrame.getFrameSize(remaining) catch break;
            
            // Check if we have complete frame
            if (remaining.len < frame_size) break;
            
            // Decode frame
            const frame = try WebSocketFrame.decode(self.allocator, remaining[0..frame_size]);
            try frames.append(frame);
            
            offset += frame_size;
        }
        
        // Remove processed data from buffer
        if (offset > 0) {
            const remaining_data = self.frame_buffer.items[offset..];
            const remaining_len = remaining_data.len;
            std.mem.copyForwards(u8, self.frame_buffer.items[0..remaining_len], remaining_data);
            self.frame_buffer.shrinkRetainingCapacity(remaining_len);
        }
        
        return frames.toOwnedSlice();
    }

    pub fn isConnected(self: Self) bool {
        return self.state == .open;
    }

    pub fn needsPing(self: Self, interval_ms: u32) bool {
        const now = std.time.timestamp();
        return (now - self.last_ping) > (interval_ms / 1000);
    }

    pub fn isTimedOut(self: Self, timeout_ms: u32) bool {
        const now = std.time.timestamp();
        return (now - self.last_pong) > (timeout_ms / 1000);
    }
};

pub const WebSocketEventType = enum {
    connection_open,
    connection_close,
    message_received,
    ping_received,
    pong_received,
    error_occurred,
};

pub const WebSocketEvent = struct {
    event_type: WebSocketEventType,
    connection_id: u64,
    message: ?WebSocketMessage = null,
    close_code: ?WebSocketCloseCode = null,
    close_reason: ?[]const u8 = null,
    error_message: ?[]const u8 = null,
    ping_data: ?[]const u8 = null,
    pong_data: ?[]const u8 = null,

    pub fn connectionOpen(connection_id: u64) WebSocketEvent {
        return WebSocketEvent{
            .event_type = .connection_open,
            .connection_id = connection_id,
        };
    }

    pub fn connectionClose(connection_id: u64, code: WebSocketCloseCode, reason: []const u8) WebSocketEvent {
        return WebSocketEvent{
            .event_type = .connection_close,
            .connection_id = connection_id,
            .close_code = code,
            .close_reason = reason,
        };
    }

    pub fn messageReceived(connection_id: u64, message: WebSocketMessage) WebSocketEvent {
        return WebSocketEvent{
            .event_type = .message_received,
            .connection_id = connection_id,
            .message = message,
        };
    }

    pub fn pingReceived(connection_id: u64, data: []const u8) WebSocketEvent {
        return WebSocketEvent{
            .event_type = .ping_received,
            .connection_id = connection_id,
            .ping_data = data,
        };
    }

    pub fn pongReceived(connection_id: u64, data: []const u8) WebSocketEvent {
        return WebSocketEvent{
            .event_type = .pong_received,
            .connection_id = connection_id,
            .pong_data = data,
        };
    }

    pub fn errorOccurred(connection_id: u64, error_message: []const u8) WebSocketEvent {
        return WebSocketEvent{
            .event_type = .error_occurred,
            .connection_id = connection_id,
            .error_message = error_message,
        };
    }
};

pub const WebSocketEventHandler = *const fn (WebSocketEvent) void;

pub const WebSocketServer = struct {
    allocator: std.mem.Allocator,
    config: WebSocketServerConfig,
    listener: std.net.Server,
    connections: std.HashMap(u64, *WebSocketConnection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    next_connection_id: u64 = 1,
    event_handler: ?WebSocketEventHandler = null,
    running: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: WebSocketServerConfig) !Self {
        const address = try std.net.Address.parseIp(config.address, config.port);
        const listener = try address.listen(.{ .reuse_address = true });

        return Self{
            .allocator = allocator,
            .config = config,
            .listener = listener,
            .connections = std.HashMap(u64, *WebSocketConnection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit();
        self.listener.deinit();
    }

    pub fn setEventHandler(self: *Self, handler: WebSocketEventHandler) void {
        self.event_handler = handler;
    }

    pub fn start(self: *Self) !void {
        self.running = true;
        std.log.info("WebSocket server listening on {}:{}", .{ self.config.address, self.config.port });

        while (self.running) {
            const client_socket = self.listener.accept() catch continue;
            
            // Handle connection (simplified for demo - real implementation would use threads)
            try self.handleNewConnection(client_socket);
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
    }

    fn handleNewConnection(self: *Self, socket: std.net.Stream) !void {
        // Read HTTP request
        var buffer: [4096]u8 = undefined;
        const bytes_read = try socket.read(&buffer);
        
        if (bytes_read == 0) {
            socket.close();
            return;
        }
        
        const request = buffer[0..bytes_read];
        
        // Check if it's a WebSocket upgrade request
        if (!WebSocketHandshake.isWebSocketRequest(request)) {
            // Send HTTP error response
            const error_response = "HTTP/1.1 400 Bad Request\r\n\r\nNot a WebSocket request";
            _ = try socket.writeAll(error_response);
            socket.close();
            return;
        }
        
        // Parse handshake
        var handshake = WebSocketHandshake.parseClientRequest(self.allocator, request) catch {
            const error_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid WebSocket handshake";
            _ = try socket.writeAll(error_response);
            socket.close();
            return;
        };
        defer handshake.deinit();
        
        // Validate handshake
        handshake.validateClientRequest() catch {
            const error_response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid WebSocket version or key";
            _ = try socket.writeAll(error_response);
            socket.close();
            return;
        };
        
        // Select protocol and extensions
        const selected_protocol = self.selectProtocol(handshake.protocol);
        const selected_extensions = self.selectExtensions(handshake.extensions);
        
        // Create response
        const response = try WebSocketHandshake.createServerResponse(
            self.allocator,
            handshake.key,
            selected_protocol,
            selected_extensions
        );
        defer self.allocator.free(response);
        
        // Send response
        _ = try socket.writeAll(response);
        
        // Create connection
        const connection_id = self.next_connection_id;
        self.next_connection_id += 1;
        
        const connection = try self.allocator.create(WebSocketConnection);
        connection.* = WebSocketConnection.init(self.allocator, connection_id, socket);
        connection.state = .open;
        
        if (selected_protocol) |protocol| {
            connection.protocol = try self.allocator.dupe(u8, protocol);
        }
        
        if (selected_extensions) |extensions| {
            connection.extensions = try self.allocator.dupe(u8, extensions);
        }
        
        try self.connections.put(connection_id, connection);
        
        // Notify connection opened
        if (self.event_handler) |handler| {
            handler(WebSocketEvent.connectionOpen(connection_id));
        }
        
        // Start handling connection frames
        try self.handleConnection(connection);
    }

    fn handleConnection(self: *Self, connection: *WebSocketConnection) !void {
        while (connection.isConnected() and self.running) {
            // Read frames
            const frames = connection.readFrames() catch |err| {
                if (self.event_handler) |handler| {
                    handler(WebSocketEvent.errorOccurred(connection.id, @errorName(err)));
                }
                break;
            };
            defer {
                for (frames) |*frame| {
                    frame.deinit();
                }
                self.allocator.free(frames);
            }
            
            // Process frames
            for (frames) |frame| {
                try self.processFrame(connection, frame);
            }
            
            // Check for ping timeout
            if (connection.isTimedOut(self.config.pong_timeout_ms)) {
                try connection.close(.normal, "Ping timeout");
                break;
            }
            
            // Send ping if needed
            if (connection.needsPing(self.config.ping_interval_ms)) {
                try connection.sendPing("ping");
            }
        }
        
        // Cleanup connection
        _ = self.connections.remove(connection.id);
        connection.deinit();
        self.allocator.destroy(connection);
    }

    fn processFrame(self: *Self, connection: *WebSocketConnection, frame: WebSocketFrame) !void {
        // Validate frame
        frame.validate() catch |err| {
            try connection.close(.protocol_error, @errorName(err));
            return;
        };
        
        switch (frame.opcode) {
            .text, .binary, .continuation => {
                try self.handleDataFrame(connection, frame);
            },
            .close => {
                try self.handleCloseFrame(connection, frame);
            },
            .ping => {
                try self.handlePingFrame(connection, frame);
            },
            .pong => {
                try self.handlePongFrame(connection, frame);
            },
            else => {
                try connection.close(.protocol_error, "Unsupported opcode");
            },
        }
    }

    fn handleDataFrame(self: *Self, connection: *WebSocketConnection, frame: WebSocketFrame) !void {
        if (frame.opcode == .continuation) {
            // Handle continuation frame
            if (connection.partial_message) |*partial| {
                try partial.data.appendSlice(frame.payload);
                
                if (frame.fin) {
                    // Complete message
                    const message = try WebSocketMessage.init(
                        self.allocator,
                        partial.opcode,
                        partial.data.items
                    );
                    
                    if (self.event_handler) |handler| {
                        handler(WebSocketEvent.messageReceived(connection.id, message));
                    }
                    
                    partial.data.deinit();
                    connection.partial_message = null;
                }
            } else {
                try connection.close(.protocol_error, "Continuation frame without initial frame");
            }
        } else {
            // Handle text/binary frame
            if (frame.fin) {
                // Complete message
                const message = try WebSocketMessage.init(self.allocator, frame.opcode, frame.payload);
                
                if (self.event_handler) |handler| {
                    handler(WebSocketEvent.messageReceived(connection.id, message));
                }
            } else {
                // Start fragmented message
                if (connection.partial_message != null) {
                    try connection.close(.protocol_error, "New data frame before completing previous");
                    return;
                }
                
                connection.partial_message = .{
                    .opcode = frame.opcode,
                    .data = std.ArrayList(u8).init(self.allocator),
                };
                
                try connection.partial_message.?.data.appendSlice(frame.payload);
            }
        }
    }

    fn handleCloseFrame(self: *Self, connection: *WebSocketConnection, frame: WebSocketFrame) !void {
        connection.received_close = true;
        
        var close_code = WebSocketCloseCode.normal;
        var close_reason: []const u8 = "";
        
        if (frame.parseCloseFrame()) |close_info| {
            close_code = close_info.code;
            close_reason = close_info.reason;
        }
        
        // Send close frame if we haven't already
        if (!connection.sent_close) {
            try connection.close(close_code, close_reason);
        }
        
        connection.state = .closed;
        
        if (self.event_handler) |handler| {
            handler(WebSocketEvent.connectionClose(connection.id, close_code, close_reason));
        }
    }

    fn handlePingFrame(self: *Self, connection: *WebSocketConnection, frame: WebSocketFrame) !void {
        // Send pong response
        try connection.sendPong(frame.payload);
        
        if (self.event_handler) |handler| {
            handler(WebSocketEvent.pingReceived(connection.id, frame.payload));
        }
    }

    fn handlePongFrame(self: *Self, connection: *WebSocketConnection, frame: WebSocketFrame) !void {
        connection.last_pong = std.time.timestamp();
        
        if (self.event_handler) |handler| {
            handler(WebSocketEvent.pongReceived(connection.id, frame.payload));
        }
    }

    fn selectProtocol(self: Self, requested_protocol: ?[]const u8) ?[]const u8 {
        if (requested_protocol) |protocol| {
            for (self.config.supported_protocols) |supported| {
                if (std.mem.eql(u8, protocol, supported)) {
                    return protocol;
                }
            }
        }
        return null;
    }

    fn selectExtensions(self: Self, requested_extensions: []const []const u8) ?[]const u8 {
        _ = self;
        _ = requested_extensions;
        // Simplified - real implementation would negotiate extensions
        return null;
    }

    pub fn broadcast(self: *Self, opcode: WebSocketOpcode, data: []const u8) void {
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            const connection = entry.value_ptr.*;
            if (connection.isConnected()) {
                switch (opcode) {
                    .text => connection.sendText(data) catch {},
                    .binary => connection.sendBinary(data) catch {},
                    else => {},
                }
            }
        }
    }

    pub fn sendToConnection(self: *Self, connection_id: u64, opcode: WebSocketOpcode, data: []const u8) !void {
        if (self.connections.get(connection_id)) |connection| {
            if (connection.isConnected()) {
                switch (opcode) {
                    .text => try connection.sendText(data),
                    .binary => try connection.sendBinary(data),
                    else => return error.UnsupportedOpcode,
                }
            }
        } else {
            return error.ConnectionNotFound;
        }
    }

    pub fn closeConnection(self: *Self, connection_id: u64, code: WebSocketCloseCode, reason: []const u8) !void {
        if (self.connections.get(connection_id)) |connection| {
            try connection.close(code, reason);
        } else {
            return error.ConnectionNotFound;
        }
    }

    pub fn getConnectionCount(self: Self) u32 {
        return @intCast(self.connections.count());
    }

    pub fn isConnectionOpen(self: Self, connection_id: u64) bool {
        if (self.connections.get(connection_id)) |connection| {
            return connection.isConnected();
        }
        return false;
    }
};

test "WebSocket connection management" {
    const allocator = std.testing.allocator;
    
    const config = WebSocketServerConfig{};
    var server = try WebSocketServer.init(allocator, config);
    defer server.deinit();
    
    try std.testing.expect(server.getConnectionCount() == 0);
}

test "WebSocket message creation" {
    const allocator = std.testing.allocator;
    
    var message = try WebSocketMessage.init(allocator, .text, "Hello WebSocket");
    defer message.deinit();
    
    try std.testing.expect(message.isText());
    try std.testing.expect(std.mem.eql(u8, message.getText(), "Hello WebSocket"));
}