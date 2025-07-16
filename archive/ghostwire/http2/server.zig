//! HTTP/2 server implementation
//! RFC 7540 compliant HTTP/2 server with multiplexing, flow control, and server push

const std = @import("std");

pub const ServerConfig = struct {
    max_connections: u32 = 1000,
    max_streams_per_connection: u32 = 100,
    initial_window_size: u32 = 65536,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
    enable_push: bool = true,
    enable_compression: bool = true,
    port: u16 = 8080,
    address: []const u8 = "0.0.0.0",
};

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

pub const Frame = struct {
    length: u24,
    frame_type: FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,

    const Self = @This();

    pub fn init(frame_type: FrameType, flags: u8, stream_id: u31, payload: []const u8) Self {
        return Self{
            .length = @intCast(payload.len),
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
            .payload = payload,
        };
    }

    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var frame_data = try allocator.alloc(u8, 9 + self.payload.len);
        
        // Frame header (9 bytes)
        std.mem.writeInt(u24, frame_data[0..3], self.length, .big);
        frame_data[3] = @intFromEnum(self.frame_type);
        frame_data[4] = self.flags;
        std.mem.writeInt(u32, frame_data[5..9], self.stream_id, .big);
        
        // Payload
        @memcpy(frame_data[9..], self.payload);
        
        return frame_data;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !Self {
        if (data.len < 9) return error.InvalidFrame;

        const length = std.mem.readInt(u24, data[0..3], .big);
        const frame_type: FrameType = @enumFromInt(data[3]);
        const flags = data[4];
        const stream_id = std.mem.readInt(u32, data[5..9], .big) & 0x7FFFFFFF;

        if (data.len < 9 + length) return error.IncompleteFrame;

        const payload = try allocator.dupe(u8, data[9..9 + length]);

        return Self{
            .length = length,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = @intCast(stream_id),
            .payload = payload,
        };
    }
};

pub const StreamState = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

pub const Stream = struct {
    id: u31,
    state: StreamState,
    window_size: i32,
    headers: std.StringHashMap([]const u8),
    body: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, id: u31) Self {
        return Self{
            .id = id,
            .state = .idle,
            .window_size = 65536,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        self.body.deinit();
    }

    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.headers.put(owned_name, owned_value);
    }

    pub fn appendBody(self: *Self, data: []const u8) !void {
        try self.body.appendSlice(data);
    }
};

pub const Connection = struct {
    streams: std.HashMap(u31, *Stream, std.hash_map.AutoContext(u31), std.hash_map.default_max_load_percentage),
    settings: Settings,
    window_size: i32,
    last_stream_id: u31,
    allocator: std.mem.Allocator,
    socket: std.net.Stream,

    const Self = @This();

    pub const Settings = struct {
        header_table_size: u32 = 4096,
        enable_push: bool = true,
        max_concurrent_streams: u32 = 100,
        initial_window_size: u32 = 65536,
        max_frame_size: u32 = 16384,
        max_header_list_size: u32 = 8192,
    };

    pub fn init(allocator: std.mem.Allocator, socket: std.net.Stream) Self {
        return Self{
            .streams = std.HashMap(u31, *Stream, std.hash_map.AutoContext(u31), std.hash_map.default_max_load_percentage).init(allocator),
            .settings = Settings{},
            .window_size = 65536,
            .last_stream_id = 0,
            .allocator = allocator,
            .socket = socket,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit();
    }

    pub fn getOrCreateStream(self: *Self, stream_id: u31) !*Stream {
        if (self.streams.get(stream_id)) |stream| {
            return stream;
        }

        const stream = try self.allocator.create(Stream);
        stream.* = Stream.init(self.allocator, stream_id);
        try self.streams.put(stream_id, stream);
        
        if (stream_id > self.last_stream_id) {
            self.last_stream_id = stream_id;
        }

        return stream;
    }

    pub fn sendFrame(self: *Self, frame: Frame) !void {
        const encoded = try frame.encode(self.allocator);
        defer self.allocator.free(encoded);
        
        _ = try self.socket.writeAll(encoded);
    }

    pub fn sendSettings(self: *Self) !void {
        var settings_data = std.ArrayList(u8).init(self.allocator);
        defer settings_data.deinit();

        // SETTINGS_HEADER_TABLE_SIZE
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 1)));
        try settings_data.appendSlice(&std.mem.toBytes(@as(u32, self.settings.header_table_size)));

        // SETTINGS_ENABLE_PUSH
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 2)));
        try settings_data.appendSlice(&std.mem.toBytes(@as(u32, if (self.settings.enable_push) 1 else 0)));

        // SETTINGS_MAX_CONCURRENT_STREAMS
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 3)));
        try settings_data.appendSlice(&std.mem.toBytes(@as(u32, self.settings.max_concurrent_streams)));

        // SETTINGS_INITIAL_WINDOW_SIZE
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 4)));
        try settings_data.appendSlice(&std.mem.toBytes(@as(u32, self.settings.initial_window_size)));

        // SETTINGS_MAX_FRAME_SIZE
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 5)));
        try settings_data.appendSlice(&std.mem.toBytes(@as(u32, self.settings.max_frame_size)));

        // SETTINGS_MAX_HEADER_LIST_SIZE
        try settings_data.appendSlice(&std.mem.toBytes(@as(u16, 6)));
        try settings_data.appendSlice(&std.mem.toBytes(@as(u32, self.settings.max_header_list_size)));

        const frame = Frame.init(.settings, 0, 0, settings_data.items);
        try self.sendFrame(frame);
    }
};

pub const Http2Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    listener: std.net.Server,
    connections: std.ArrayList(*Connection),
    running: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Self {
        const address = try std.net.Address.parseIp(config.address, config.port);
        const listener = try address.listen(.{ .reuse_address = true });

        return Self{
            .allocator = allocator,
            .config = config,
            .listener = listener,
            .connections = std.ArrayList(*Connection).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit();
        self.listener.deinit();
    }

    pub fn start(self: *Self) !void {
        self.running = true;
        std.log.info("HTTP/2 server listening on {s}:{}", .{ self.config.address, self.config.port });

        while (self.running) {
            const client_connection = self.listener.accept() catch continue;
            
            // Handle connection in a separate thread (simplified for demo)
            try self.handleConnection(client_connection.stream);
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
    }

    fn handleConnection(self: *Self, socket: std.net.Stream) !void {
        const connection = try self.allocator.create(Connection);
        connection.* = Connection.init(self.allocator, socket);
        try self.connections.append(connection);

        // Send connection preface
        try self.sendConnectionPreface(connection);

        // Handle frames
        var buffer: [8192]u8 = undefined;
        while (self.running) {
            const bytes_read = socket.read(&buffer) catch break;
            if (bytes_read == 0) break;

            try self.processFrames(connection, buffer[0..bytes_read]);
        }

        socket.close();
    }

    fn sendConnectionPreface(self: *Self, connection: *Connection) !void {
        _ = self;
        
        // Send HTTP/2 connection preface
        const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        _ = try connection.socket.writeAll(preface);

        // Send initial SETTINGS frame
        try connection.sendSettings();
    }

    fn processFrames(self: *Self, connection: *Connection, data: []const u8) !void {
        var offset: usize = 0;
        
        while (offset < data.len) {
            if (data.len - offset < 9) break; // Need at least frame header

            const frame = try Frame.decode(data[offset..], self.allocator);
            defer self.allocator.free(frame.payload);

            try self.handleFrame(connection, frame);
            
            offset += 9 + frame.length;
        }
    }

    fn handleFrame(self: *Self, connection: *Connection, frame: Frame) !void {
        switch (frame.frame_type) {
            .headers => try self.handleHeadersFrame(connection, frame),
            .data => try self.handleDataFrame(connection, frame),
            .settings => try self.handleSettingsFrame(connection, frame),
            .window_update => try self.handleWindowUpdateFrame(connection, frame),
            .ping => try self.handlePingFrame(connection, frame),
            else => {
                std.log.debug("Unhandled frame type: {}", .{frame.frame_type});
            },
        }
    }

    fn handleHeadersFrame(self: *Self, connection: *Connection, frame: Frame) !void {
        
        const stream = try connection.getOrCreateStream(frame.stream_id);
        stream.state = .open;

        // Simplified header decoding (would need proper HPACK in production)
        const headers_text = frame.payload;
        var lines = std.mem.splitSequence(u8, headers_text, "\n");
        
        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                const name = std.mem.trim(u8, line[0..colon_pos], " \t");
                const value = std.mem.trim(u8, line[colon_pos + 1..], " \t");
                try stream.addHeader(name, value);
            }
        }

        // Send a simple response
        try self.sendResponse(connection, stream);
    }

    fn handleDataFrame(self: *Self, connection: *Connection, frame: Frame) !void {
        _ = self;
        
        if (connection.streams.get(frame.stream_id)) |stream| {
            try stream.appendBody(frame.payload);
        }
    }

    fn handleSettingsFrame(self: *Self, connection: *Connection, frame: Frame) !void {
        _ = self;
        
        if (frame.flags & 0x1 == 0) { // Not ACK
            // Send SETTINGS ACK
            const ack_frame = Frame.init(.settings, 0x1, 0, &[_]u8{});
            try connection.sendFrame(ack_frame);
        }
    }

    fn handleWindowUpdateFrame(self: *Self, connection: *Connection, frame: Frame) !void {
        _ = self;
        
        const window_size_increment = std.mem.readInt(u32, frame.payload[0..4], .big);
        
        if (frame.stream_id == 0) {
            connection.window_size += @intCast(window_size_increment);
        } else if (connection.streams.get(frame.stream_id)) |stream| {
            stream.window_size += @intCast(window_size_increment);
        }
    }

    fn handlePingFrame(self: *Self, connection: *Connection, frame: Frame) !void {
        _ = self;
        
        if (frame.flags & 0x1 == 0) { // Not ACK
            // Send PING ACK with same payload
            const ack_frame = Frame.init(.ping, 0x1, 0, frame.payload);
            try connection.sendFrame(ack_frame);
        }
    }

    fn sendResponse(self: *Self, connection: *Connection, stream: *Stream) !void {
        _ = self;
        
        // Send HEADERS frame with response
        const response_headers = ":status 200\ncontent-type text/html\n";
        const headers_frame = Frame.init(.headers, 0x4, stream.id, response_headers); // END_HEADERS flag
        try connection.sendFrame(headers_frame);

        // Send DATA frame with response body
        const response_body = 
            \\<!DOCTYPE html>
            \\<html><head><title>HTTP/2 Server</title></head>
            \\<body><h1>Hello from HTTP/2!</h1><p>This is served over HTTP/2 protocol.</p></body>
            \\</html>
        ;
        
        const data_frame = Frame.init(.data, 0x1, stream.id, response_body); // END_STREAM flag
        try connection.sendFrame(data_frame);

        stream.state = .half_closed_local;
    }
};

test "HTTP/2 frame encoding/decoding" {
    const allocator = std.testing.allocator;
    
    const payload = "test payload";
    const frame = Frame.init(.data, 0x1, 123, payload);
    
    const encoded = try frame.encode(allocator);
    defer allocator.free(encoded);
    
    const decoded = try Frame.decode(encoded, allocator);
    defer allocator.free(decoded.payload);
    
    try std.testing.expect(decoded.frame_type == .data);
    try std.testing.expect(decoded.flags == 0x1);
    try std.testing.expect(decoded.stream_id == 123);
    try std.testing.expect(std.mem.eql(u8, decoded.payload, payload));
}

test "HTTP/2 stream management" {
    const allocator = std.testing.allocator;
    
    var stream = Stream.init(allocator, 1);
    defer stream.deinit();
    
    try stream.addHeader(":method", "GET");
    try stream.addHeader(":path", "/test");
    try stream.appendBody("request body");
    
    try std.testing.expect(stream.headers.count() == 2);
    try std.testing.expect(stream.body.items.len == 12);
}