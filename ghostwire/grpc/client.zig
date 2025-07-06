//! gRPC client implementation for Ghostwire
//! Native Zig-based gRPC client with connection pooling and load balancing

const std = @import("std");
const GrpcMessage = @import("server.zig").GrpcMessage;
const GrpcMetadata = @import("server.zig").GrpcMetadata;
const GrpcStatus = @import("server.zig").GrpcStatus;

pub const ClientConfig = struct {
    max_connections: u32 = 10,
    timeout_ms: u32 = 30000,
    keepalive_timeout_ms: u32 = 60000,
    max_retry_attempts: u8 = 3,
    initial_backoff_ms: u32 = 1000,
    max_backoff_ms: u32 = 30000,
    enable_compression: bool = true,
    enable_keepalive: bool = true,
};

pub const CallOptions = struct {
    timeout_ms: ?u32 = null,
    metadata: ?*GrpcMetadata = null,
    retry_policy: ?RetryPolicy = null,
    compression: bool = true,
};

pub const RetryPolicy = struct {
    max_attempts: u8 = 3,
    initial_backoff_ms: u32 = 1000,
    max_backoff_ms: u32 = 30000,
    backoff_multiplier: f32 = 1.5,
    retryable_status_codes: []const GrpcStatus = &[_]GrpcStatus{ .unavailable, .deadline_exceeded },
};

pub const GrpcCall = struct {
    service: []const u8,
    method: []const u8,
    request_data: []const u8,
    response_data: ?[]const u8 = null,
    metadata: GrpcMetadata,
    trailers: GrpcMetadata,
    status: GrpcStatus = .unknown,
    allocator: std.mem.Allocator,
    call_id: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, service: []const u8, method: []const u8, request_data: []const u8) !Self {
        return Self{
            .service = try allocator.dupe(u8, service),
            .method = try allocator.dupe(u8, method),
            .request_data = try allocator.dupe(u8, request_data),
            .metadata = GrpcMetadata.init(allocator),
            .trailers = GrpcMetadata.init(allocator),
            .allocator = allocator,
            .call_id = @intCast(std.time.microTimestamp()),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.service);
        self.allocator.free(self.method);
        self.allocator.free(self.request_data);
        if (self.response_data) |data| {
            self.allocator.free(data);
        }
        self.metadata.deinit();
        self.trailers.deinit();
    }

    pub fn getFullMethod(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "/{s}/{s}", .{ self.service, self.method });
    }

    pub fn isSuccess(self: *const Self) bool {
        return self.status == .ok;
    }
};

pub const ConnectionPool = struct {
    connections: std.ArrayList(*Connection),
    available: std.ArrayList(usize),
    mutex: std.Thread.Mutex = .{},
    allocator: std.mem.Allocator,
    target: []const u8,
    max_size: u32,

    const Self = @This();

    const Connection = struct {
        target: []const u8,
        socket: ?std.net.Stream = null,
        last_used: i64,
        in_use: bool = false,
        healthy: bool = true,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, target: []const u8) !*Connection {
            const conn = try allocator.create(Connection);
            conn.* = .{
                .target = try allocator.dupe(u8, target),
                .last_used = std.time.timestamp(),
                .allocator = allocator,
            };
            return conn;
        }

        pub fn deinit(self: *Connection) void {
            if (self.socket) |socket| {
                socket.close();
            }
            self.allocator.free(self.target);
            self.allocator.destroy(self);
        }

        pub fn connect(self: *Connection) !void {
            if (self.socket != null) return; // Already connected

            // Parse target (simplified)
            var parts = std.mem.split(u8, self.target, ":");
            const host = parts.next() orelse return error.InvalidTarget;
            const port_str = parts.next() orelse "9090";
            const port = try std.fmt.parseInt(u16, port_str, 10);

            const address = try std.net.Address.resolveIp(host, port);
            self.socket = try std.net.tcpConnectToAddress(address);
            self.healthy = true;
        }

        pub fn isExpired(self: *const Connection, timeout_ms: u32) bool {
            const now = std.time.timestamp();
            return (now - self.last_used) > (timeout_ms / 1000);
        }

        pub fn markUsed(self: *Connection) void {
            self.last_used = std.time.timestamp();
            self.in_use = true;
        }

        pub fn release(self: *Connection) void {
            self.in_use = false;
            self.last_used = std.time.timestamp();
        }
    };

    pub fn init(allocator: std.mem.Allocator, target: []const u8, max_size: u32) !Self {
        return Self{
            .connections = std.ArrayList(*Connection).init(allocator),
            .available = std.ArrayList(usize).init(allocator),
            .allocator = allocator,
            .target = try allocator.dupe(u8, target),
            .max_size = max_size,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.connections.items) |conn| {
            conn.deinit();
        }
        self.connections.deinit();
        self.available.deinit();
        self.allocator.free(self.target);
    }

    pub fn getConnection(self: *Self) !*Connection {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Find available connection
        while (self.available.popOrNull()) |index| {
            const conn = self.connections.items[index];
            if (!conn.healthy) continue;
            
            conn.markUsed();
            return conn;
        }

        // Create new connection if under limit
        if (self.connections.items.len < self.max_size) {
            const conn = try Connection.init(self.allocator, self.target);
            try conn.connect();
            try self.connections.append(conn);
            conn.markUsed();
            return conn;
        }

        return error.NoAvailableConnections;
    }

    pub fn releaseConnection(self: *Self, conn: *Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        conn.release();
        
        // Find connection index and mark as available
        for (self.connections.items, 0..) |c, i| {
            if (c == conn) {
                self.available.append(i) catch {}; // Best effort
                break;
            }
        }
    }

    pub fn cleanup(self: *Self, timeout_ms: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var i: usize = 0;
        while (i < self.connections.items.len) {
            const conn = self.connections.items[i];
            if (!conn.in_use and conn.isExpired(timeout_ms)) {
                conn.deinit();
                _ = self.connections.swapRemove(i);
                
                // Remove from available list
                var j: usize = 0;
                while (j < self.available.items.len) {
                    if (self.available.items[j] == i) {
                        _ = self.available.swapRemove(j);
                        break;
                    } else if (self.available.items[j] > i) {
                        self.available.items[j] -= 1;
                    }
                    j += 1;
                }
            } else {
                i += 1;
            }
        }
    }
};

pub const GrpcClient = struct {
    allocator: std.mem.Allocator,
    config: ClientConfig,
    pool: ConnectionPool,
    target: []const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, target: []const u8, config: ClientConfig) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .pool = try ConnectionPool.init(allocator, target, config.max_connections),
            .target = try allocator.dupe(u8, target),
        };
    }

    pub fn deinit(self: *Self) void {
        self.pool.deinit();
        self.allocator.free(self.target);
    }

    pub fn call(self: *Self, service: []const u8, method: []const u8, request_data: []const u8, options: CallOptions) !GrpcCall {
        var grpc_call = try GrpcCall.init(self.allocator, service, method, request_data);
        
        _ = options.timeout_ms orelse self.config.timeout_ms;
        const retry_policy = options.retry_policy orelse RetryPolicy{};

        var attempt: u8 = 0;
        var backoff_ms: u32 = retry_policy.initial_backoff_ms;

        while (attempt < retry_policy.max_attempts) {
            const result = self.executeCall(&grpc_call, options);
            
            if (result) |_| {
                if (grpc_call.isSuccess()) {
                    return grpc_call;
                }
                
                // Check if status is retryable
                var retryable = false;
                for (retry_policy.retryable_status_codes) |status| {
                    if (grpc_call.status == status) {
                        retryable = true;
                        break;
                    }
                }
                
                if (!retryable) {
                    return grpc_call; // Return with error status
                }
            } else |err| {
                std.log.warn("gRPC call attempt {} failed: {}", .{ attempt + 1, err });
            }

            attempt += 1;
            if (attempt < retry_policy.max_attempts) {
                std.time.sleep(backoff_ms * std.time.ns_per_ms);
                backoff_ms = @min(
                    @as(u32, @intFromFloat(@as(f32, @floatFromInt(backoff_ms)) * retry_policy.backoff_multiplier)),
                    retry_policy.max_backoff_ms
                );
            }
        }

        grpc_call.status = .unavailable;
        try grpc_call.trailers.set("grpc-message", "All retry attempts failed");
        return grpc_call;
    }

    fn executeCall(self: *Self, grpc_call: *GrpcCall, options: CallOptions) !void {
        const conn = try self.pool.getConnection();
        defer self.pool.releaseConnection(conn);

        // Create gRPC message
        const message = try GrpcMessage.init(self.allocator, grpc_call.request_data);
        defer message.deinit();

        const encoded_message = try message.encode(self.allocator);
        defer self.allocator.free(encoded_message);

        // Build HTTP/2 request (simplified)
        const method_path = try grpc_call.getFullMethod(self.allocator);
        defer self.allocator.free(method_path);

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit();

        // HTTP/2 headers (simplified - real implementation would use proper HPACK)
        try request.writer().print("POST {s} HTTP/2.0\r\n", .{method_path});
        try request.appendSlice("content-type: application/grpc\r\n");
        try request.writer().print("content-length: {}\r\n", .{encoded_message.len});
        
        // Add user metadata
        if (options.metadata) |metadata| {
            var iter = metadata.headers.iterator();
            while (iter.next()) |entry| {
                try request.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            }
        }

        try request.appendSlice("\r\n");
        try request.appendSlice(encoded_message);

        // Send request
        if (conn.socket) |socket| {
            _ = try socket.writeAll(request.items);

            // Read response (simplified)
            var response_buffer: [8192]u8 = undefined;
            const bytes_read = try socket.read(&response_buffer);
            
            if (bytes_read > 0) {
                try self.parseResponse(grpc_call, response_buffer[0..bytes_read]);
            }
        }
    }

    fn parseResponse(self: *Self, grpc_call: *GrpcCall, response_data: []const u8) !void {
        // Simplified response parsing - real implementation would properly parse HTTP/2 frames
        _ = self;

        // Look for grpc-status
        if (std.mem.indexOf(u8, response_data, "grpc-status: ")) |status_start| {
            const status_line_start = status_start + "grpc-status: ".len;
            const status_line_end = std.mem.indexOfScalarPos(u8, response_data, status_line_start, '\r') orelse response_data.len;
            const status_str = response_data[status_line_start..status_line_end];
            
            const status_code = std.fmt.parseInt(u32, status_str, 10) catch 0;
            grpc_call.status = @enumFromInt(status_code);
        }

        // Look for response body (after \r\n\r\n)
        if (std.mem.indexOf(u8, response_data, "\r\n\r\n")) |body_start| {
            const body_data = response_data[body_start + 4..];
            if (body_data.len > 5) { // Minimum gRPC message size
                const decoded_message = GrpcMessage.decode(grpc_call.allocator, body_data) catch return;
                grpc_call.response_data = try grpc_call.allocator.dupe(u8, decoded_message.data);
            }
        }
    }

    pub fn cleanup(self: *Self) void {
        self.pool.cleanup(self.config.keepalive_timeout_ms);
    }

    // Convenience methods for common patterns
    pub fn unaryCall(self: *Self, service: []const u8, method: []const u8, request: anytype) ![]u8 {
        const request_data = try std.json.stringifyAlloc(self.allocator, request, .{});
        defer self.allocator.free(request_data);

        var grpc_call_result = try self.call(service, method, request_data, .{});
        defer grpc_call_result.deinit();

        if (!grpc_call_result.isSuccess()) {
            return error.GrpcCallFailed;
        }

        return if (grpc_call_result.response_data) |data| 
            try self.allocator.dupe(u8, data)
        else 
            error.NoResponseData;
    }

    pub fn streamingCall(self: *Self, service: []const u8, method: []const u8) !StreamingCall {
        return StreamingCall.init(self.allocator, self, service, method);
    }
};

pub const StreamingCall = struct {
    allocator: std.mem.Allocator,
    client: *GrpcClient,
    service: []const u8,
    method: []const u8,
    connection: ?*ConnectionPool.Connection = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, client: *GrpcClient, service: []const u8, method: []const u8) !Self {
        return Self{
            .allocator = allocator,
            .client = client,
            .service = try allocator.dupe(u8, service),
            .method = try allocator.dupe(u8, method),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.connection) |conn| {
            self.client.pool.releaseConnection(conn);
        }
        self.allocator.free(self.service);
        self.allocator.free(self.method);
    }

    pub fn send(self: *Self, data: []const u8) !void {
        if (self.connection == null) {
            self.connection = try self.client.pool.getConnection();
        }
        
        // Send streaming message (implementation would manage HTTP/2 stream)
        _ = data;
        // Implementation here
    }

    pub fn receive(_: *Self) !?[]u8 {
        // Receive streaming message
        // Implementation here
        return null;
    }

    pub fn close(self: *Self) !void {
        // Close streaming call
        if (self.connection) |conn| {
            self.client.pool.releaseConnection(conn);
            self.connection = null;
        }
    }
};

test "gRPC client connection pool" {
    const allocator = std.testing.allocator;
    
    var pool = try ConnectionPool.init(allocator, "localhost:9090", 5);
    defer pool.deinit();
    
    // This would normally require a running server
    // const conn = try pool.getConnection();
    // defer pool.releaseConnection(conn);
    
    try std.testing.expect(pool.max_size == 5);
}

test "gRPC call creation" {
    const allocator = std.testing.allocator;
    
    var call = try GrpcCall.init(allocator, "test.Service", "TestMethod", "test data");
    defer call.deinit();
    
    try std.testing.expect(std.mem.eql(u8, call.service, "test.Service"));
    try std.testing.expect(std.mem.eql(u8, call.method, "TestMethod"));
    try std.testing.expect(call.status == .unknown);
}