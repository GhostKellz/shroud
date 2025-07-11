//! gRPC server implementation for Ghostwire
//! Native Zig-based gRPC (ZRPC) with QUIC and HTTP/2 transport support
//! Interoperates with Rust nodes and WASM environments

const std = @import("std");
const Http2Server = @import("../http2/server.zig").Http2Server;

pub const GrpcConfig = struct {
    address: []const u8 = "0.0.0.0",
    port: u16 = 9090,
    max_connections: u32 = 1000,
    max_message_size: usize = 4 * 1024 * 1024, // 4MB
    enable_reflection: bool = true,
    enable_health_check: bool = true,
    transport: Transport = .http2,
    // FFI-compatible extensions
    request_timeout_ms: u32 = 30000,
    enable_discovery: bool = true,
    enable_post_quantum: bool = true,
};

pub const Transport = enum {
    http2,
    quic,   // gRPC over QUIC (experimental)
};

pub const GrpcStatus = enum(u32) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,

    pub fn toString(self: GrpcStatus) []const u8 {
        return switch (self) {
            .ok => "OK",
            .cancelled => "CANCELLED",
            .unknown => "UNKNOWN",
            .invalid_argument => "INVALID_ARGUMENT",
            .deadline_exceeded => "DEADLINE_EXCEEDED",
            .not_found => "NOT_FOUND",
            .already_exists => "ALREADY_EXISTS",
            .permission_denied => "PERMISSION_DENIED",
            .resource_exhausted => "RESOURCE_EXHAUSTED",
            .failed_precondition => "FAILED_PRECONDITION",
            .aborted => "ABORTED",
            .out_of_range => "OUT_OF_RANGE",
            .unimplemented => "UNIMPLEMENTED",
            .internal => "INTERNAL",
            .unavailable => "UNAVAILABLE",
            .data_loss => "DATA_LOSS",
            .unauthenticated => "UNAUTHENTICATED",
        };
    }
};

pub const GrpcMetadata = struct {
    headers: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .headers = std.StringHashMap([]const u8).init(allocator),
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
    }

    pub fn set(self: *Self, key: []const u8, value: []const u8) !void {
        const owned_key = try self.allocator.dupe(u8, key);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.headers.put(owned_key, owned_value);
    }

    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        return self.headers.get(key);
    }
};

pub const GrpcMessage = struct {
    data: []const u8,
    compressed: bool = false,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, data: []const u8) !Self {
        return Self{
            .data = try allocator.dupe(u8, data),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }

    pub fn encode(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        // gRPC message format: [Compressed-Flag][Message-Length][Message]
        var encoded = try allocator.alloc(u8, 5 + self.data.len);
        
        // Compressed flag (1 byte)
        encoded[0] = if (self.compressed) 1 else 0;
        
        // Message length (4 bytes, big-endian)
        std.mem.writeInt(u32, encoded[1..5], @intCast(self.data.len), .big);
        
        // Message data
        @memcpy(encoded[5..], self.data);
        
        return encoded;
    }

    pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) !Self {
        if (encoded.len < 5) return error.InvalidMessage;
        
        const compressed = encoded[0] != 0;
        const length = std.mem.readInt(u32, encoded[1..5], .big);
        
        if (encoded.len < 5 + length) return error.IncompleteMessage;
        
        const data = try allocator.dupe(u8, encoded[5..5 + length]);
        
        return Self{
            .data = data,
            .compressed = compressed,
            .allocator = allocator,
        };
    }
};

pub const GrpcRequest = struct {
    service: []const u8,
    method: []const u8,
    metadata: GrpcMetadata,
    message: ?GrpcMessage,
    stream_id: u64,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, service: []const u8, method: []const u8, stream_id: u64) !Self {
        return Self{
            .service = try allocator.dupe(u8, service),
            .method = try allocator.dupe(u8, method),
            .metadata = GrpcMetadata.init(allocator),
            .message = null,
            .stream_id = stream_id,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.service);
        self.allocator.free(self.method);
        self.metadata.deinit();
        if (self.message) |*msg| {
            msg.deinit();
        }
    }

    pub fn setMessage(self: *Self, data: []const u8) !void {
        if (self.message) |*msg| {
            msg.deinit();
        }
        self.message = try GrpcMessage.init(self.allocator, data);
    }

    pub fn getFullMethod(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "/{s}/{s}", .{ self.service, self.method });
    }
};

pub const GrpcResponse = struct {
    status: GrpcStatus,
    message: ?GrpcMessage,
    metadata: GrpcMetadata,
    trailers: GrpcMetadata,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .status = .ok,
            .message = null,
            .metadata = GrpcMetadata.init(allocator),
            .trailers = GrpcMetadata.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.message) |*msg| {
            msg.deinit();
        }
        self.metadata.deinit();
        self.trailers.deinit();
    }

    pub fn setMessage(self: *Self, data: []const u8) !void {
        if (self.message) |*msg| {
            msg.deinit();
        }
        self.message = try GrpcMessage.init(self.allocator, data);
    }

    pub fn setStatus(self: *Self, status: GrpcStatus) void {
        self.status = status;
    }

    pub fn setError(self: *Self, status: GrpcStatus, message: []const u8) !void {
        self.status = status;
        try self.trailers.set("grpc-message", message);
    }
};

pub const GrpcServiceHandler = *const fn (*GrpcRequest, *GrpcResponse) anyerror!void;

pub const GrpcService = struct {
    name: []const u8,
    methods: std.StringHashMap(GrpcServiceHandler),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, name: []const u8) !Self {
        return Self{
            .name = try allocator.dupe(u8, name),
            .methods = std.StringHashMap(GrpcServiceHandler).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.name);
        var iterator = self.methods.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.methods.deinit();
    }

    pub fn addMethod(self: *Self, method_name: []const u8, handler: GrpcServiceHandler) !void {
        const owned_name = try self.allocator.dupe(u8, method_name);
        try self.methods.put(owned_name, handler);
    }

    pub fn getHandler(self: *const Self, method_name: []const u8) ?GrpcServiceHandler {
        return self.methods.get(method_name);
    }
};

// Service registration and discovery types
pub const ServiceType = enum {
    ghostd,
    walletd,
    edge_node,
    other,
};

pub const HealthStatus = enum {
    unknown,
    healthy,
    unhealthy,
    maintenance,
};

pub const RegisteredService = struct {
    name: []const u8,
    endpoint: []const u8,
    service_type: ServiceType,
    health_status: HealthStatus,
    last_health_check: i64,
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8, endpoint: []const u8, service_type: ServiceType) !RegisteredService {
        return RegisteredService{
            .name = try allocator.dupe(u8, name),
            .endpoint = try allocator.dupe(u8, endpoint),
            .service_type = service_type,
            .health_status = .unknown,
            .last_health_check = std.time.timestamp(),
        };
    }
    
    pub fn deinit(self: *RegisteredService, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.endpoint);
    }
};

pub const ServerStats = struct {
    total_connections: u64 = 0,
    active_connections: u32 = 0,
    requests_handled: u64 = 0,
    errors: u64 = 0,
};

pub const GrpcServer = struct {
    allocator: std.mem.Allocator,
    config: GrpcConfig,
    services: std.StringHashMap(*GrpcService),
    registered_services: std.StringHashMap(RegisteredService),
    http2_server: ?Http2Server = null,
    running: bool = false,
    stats: ServerStats = .{},

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: GrpcConfig) !Self {
        var server = Self{
            .allocator = allocator,
            .config = config,
            .services = std.StringHashMap(*GrpcService).init(allocator),
            .registered_services = std.StringHashMap(RegisteredService).init(allocator),
        };

        // Initialize HTTP/2 transport
        if (config.transport == .http2) {
            const http2_config = @import("../http2/server.zig").ServerConfig{
                .address = config.address,
                .port = config.port,
                .max_connections = config.max_connections,
            };
            server.http2_server = try Http2Server.init(allocator, http2_config);
        }

        // Add built-in services
        if (config.enable_health_check) {
            try server.addHealthService();
        }

        if (config.enable_reflection) {
            try server.addReflectionService();
        }

        return server;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        
        var iterator = self.services.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.services.deinit();
        
        var reg_iterator = self.registered_services.iterator();
        while (reg_iterator.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.registered_services.deinit();

        if (self.http2_server) |*server| {
            server.deinit();
        }
    }

    pub fn addService(self: *Self, service: *GrpcService) !void {
        const owned_name = try self.allocator.dupe(u8, service.name);
        try self.services.put(owned_name, service);
    }

    pub fn start(self: *Self) !void {
        self.running = true;
        std.log.info("gRPC server listening on {}:{}", .{ self.config.address, self.config.port });

        switch (self.config.transport) {
            .http2 => {
                if (self.http2_server) |*server| {
                    try server.start();
                }
            },
            .quic => {
                // QUIC transport implementation would go here
                return error.NotImplemented;
            },
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        
        if (self.http2_server) |*server| {
            server.stop();
        }
    }

    fn addHealthService(self: *Self) !void {
        const health_service = try self.allocator.create(GrpcService);
        health_service.* = try GrpcService.init(self.allocator, "grpc.health.v1.Health");
        
        try health_service.addMethod("Check", healthCheckHandler);
        try health_service.addMethod("Watch", healthWatchHandler);
        
        try self.addService(health_service);
    }

    fn addReflectionService(self: *Self) !void {
        const reflection_service = try self.allocator.create(GrpcService);
        reflection_service.* = try GrpcService.init(self.allocator, "grpc.reflection.v1alpha.ServerReflection");
        
        try reflection_service.addMethod("ServerReflectionInfo", reflectionHandler);
        
        try self.addService(reflection_service);
    }

    fn handleGrpcRequest(self: *Self, service_name: []const u8, method_name: []const u8, request_data: []const u8, stream_id: u64) !GrpcResponse {
        // Find service
        const service = self.services.get(service_name) orelse {
            var response = GrpcResponse.init(self.allocator);
            try response.setError(.not_found, "Service not found");
            return response;
        };

        // Find method handler
        const handler = service.getHandler(method_name) orelse {
            var response = GrpcResponse.init(self.allocator);
            try response.setError(.unimplemented, "Method not implemented");
            return response;
        };

        // Create request
        var request = try GrpcRequest.init(self.allocator, service_name, method_name, stream_id);
        defer request.deinit();
        
        try request.setMessage(request_data);

        // Create response
        var response = GrpcResponse.init(self.allocator);

        // Execute handler
        handler(&request, &response) catch |err| {
            response.setStatus(.internal);
            try response.trailers.set("grpc-message", @errorName(err));
        };

        return response;
    }

    fn parseGrpcPath(path: []const u8) ?struct { service: []const u8, method: []const u8 } {
        // gRPC path format: /{service}/{method}
        if (!std.mem.startsWith(u8, path, "/")) return null;
        
        const without_prefix = path[1..];
        if (std.mem.indexOf(u8, without_prefix, "/")) |slash_pos| {
            return .{
                .service = without_prefix[0..slash_pos],
                .method = without_prefix[slash_pos + 1..],
            };
        }
        
        return null;
    }
    
    // FFI-compatible methods
    pub fn registerService(self: *Self, name: []const u8, endpoint: []const u8, service_type: ServiceType) !void {
        const registered_service = try RegisteredService.init(self.allocator, name, endpoint, service_type);
        const owned_name = try self.allocator.dupe(u8, name);
        try self.registered_services.put(owned_name, registered_service);
    }
    
    pub fn unregisterService(self: *Self, name: []const u8) !void {
        if (self.registered_services.fetchRemove(name)) |kv| {
            var value = kv.value;
            value.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }
    
    pub fn createConnection(self: *Self, service_name: []const u8) !*GrpcConnection {
        _ = service_name;
        // Create a new connection - this would typically create a client connection
        const connection = try self.allocator.create(GrpcConnection);
        connection.* = GrpcConnection{
            .connection_id = @intCast(std.time.microTimestamp()),
            .allocator = self.allocator,
        };
        return connection;
    }
    
    pub fn getServices(self: *Self) []RegisteredService {
        var services = self.allocator.alloc(RegisteredService, self.registered_services.count()) catch return &[_]RegisteredService{};
        var i: usize = 0;
        var iterator = self.registered_services.iterator();
        while (iterator.next()) |entry| {
            services[i] = entry.value_ptr.*;
            i += 1;
        }
        return services;
    }
    
    pub fn checkServiceHealth(self: *Self, service_name: []const u8) HealthStatus {
        if (self.registered_services.get(service_name)) |service| {
            return service.health_status;
        }
        return .unknown;
    }
    
    pub fn updateStats(self: *Self) void {
        // Update statistics - would typically collect from actual connections
        self.stats.total_connections += 1;
    }
};

// Connection type for FFI compatibility
pub const GrpcConnection = struct {
    connection_id: u64,
    allocator: std.mem.Allocator,
    
    pub fn sendUnaryRequest(self: *GrpcConnection, method: GrpcMethod, request_data: []const u8) !GrpcResponseInternal {
        _ = method;
        _ = request_data;
        // Mock implementation - would send actual request
        return GrpcResponseInternal{
            .body = try self.allocator.dupe(u8, "mock response"),
            .status_code = 0,
            .status_message = try self.allocator.dupe(u8, "OK"),
            .response_id = self.connection_id,
        };
    }
    
    pub fn createStream(self: *GrpcConnection, method: GrpcMethod) !*GrpcStream {
        _ = method;
        const stream = try self.allocator.create(GrpcStream);
        stream.* = GrpcStream{
            .stream_id = @intCast(std.time.microTimestamp()),
            .allocator = self.allocator,
        };
        return stream;
    }
};

// Method type for FFI compatibility
pub const GrpcMethod = struct {
    service: []const u8,
    method: []const u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, service: []const u8, method: []const u8) !GrpcMethod {
        return GrpcMethod{
            .service = try allocator.dupe(u8, service),
            .method = try allocator.dupe(u8, method),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: GrpcMethod, allocator: std.mem.Allocator) void {
        allocator.free(self.service);
        allocator.free(self.method);
    }
};

// Response type for FFI compatibility
pub const GrpcResponseInternal = struct {
    body: []const u8,
    status_code: u32,
    status_message: []const u8,
    response_id: u64,
};

// Stream type for FFI compatibility
pub const GrpcStream = struct {
    stream_id: u64,
    allocator: std.mem.Allocator,
    
    pub const MessageType = enum {
        stream_data,
        stream_end,
    };
    
    pub const StreamMessage = struct {
        message_type: MessageType,
        data: []const u8,
        allocator: std.mem.Allocator,
        
        pub fn deinit(self: *StreamMessage, allocator: std.mem.Allocator) void {
            allocator.free(self.data);
        }
    };
    
    pub fn sendMessage(self: *GrpcStream, message_type: MessageType, data: []const u8) !void {
        _ = self;
        _ = message_type;
        _ = data;
        // Mock implementation
    }
    
    pub fn receiveMessage(self: *GrpcStream) !StreamMessage {
        // Mock implementation
        return StreamMessage{
            .message_type = .stream_data,
            .data = try self.allocator.dupe(u8, "mock stream data"),
            .allocator = self.allocator,
        };
    }
    
    pub fn close(self: *GrpcStream) !void {
        _ = self;
        // Mock implementation
    }
};

// Built-in service handlers
fn healthCheckHandler(request: *GrpcRequest, response: *GrpcResponse) !void {
    _ = request;
    
    // Simple health check response (would normally check actual service health)
    const health_response = "{\"status\": \"SERVING\"}";
    try response.setMessage(health_response);
    response.setStatus(.ok);
}

fn healthWatchHandler(request: *GrpcRequest, response: *GrpcResponse) !void {
    _ = request;
    
    // Health watch streaming (simplified)
    response.setStatus(.unimplemented);
    try response.trailers.set("grpc-message", "Health watch not implemented");
}

fn reflectionHandler(request: *GrpcRequest, response: *GrpcResponse) !void {
    _ = request;
    
    // Server reflection (simplified)
    response.setStatus(.unimplemented);
    try response.trailers.set("grpc-message", "Reflection not fully implemented");
}

// Protobuf serialization helpers (simplified)
pub const Protobuf = struct {
    pub fn encode(allocator: std.mem.Allocator, data: anytype) ![]u8 {
        // Simplified protobuf encoding - in production, use a proper protobuf library
        const json_str = try std.json.stringifyAlloc(allocator, data, .{});
        return json_str;
    }

    pub fn decode(comptime T: type, allocator: std.mem.Allocator, data: []const u8) !T {
        // Simplified protobuf decoding - in production, use a proper protobuf library
        return std.json.parseFromSlice(T, allocator, data, .{});
    }
};

// Example service implementation
pub const EchoService = struct {
    const Self = @This();

    pub fn createService(allocator: std.mem.Allocator) !*GrpcService {
        const service = try allocator.create(GrpcService);
        service.* = try GrpcService.init(allocator, "echo.EchoService");
        
        try service.addMethod("Echo", echoHandler);
        try service.addMethod("EchoStream", echoStreamHandler);
        
        return service;
    }

    fn echoHandler(request: *GrpcRequest, response: *GrpcResponse) !void {
        if (request.message) |msg| {
            // Echo back the same message
            try response.setMessage(msg.data);
            response.setStatus(.ok);
        } else {
            response.setStatus(.invalid_argument);
            try response.trailers.set("grpc-message", "No message provided");
        }
    }

    fn echoStreamHandler(request: *GrpcRequest, response: *GrpcResponse) !void {
        _ = request;
        
        // Streaming echo (simplified)
        response.setStatus(.unimplemented);
        try response.trailers.set("grpc-message", "Streaming not implemented");
    }
};

test "gRPC message encoding/decoding" {
    const allocator = std.testing.allocator;
    
    const original_data = "Hello, gRPC!";
    var message = try GrpcMessage.init(allocator, original_data);
    defer message.deinit();
    
    const encoded = try message.encode(allocator);
    defer allocator.free(encoded);
    
    var decoded = try GrpcMessage.decode(allocator, encoded);
    defer decoded.deinit();
    
    try std.testing.expect(std.mem.eql(u8, decoded.data, original_data));
    try std.testing.expect(decoded.compressed == message.compressed);
}

test "gRPC service registration" {
    const allocator = std.testing.allocator;
    
    const config = GrpcConfig{};
    var server = try GrpcServer.init(allocator, config);
    defer server.deinit();
    
    const echo_service = try EchoService.createService(allocator);
    try server.addService(echo_service);
    
    try std.testing.expect(server.services.count() >= 1); // At least echo service (plus built-ins)
}