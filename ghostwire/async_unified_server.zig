//! GhostWire Async Unified Server - Local async powered
//! High-performance async server supporting HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket

const std = @import("std");
const async_local = @import("async_local.zig");
const ghostwire_async = @import("async_core.zig");

const AsyncRuntime = async_local.AsyncRuntime;
const AsyncServerCore = ghostwire_async.AsyncServerCore;

/// Async unified server configuration
pub const AsyncUnifiedServerConfig = struct {
    bind_address: []const u8 = "0.0.0.0",
    http_port: u16 = 8080,
    https_port: u16 = 8443,
    quic_port: u16 = 8443, // QUIC usually shares port with HTTPS
    grpc_port: u16 = 9090,
    websocket_port: u16 = 8081,

    max_connections: u32 = 10000,
    connection_timeout_ms: u32 = 30000,
    keep_alive_timeout_ms: u32 = 60000,
    max_request_size: u32 = 10 * 1024 * 1024, // 10MB

    enable_http1: bool = true,
    enable_http2: bool = true,
    enable_http3: bool = true,
    enable_grpc: bool = true,
    enable_websocket: bool = true,
    enable_tls: bool = true,

    worker_threads: u32 = 0, // 0 = auto-detect CPU count
    io_threads: u32 = 0, // 0 = auto-detect CPU count

    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
};

/// HTTP request/response types for async handling
pub const AsyncHttpRequest = struct {
    method: []const u8,
    path: []const u8,
    version: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    connection_id: u64,

    pub fn init(allocator: std.mem.Allocator, connection_id: u64) AsyncHttpRequest {
        return AsyncHttpRequest{
            .method = "",
            .path = "",
            .version = "",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .connection_id = connection_id,
        };
    }

    pub fn deinit(self: *AsyncHttpRequest) void {
        self.headers.deinit();
    }

    pub fn getHeader(self: *const AsyncHttpRequest, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    pub fn isWebSocketUpgrade(self: *const AsyncHttpRequest) bool {
        const upgrade = self.getHeader("upgrade") orelse return false;
        const connection = self.getHeader("connection") orelse return false;
        return std.mem.eql(u8, upgrade, "websocket") and
            std.mem.indexOf(u8, connection, "upgrade") != null;
    }

    pub fn isGrpcRequest(self: *const AsyncHttpRequest) bool {
        const content_type = self.getHeader("content-type") orelse return false;
        return std.mem.startsWith(u8, content_type, "application/grpc");
    }
};

pub const AsyncHttpResponse = struct {
    status_code: u16 = 200,
    status_text: []const u8 = "OK",
    headers: std.StringHashMap([]const u8),
    body: []const u8 = "",

    pub fn init(allocator: std.mem.Allocator) AsyncHttpResponse {
        return AsyncHttpResponse{
            .headers = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *AsyncHttpResponse) void {
        self.headers.deinit();
    }

    pub fn setHeader(self: *AsyncHttpResponse, name: []const u8, value: []const u8) !void {
        try self.headers.put(name, value);
    }

    pub fn setContentType(self: *AsyncHttpResponse, content_type: []const u8) !void {
        try self.setHeader("content-type", content_type);
    }

    pub fn setStatus(self: *AsyncHttpResponse, code: u16, text: []const u8) void {
        self.status_code = code;
        self.status_text = text;
    }

    pub fn toBytes(self: *const AsyncHttpResponse, allocator: std.mem.Allocator) ![]u8 {
        var response = std.ArrayList(u8).init(allocator);
        defer response.deinit();

        // Status line
        try response.writer().print("HTTP/1.1 {} {}\r\n", .{ self.status_code, self.status_text });

        // Headers
        var header_iter = self.headers.iterator();
        while (header_iter.next()) |entry| {
            try response.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // Content-Length if not already set
        if (self.headers.get("content-length") == null) {
            try response.writer().print("content-length: {}\r\n", .{self.body.len});
        }

        try response.appendSlice("\r\n");
        try response.appendSlice(self.body);

        return try response.toOwnedSlice();
    }
};

/// Async request handler function type
pub const AsyncRequestHandler = *const fn (request: *AsyncHttpRequest, response: *AsyncHttpResponse) anyerror!void;

/// Async middleware function type
pub const AsyncMiddleware = *const fn (request: *AsyncHttpRequest, response: *AsyncHttpResponse, next: AsyncRequestHandler) anyerror!void;

/// Route definition for async handling
pub const AsyncRoute = struct {
    method: []const u8,
    path: []const u8,
    handler: AsyncRequestHandler,
    middlewares: []AsyncMiddleware,

    pub fn matches(self: *const AsyncRoute, method: []const u8, path: []const u8) bool {
        return std.mem.eql(u8, self.method, method) and self.matchPath(path);
    }

    fn matchPath(self: *const AsyncRoute, path: []const u8) bool {
        // Simple path matching - TODO: implement pattern matching
        return std.mem.eql(u8, self.path, path);
    }
};

/// Async unified server implementation
pub const AsyncUnifiedServer = struct {
    allocator: std.mem.Allocator,
    runtime: *AsyncRuntime,
    config: AsyncUnifiedServerConfig,
    server_core: *AsyncServerCore,
    routes: std.ArrayList(AsyncRoute),
    middlewares: std.ArrayList(AsyncMiddleware),
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, runtime: *AsyncRuntime, config: AsyncUnifiedServerConfig) !*AsyncUnifiedServer {
        const server_core_config = AsyncServerCore.ServerConfig{
            .bind_address = config.bind_address,
            .port = config.http_port,
            .max_connections = config.max_connections,
            .enable_http = config.enable_http1 or config.enable_http2,
            .enable_quic = config.enable_http3,
            .enable_websocket = config.enable_websocket,
            .enable_grpc = config.enable_grpc,
        };

        const server_core = try AsyncServerCore.init(allocator, runtime, server_core_config);

        const server = try allocator.create(AsyncUnifiedServer);
        server.* = AsyncUnifiedServer{
            .allocator = allocator,
            .runtime = runtime,
            .config = config,
            .server_core = server_core,
            .routes = std.ArrayList(AsyncRoute).init(allocator),
            .middlewares = std.ArrayList(AsyncMiddleware).init(allocator),
            .running = std.atomic.Value(bool).init(false),
        };

        return server;
    }

    pub fn deinit(self: *AsyncUnifiedServer) void {
        self.stop();
        self.server_core.deinit();
        self.routes.deinit();
        self.middlewares.deinit();
        self.allocator.destroy(self);
    }

    /// Add route handler
    pub fn addRoute(self: *AsyncUnifiedServer, method: []const u8, path: []const u8, handler: AsyncRequestHandler) !void {
        const route = AsyncRoute{
            .method = method,
            .path = path,
            .handler = handler,
            .middlewares = &[_]AsyncMiddleware{},
        };
        try self.routes.append(route);
    }

    /// Add global middleware
    pub fn use(self: *AsyncUnifiedServer, middleware: AsyncMiddleware) !void {
        try self.middlewares.append(middleware);
    }

    /// Start the async server
    pub fn start(self: *AsyncUnifiedServer) !void {
        if (self.running.swap(true, .monotonic)) {
            return error.ServerAlreadyRunning;
        }

        // Start the core server
        try self.server_core.start(AsyncServerCore.ServerConfig{
            .bind_address = self.config.bind_address,
            .port = self.config.http_port,
            .max_connections = self.config.max_connections,
            .enable_http = self.config.enable_http1 or self.config.enable_http2,
            .enable_quic = self.config.enable_http3,
            .enable_websocket = self.config.enable_websocket,
            .enable_grpc = self.config.enable_grpc,
        });

        std.log.info("AsyncUnifiedServer started on {}:{}", .{ self.config.bind_address, self.config.http_port });

        // Start request processing loop
        _ = try self.runtime.spawn(struct {
            fn processRequests(server: *AsyncUnifiedServer) !void {
                while (server.running.load(.monotonic)) {
                    // In a real implementation, this would process incoming requests
                    // from the server core and route them through handlers

                    // Mock task spawning
                    std.time.sleep(1 * std.time.ns_per_ms);

                    std.time.sleep(100 * std.time.ns_per_ms);
                }
            }
        }.processRequests(self));
    }

    /// Stop the async server
    pub fn stop(self: *AsyncUnifiedServer) void {
        if (self.running.swap(false, .monotonic)) {
            std.log.info("AsyncUnifiedServer stopping...");
        }
    }

    /// Handle incoming HTTP request
    fn handleRequest(self: *AsyncUnifiedServer, request: *AsyncHttpRequest, response: *AsyncHttpResponse) !void {
        // Find matching route
        for (self.routes.items) |route| {
            if (route.matches(request.method, request.path)) {
                // Apply middlewares then handler
                try self.applyMiddlewares(request, response, route.handler, route.middlewares);
                return;
            }
        }

        // No route found
        response.setStatus(404, "Not Found");
        response.body = "404 - Not Found";
    }

    fn applyMiddlewares(self: *AsyncUnifiedServer, request: *AsyncHttpRequest, response: *AsyncHttpResponse, handler: AsyncRequestHandler, middlewares: []AsyncMiddleware) !void {
        _ = self;
        if (middlewares.len == 0) {
            try handler(request, response);
            return;
        }

        // Apply first middleware
        const middleware = middlewares[0];
        const remaining = middlewares[1..];

        try middleware(request, response, struct {
            fn next(req: *AsyncHttpRequest, resp: *AsyncHttpResponse) anyerror!void {
                // This is a simplified middleware chain - in a real implementation,
                // we'd need to capture the remaining middlewares and handler
                if (remaining.len > 0) {
                    // Apply next middleware in chain
                    try remaining[0](req, resp, handler);
                } else {
                    try handler(req, resp);
                }
            }
        }.next);
    }

    /// Get server statistics
    pub fn getStats(self: *AsyncUnifiedServer) ServerStats {
        return ServerStats{
            .active_connections = self.server_core.getActiveConnections(),
            .total_connections = self.server_core.getConnectionCount(),
            .routes_registered = @intCast(self.routes.items.len),
            .middlewares_registered = @intCast(self.middlewares.items.len),
            .uptime_ms = if (self.running.load(.monotonic)) @intCast(std.time.milliTimestamp()) else 0,
        };
    }

    pub const ServerStats = struct {
        active_connections: u32,
        total_connections: u64,
        routes_registered: u32,
        middlewares_registered: u32,
        uptime_ms: i64,
    };
};

/// Built-in middleware implementations
pub const AsyncMiddlewares = struct {
    /// CORS middleware
    pub fn cors(request: *AsyncHttpRequest, response: *AsyncHttpResponse, next: AsyncRequestHandler) !void {
        // Add CORS headers
        try response.setHeader("access-control-allow-origin", "*");
        try response.setHeader("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS");
        try response.setHeader("access-control-allow-headers", "content-type, authorization");

        // Handle preflight
        if (std.mem.eql(u8, request.method, "OPTIONS")) {
            response.setStatus(200, "OK");
            return;
        }

        try next(request, response);
    }

    /// Logging middleware
    pub fn logging(request: *AsyncHttpRequest, response: *AsyncHttpResponse, next: AsyncRequestHandler) !void {
        const start_time = std.time.milliTimestamp();

        try next(request, response);

        const duration = std.time.milliTimestamp() - start_time;
        std.log.info("{s} {s} - {} ({} ms)", .{ request.method, request.path, response.status_code, duration });
    }

    /// Rate limiting middleware (simplified)
    pub fn rateLimit(request: *AsyncHttpRequest, response: *AsyncHttpResponse, next: AsyncRequestHandler) !void {
        // Simplified rate limiting - in reality would use connection ID and time windows
        _ = request.connection_id;

        // Mock rate limit check
        if (std.crypto.random.int(u8) < 10) { // 10/256 chance of rate limit
            response.setStatus(429, "Too Many Requests");
            response.body = "Rate limit exceeded";
            return;
        }

        try next(request, response);
    }
};

/// Async server builder for convenient setup
pub const AsyncServerBuilder = struct {
    allocator: std.mem.Allocator,
    runtime: *AsyncRuntime,
    config: AsyncUnifiedServerConfig,

    pub fn init(allocator: std.mem.Allocator, runtime: *AsyncRuntime) AsyncServerBuilder {
        return AsyncServerBuilder{
            .allocator = allocator,
            .runtime = runtime,
            .config = AsyncUnifiedServerConfig{},
        };
    }

    pub fn bindAddress(self: *AsyncServerBuilder, address: []const u8) *AsyncServerBuilder {
        self.config.bind_address = address;
        return self;
    }

    pub fn port(self: *AsyncServerBuilder, port_num: u16) *AsyncServerBuilder {
        self.config.http_port = port_num;
        return self;
    }

    pub fn maxConnections(self: *AsyncServerBuilder, max: u32) *AsyncServerBuilder {
        self.config.max_connections = max;
        return self;
    }

    pub fn enableProtocol(self: *AsyncServerBuilder, protocol: AsyncProtocol, enabled: bool) *AsyncServerBuilder {
        switch (protocol) {
            .http1 => self.config.enable_http1 = enabled,
            .http2 => self.config.enable_http2 = enabled,
            .http3 => self.config.enable_http3 = enabled,
            .grpc => self.config.enable_grpc = enabled,
            .websocket => self.config.enable_websocket = enabled,
        }
        return self;
    }

    pub fn build(self: *AsyncServerBuilder) !*AsyncUnifiedServer {
        return try AsyncUnifiedServer.init(self.allocator, self.runtime, self.config);
    }

    pub const AsyncProtocol = enum {
        http1,
        http2,
        http3,
        grpc,
        websocket,
    };
};

test "async unified server basic functionality" {
    const runtime = try AsyncRuntime.init(std.testing.allocator);
    defer runtime.deinit();

    var builder = AsyncServerBuilder.init(std.testing.allocator, runtime);
    const server = try builder.port(8080).maxConnections(100).build();
    defer server.deinit();

    // Test route registration
    try server.addRoute("GET", "/test", struct {
        fn handler(request: *AsyncHttpRequest, response: *AsyncHttpResponse) !void {
            _ = request;
            response.body = "Hello, async world!";
        }
    }.handler);

    const stats = server.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats.routes_registered);
}

test "async http request parsing" {
    var request = AsyncHttpRequest.init(std.testing.allocator, 123);
    defer request.deinit();

    try request.headers.put("content-type", "application/json");
    try request.headers.put("upgrade", "websocket");
    try request.headers.put("connection", "upgrade");

    try std.testing.expect(request.isWebSocketUpgrade());
    try std.testing.expectEqualStrings("application/json", request.getHeader("content-type").?);
}

test "async http response building" {
    var response = AsyncHttpResponse.init(std.testing.allocator);
    defer response.deinit();

    try response.setContentType("application/json");
    response.setStatus(201, "Created");
    response.body = "{\"status\": \"success\"}";

    const response_bytes = try response.toBytes(std.testing.allocator);
    defer std.testing.allocator.free(response_bytes);

    try std.testing.expect(std.mem.indexOf(u8, response_bytes, "HTTP/1.1 201 Created") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_bytes, "content-type: application/json") != null);
}
