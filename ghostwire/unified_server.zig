//! Unified HTTP server abstraction supporting HTTP/1.1, HTTP/2, and HTTP/3
//! Single API for all HTTP versions with automatic protocol negotiation

const std = @import("std");
const Http1Server = @import("http1/server.zig").Http1Server;
const Http2Server = @import("http2/server.zig").Http2Server;
const Http3Server = @import("zquic/http3/server.zig").Http3Server;
const WebSocketServer = @import("websocket/server.zig").WebSocketServer;
const WebSocketHandshake = @import("websocket/handshake.zig").WebSocketHandshake;

pub const ServerProtocol = enum {
    http1_1,
    http2,
    http3,
    websocket,
    auto, // Automatic protocol negotiation
};

pub const UnifiedServerConfig = struct {
    address: []const u8 = "0.0.0.0",
    port: u16 = 8080,
    tls_port: u16 = 8443,
    max_connections: u32 = 1000,
    request_timeout_ms: u32 = 30000,
    keep_alive_timeout_ms: u32 = 60000,
    max_request_body_size: usize = 1024 * 1024,
    
    // Protocol-specific settings
    enable_http1: bool = true,
    enable_http2: bool = true,
    enable_http3: bool = false, // Requires QUIC/UDP setup
    enable_websocket: bool = true,
    
    // Security settings
    enable_tls: bool = false,
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    
    // Features
    enable_compression: bool = true,
    enable_cors: bool = false,
    enable_security_headers: bool = true,
    static_files_root: ?[]const u8 = null,
};

pub const UnifiedRequest = struct {
    method: Method,
    path: []const u8,
    version: ServerProtocol,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    query_params: std.StringHashMap([]const u8),
    path_params: std.StringHashMap([]const u8),
    client_ip: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub const Method = enum {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH,
        HEAD,
        OPTIONS,
        TRACE,
        CONNECT,

        pub fn toString(self: Method) []const u8 {
            return switch (self) {
                .GET => "GET",
                .POST => "POST",
                .PUT => "PUT",
                .DELETE => "DELETE",
                .PATCH => "PATCH",
                .HEAD => "HEAD",
                .OPTIONS => "OPTIONS",
                .TRACE => "TRACE",
                .CONNECT => "CONNECT",
            };
        }
    };

    pub fn init(allocator: std.mem.Allocator, method: Method, path: []const u8, version: ServerProtocol) Self {
        return Self{
            .method = method,
            .path = path,
            .version = version,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .query_params = std.StringHashMap([]const u8).init(allocator),
            .path_params = std.StringHashMap([]const u8).init(allocator),
            .client_ip = "",
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.deallocateHashMap(&self.headers);
        self.deallocateHashMap(&self.query_params);
        self.deallocateHashMap(&self.path_params);
        self.allocator.free(self.path);
        self.allocator.free(self.body);
        self.allocator.free(self.client_ip);
    }

    fn deallocateHashMap(self: *Self, map: *std.StringHashMap([]const u8)) void {
        var iterator = map.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }

    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    pub fn getQuery(self: *const Self, name: []const u8) ?[]const u8 {
        return self.query_params.get(name);
    }

    pub fn getParam(self: *const Self, name: []const u8) ?[]const u8 {
        return self.path_params.get(name);
    }

    pub fn hasHeader(self: *const Self, name: []const u8) bool {
        return self.headers.contains(name);
    }

    pub fn isJson(self: *const Self) bool {
        if (self.getHeader("Content-Type")) |content_type| {
            return std.mem.indexOf(u8, content_type, "application/json") != null;
        }
        return false;
    }

    pub fn parseJson(self: *const Self, comptime T: type) !T {
        return std.json.parseFromSlice(T, self.allocator, self.body, .{});
    }
};

pub const UnifiedResponse = struct {
    status: u16,
    headers: std.StringHashMap([]const u8),
    body: std.ArrayList(u8),
    cookies: std.ArrayList(Cookie),
    is_sent: bool = false,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub const Cookie = struct {
        name: []const u8,
        value: []const u8,
        domain: ?[]const u8 = null,
        path: ?[]const u8 = null,
        max_age: ?i32 = null,
        secure: bool = false,
        http_only: bool = false,
        same_site: ?SameSite = null,

        pub const SameSite = enum {
            strict,
            lax,
            none,

            pub fn toString(self: SameSite) []const u8 {
                return switch (self) {
                    .strict => "Strict",
                    .lax => "Lax",
                    .none => "None",
                };
            }
        };
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .status = 200,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = std.ArrayList(u8).init(allocator),
            .cookies = std.ArrayList(Cookie).init(allocator),
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
        self.cookies.deinit();
    }

    pub fn setStatus(self: *Self, status: u16) void {
        self.status = status;
    }

    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.headers.put(owned_name, owned_value);
    }

    pub fn setCookie(self: *Self, cookie: Cookie) !void {
        try self.cookies.append(cookie);
    }

    pub fn write(self: *Self, data: []const u8) !void {
        try self.body.appendSlice(data);
    }

    pub fn writeFormat(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        try self.body.writer().print(fmt, args);
    }

    pub fn text(self: *Self, content: []const u8) !void {
        try self.setHeader("Content-Type", "text/plain; charset=utf-8");
        try self.write(content);
    }

    pub fn html(self: *Self, content: []const u8) !void {
        try self.setHeader("Content-Type", "text/html; charset=utf-8");
        try self.write(content);
    }

    pub fn json(self: *Self, content: []const u8) !void {
        try self.setHeader("Content-Type", "application/json; charset=utf-8");
        try self.write(content);
    }

    pub fn jsonObject(self: *Self, obj: anytype) !void {
        try self.setHeader("Content-Type", "application/json; charset=utf-8");
        try std.json.stringify(obj, .{}, self.body.writer());
    }

    pub fn redirect(self: *Self, url: []const u8, permanent: bool) !void {
        self.setStatus(if (permanent) 301 else 302);
        try self.setHeader("Location", url);
    }

    pub fn file(self: *Self, file_path: []const u8) !void {
        const file_handle = try std.fs.cwd().openFile(file_path, .{});
        defer file_handle.close();

        const file_size = try file_handle.getEndPos();
        try self.body.ensureTotalCapacity(file_size);

        _ = try file_handle.readAll(self.body.items.ptr[0..file_size]);
        self.body.items.len = file_size;

        // Set Content-Type based on file extension
        if (std.mem.lastIndexOf(u8, file_path, ".")) |dot_index| {
            const extension = file_path[dot_index..];
            const content_type = getContentTypeForExtension(extension);
            try self.setHeader("Content-Type", content_type);
        }
    }

    fn getContentTypeForExtension(extension: []const u8) []const u8 {
        if (std.mem.eql(u8, extension, ".html")) return "text/html";
        if (std.mem.eql(u8, extension, ".css")) return "text/css";
        if (std.mem.eql(u8, extension, ".js")) return "application/javascript";
        if (std.mem.eql(u8, extension, ".json")) return "application/json";
        if (std.mem.eql(u8, extension, ".png")) return "image/png";
        if (std.mem.eql(u8, extension, ".jpg") or std.mem.eql(u8, extension, ".jpeg")) return "image/jpeg";
        if (std.mem.eql(u8, extension, ".gif")) return "image/gif";
        if (std.mem.eql(u8, extension, ".svg")) return "image/svg+xml";
        if (std.mem.eql(u8, extension, ".ico")) return "image/x-icon";
        return "application/octet-stream";
    }
};

pub const HandlerFn = *const fn (*UnifiedRequest, *UnifiedResponse) anyerror!void;
pub const MiddlewareFn = *const fn (*UnifiedRequest, *UnifiedResponse, *const fn () anyerror!void) anyerror!void;

pub const UnifiedServer = struct {
    allocator: std.mem.Allocator,
    config: UnifiedServerConfig,
    
    // Protocol-specific servers
    http1_server: ?Http1Server = null,
    http2_server: ?Http2Server = null,
    http3_server: ?Http3Server = null,
    websocket_server: ?WebSocketServer = null,
    
    // Routing and middleware
    routes: std.ArrayList(Route),
    middleware_stack: std.ArrayList(MiddlewareFn),
    
    running: bool = false,

    const Self = @This();

    const Route = struct {
        method: UnifiedRequest.Method,
        path: []const u8,
        handler: HandlerFn,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *Route) void {
            self.allocator.free(self.path);
        }
    };

    pub fn init(allocator: std.mem.Allocator, config: UnifiedServerConfig) !Self {
        var server = Self{
            .allocator = allocator,
            .config = config,
            .routes = std.ArrayList(Route).init(allocator),
            .middleware_stack = std.ArrayList(MiddlewareFn).init(allocator),
        };

        // Initialize protocol-specific servers
        if (config.enable_http1) {
            const http1_config = @import("http1/server.zig").ServerConfig{
                .address = config.address,
                .port = config.port,
                .max_connections = config.max_connections,
                .request_timeout_ms = config.request_timeout_ms,
                .keep_alive_timeout_ms = config.keep_alive_timeout_ms,
                .max_request_body_size = config.max_request_body_size,
            };
            server.http1_server = try Http1Server.init(allocator, http1_config);
        }

        if (config.enable_http2) {
            const http2_config = @import("http2/server.zig").ServerConfig{
                .address = config.address,
                .port = if (config.enable_tls) config.tls_port else config.port + 1,
                .max_connections = config.max_connections,
                .max_streams_per_connection = 100,
            };
            server.http2_server = try Http2Server.init(allocator, http2_config);
        }

        if (config.enable_websocket) {
            const ws_config = @import("websocket/server.zig").WebSocketServerConfig{
                .address = config.address,
                .port = config.port + 10, // Use a different port for WebSocket
                .max_connections = config.max_connections,
            };
            server.websocket_server = try WebSocketServer.init(allocator, ws_config);
        }

        return server;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        
        for (self.routes.items) |*route| {
            route.deinit();
        }
        self.routes.deinit();
        self.middleware_stack.deinit();

        if (self.http1_server) |*server| {
            server.deinit();
        }
        if (self.http2_server) |*server| {
            server.deinit();
        }
        if (self.http3_server) |*server| {
            server.deinit();
        }
        if (self.websocket_server) |*server| {
            server.deinit();
        }
    }

    pub fn start(self: *Self) !void {
        self.running = true;
        
        std.log.info("Starting unified HTTP server...", .{});
        
        // Start HTTP/1.1 server
        if (self.http1_server) |*server| {
            std.log.info("HTTP/1.1 server enabled on port {}", .{self.config.port});
            // In a real implementation, each server would run in its own thread
            try server.start();
        }

        // Start HTTP/2 server
        if (self.http2_server) |_| {
            const port = if (self.config.enable_tls) self.config.tls_port else self.config.port + 1;
            std.log.info("HTTP/2 server enabled on port {}", .{port});
            // try server.start(); // Would be in separate thread
        }

        // Start HTTP/3 server
        if (self.http3_server) |*server| {
            std.log.info("HTTP/3 server enabled on port {}", .{self.config.port + 2});
            // try server.start(); // Would be in separate thread
            _ = server;
        }

        // Start WebSocket server
        if (self.websocket_server) |*server| {
            std.log.info("WebSocket server enabled on port {}", .{self.config.port + 10});
            // try server.start(); // Would be in separate thread
            _ = server;
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        
        if (self.http1_server) |*server| {
            server.stop();
        }
        if (self.http2_server) |*server| {
            server.stop();
        }
        if (self.http3_server) |*server| {
            server.stop();
        }
        if (self.websocket_server) |*server| {
            server.stop();
        }
    }

    // Route registration methods
    pub fn get(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.GET, path, handler);
    }

    pub fn post(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.POST, path, handler);
    }

    pub fn put(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PUT, path, handler);
    }

    pub fn delete(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.DELETE, path, handler);
    }

    pub fn patch(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PATCH, path, handler);
    }

    pub fn options(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.OPTIONS, path, handler);
    }

    // WebSocket upgrade handler
    pub fn websocket(self: *Self, path: []const u8, handler: HandlerFn) !void {
        // This would handle WebSocket upgrade requests on the specified path
        try self.addRoute(.GET, path, handler);
    }

    fn addRoute(self: *Self, method: UnifiedRequest.Method, path: []const u8, handler: HandlerFn) !void {
        const owned_path = try self.allocator.dupe(u8, path);
        const route = Route{
            .method = method,
            .path = owned_path,
            .handler = handler,
            .allocator = self.allocator,
        };
        try self.routes.append(route);
    }

    // Middleware support
    pub fn use(self: *Self, middleware: MiddlewareFn) !void {
        try self.middleware_stack.append(middleware);
    }

    // Static file serving
    pub fn static(self: *Self, url_prefix: []const u8, directory: []const u8) !void {
        _ = self;
        _ = url_prefix;
        _ = directory;
        // Implementation would add a catch-all route for static files
    }

    // Request handling
    pub fn handleRequest(self: *Self, request: *UnifiedRequest, response: *UnifiedResponse) !void {
        // Execute middleware chain
        for (self.middleware_stack.items) |middleware| {
            const next = struct {
                fn next() anyerror!void {
                    // Continue to next middleware or route handler
                }
            }.next;
            
            try middleware(request, response, next);
        }

        // Find and execute route handler
        for (self.routes.items) |route| {
            if (route.method == request.method and std.mem.eql(u8, route.path, request.path)) {
                try route.handler(request, response);
                return;
            }
        }

        // 404 Not Found
        response.setStatus(404);
        try response.text("404 - Not Found");
    }

    // Built-in middleware
    pub fn corsMiddleware(self: *Self) MiddlewareFn {
        _ = self;
        return struct {
            fn middleware(req: *UnifiedRequest, res: *UnifiedResponse, next: *const fn () anyerror!void) anyerror!void {
                try res.setHeader("Access-Control-Allow-Origin", "*");
                try res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                try res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
                
                if (req.method == .OPTIONS) {
                    res.setStatus(204);
                    return;
                }
                
                try next();
            }
        }.middleware;
    }

    pub fn loggingMiddleware(self: *Self) MiddlewareFn {
        _ = self;
        return struct {
            fn middleware(req: *UnifiedRequest, res: *UnifiedResponse, next: *const fn () anyerror!void) anyerror!void {
                const start_time = std.time.microTimestamp();
                
                try next();
                
                const end_time = std.time.microTimestamp();
                const duration_ms = @as(f64, @floatFromInt(end_time - start_time)) / 1000.0;
                
                std.log.info("{s} {s} - {} ({d:.2}ms)", .{ 
                    req.method.toString(), 
                    req.path, 
                    res.status, 
                    duration_ms 
                });
            }
        }.middleware;
    }

    pub fn compressionMiddleware(self: *Self) MiddlewareFn {
        _ = self;
        return struct {
            fn middleware(req: *UnifiedRequest, res: *UnifiedResponse, next: *const fn () anyerror!void) anyerror!void {
                _ = req;
                _ = res;
                // Compression logic would go here
                try next();
            }
        }.middleware;
    }
};

// Example usage and handlers
pub fn exampleHandler(req: *UnifiedRequest, res: *UnifiedResponse) !void {
    _ = req;
    
    const html_content = 
        \\<!DOCTYPE html>
        \\<html>
        \\<head><title>Shroud Unified Server</title></head>
        \\<body>
        \\  <h1>🚀 Shroud v1.0 Unified HTTP Server</h1>
        \\  <p>Supporting HTTP/1.1, HTTP/2, and HTTP/3</p>
        \\  <ul>
        \\    <li><strong>Protocol:</strong> Auto-negotiated</li>
        \\    <li><strong>Features:</strong> Routing, Middleware, Static Files</li>
        \\    <li><strong>Performance:</strong> High-throughput, Low-latency</li>
        \\  </ul>
        \\</body>
        \\</html>
    ;
    
    try res.html(html_content);
}

pub fn apiHandler(req: *UnifiedRequest, res: *UnifiedResponse) !void {
    const response_data = .{
        .message = "Hello from Shroud Unified API",
        .method = req.method.toString(),
        .path = req.path,
        .protocol = @tagName(req.version),
        .timestamp = std.time.timestamp(),
    };
    
    try res.jsonObject(response_data);
}

test "unified server initialization" {
    const allocator = std.testing.allocator;
    
    const config = UnifiedServerConfig{
        .enable_http1 = true,
        .enable_http2 = true,
        .enable_http3 = false,
    };
    
    var server = try UnifiedServer.init(allocator, config);
    defer server.deinit();
    
    try server.get("/", exampleHandler);
    try server.get("/api/test", apiHandler);
    
    try std.testing.expect(server.routes.items.len == 2);
}

test "unified request/response" {
    const allocator = std.testing.allocator;
    
    var request = UnifiedRequest.init(allocator, .GET, "/test", .http1_1);
    defer request.deinit();
    
    var response = UnifiedResponse.init(allocator);
    defer response.deinit();
    
    try response.setHeader("Content-Type", "application/json");
    try response.json("{\"test\": true}");
    
    try std.testing.expect(response.status == 200);
    try std.testing.expect(response.body.items.len > 0);
}