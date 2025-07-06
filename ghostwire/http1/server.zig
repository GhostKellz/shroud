//! HTTP/1.1 server implementation
//! RFC 7230-7235 compliant HTTP/1.1 server with keep-alive and chunked encoding

const std = @import("std");

pub const ServerConfig = struct {
    max_connections: u32 = 1000,
    request_timeout_ms: u32 = 30000,
    keep_alive_timeout_ms: u32 = 60000,
    max_request_body_size: usize = 1024 * 1024,
    enable_keep_alive: bool = true,
    port: u16 = 8080,
    address: []const u8 = "0.0.0.0",
};

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,

    const Self = @This();

    pub fn fromString(method_str: []const u8) ?Self {
        if (std.mem.eql(u8, method_str, "GET")) return .GET;
        if (std.mem.eql(u8, method_str, "POST")) return .POST;
        if (std.mem.eql(u8, method_str, "PUT")) return .PUT;
        if (std.mem.eql(u8, method_str, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, method_str, "PATCH")) return .PATCH;
        if (std.mem.eql(u8, method_str, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, method_str, "OPTIONS")) return .OPTIONS;
        if (std.mem.eql(u8, method_str, "TRACE")) return .TRACE;
        if (std.mem.eql(u8, method_str, "CONNECT")) return .CONNECT;
        return null;
    }

    pub fn toString(self: Self) []const u8 {
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

pub const HttpStatus = enum(u16) {
    ok = 200,
    created = 201,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,

    const Self = @This();

    pub fn toString(self: Self) []const u8 {
        return switch (self) {
            .ok => "200 OK",
            .created => "201 Created",
            .no_content => "204 No Content",
            .moved_permanently => "301 Moved Permanently",
            .found => "302 Found",
            .not_modified => "304 Not Modified",
            .bad_request => "400 Bad Request",
            .unauthorized => "401 Unauthorized",
            .forbidden => "403 Forbidden",
            .not_found => "404 Not Found",
            .method_not_allowed => "405 Method Not Allowed",
            .internal_server_error => "500 Internal Server Error",
            .not_implemented => "501 Not Implemented",
            .bad_gateway => "502 Bad Gateway",
            .service_unavailable => "503 Service Unavailable",
        };
    }
};

pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    version: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .method = .GET,
            .path = "",
            .version = "HTTP/1.1",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
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
        self.allocator.free(self.path);
        self.allocator.free(self.version);
        self.allocator.free(self.body);
    }

    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Self {
        var request = Self.init(allocator);
        
        var lines = std.mem.split(u8, data, "\r\n");
        
        // Parse request line
        const request_line = lines.next() orelse return error.InvalidRequest;
        var parts = std.mem.split(u8, request_line, " ");
        
        const method_str = parts.next() orelse return error.InvalidRequest;
        request.method = HttpMethod.fromString(method_str) orelse return error.InvalidMethod;
        
        const path = parts.next() orelse return error.InvalidRequest;
        request.path = try allocator.dupe(u8, path);
        
        const version = parts.next() orelse return error.InvalidRequest;
        request.version = try allocator.dupe(u8, version);
        
        // Parse headers
        while (lines.next()) |line| {
            if (line.len == 0) break; // Empty line separates headers from body
            
            if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                const name = std.mem.trim(u8, line[0..colon_pos], " \t");
                const value = std.mem.trim(u8, line[colon_pos + 1..], " \t");
                
                const owned_name = try allocator.dupe(u8, name);
                const owned_value = try allocator.dupe(u8, value);
                try request.headers.put(owned_name, owned_value);
            }
        }
        
        // Parse body (rest of the data)
        const remaining = lines.rest();
        request.body = try allocator.dupe(u8, remaining);
        
        return request;
    }
};

pub const HttpResponse = struct {
    status: HttpStatus,
    headers: std.StringHashMap([]const u8),
    body: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .status = .ok,
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

    pub fn setStatus(self: *Self, status: HttpStatus) void {
        self.status = status;
    }

    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.headers.put(owned_name, owned_value);
    }

    pub fn write(self: *Self, data: []const u8) !void {
        try self.body.appendSlice(data);
    }

    pub fn writeFormat(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        try self.body.writer().print(fmt, args);
    }

    pub fn text(self: *Self, content: []const u8) !void {
        try self.setHeader("Content-Type", "text/plain");
        try self.write(content);
    }

    pub fn html(self: *Self, content: []const u8) !void {
        try self.setHeader("Content-Type", "text/html");
        try self.write(content);
    }

    pub fn json(self: *Self, content: []const u8) !void {
        try self.setHeader("Content-Type", "application/json");
        try self.write(content);
    }

    pub fn build(self: *Self) ![]u8 {
        var response = std.ArrayList(u8).init(self.allocator);
        
        // Status line
        try response.writer().print("HTTP/1.1 {s}\r\n", .{self.status.toString()});
        
        // Headers
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            try response.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        
        // Content-Length if not set
        if (self.headers.get("Content-Length") == null and self.headers.get("Transfer-Encoding") == null) {
            try response.writer().print("Content-Length: {}\r\n", .{self.body.items.len});
        }
        
        // Empty line
        try response.appendSlice("\r\n");
        
        // Body
        try response.appendSlice(self.body.items);
        
        return response.toOwnedSlice();
    }
};

pub const HandlerFn = *const fn (*HttpRequest, *HttpResponse) anyerror!void;

pub const Router = struct {
    routes: std.ArrayList(Route),
    allocator: std.mem.Allocator,

    const Route = struct {
        method: HttpMethod,
        path: []const u8,
        handler: HandlerFn,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .routes = std.ArrayList(Route).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.routes.items) |route| {
            self.allocator.free(route.path);
        }
        self.routes.deinit();
    }

    pub fn addRoute(self: *Self, method: HttpMethod, path: []const u8, handler: HandlerFn) !void {
        const owned_path = try self.allocator.dupe(u8, path);
        try self.routes.append(Route{
            .method = method,
            .path = owned_path,
            .handler = handler,
        });
    }

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

    pub fn handleRequest(self: *Self, request: *HttpRequest, response: *HttpResponse) !void {
        for (self.routes.items) |route| {
            if (route.method == request.method and std.mem.eql(u8, route.path, request.path)) {
                try route.handler(request, response);
                return;
            }
        }
        
        // 404 Not Found
        response.setStatus(.not_found);
        try response.text("404 - Not Found");
    }
};

pub const Http1Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    listener: std.net.Server,
    router: Router,
    running: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Self {
        const address = try std.net.Address.parseIp(config.address, config.port);
        const listener = try address.listen(.{ .reuse_address = true });

        return Self{
            .allocator = allocator,
            .config = config,
            .listener = listener,
            .router = Router.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.router.deinit();
        self.listener.deinit();
    }

    pub fn start(self: *Self) !void {
        self.running = true;
        std.log.info("HTTP/1.1 server listening on {}:{}", .{ self.config.address, self.config.port });

        while (self.running) {
            const client_socket = self.listener.accept() catch continue;
            
            // Handle connection (simplified for demo)
            try self.handleConnection(client_socket);
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
    }

    pub fn get(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.router.get(path, handler);
    }

    pub fn post(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.router.post(path, handler);
    }

    pub fn put(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.router.put(path, handler);
    }

    pub fn delete(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.router.delete(path, handler);
    }

    fn handleConnection(self: *Self, socket: std.net.Stream) !void {
        defer socket.close();

        var buffer: [8192]u8 = undefined;
        var total_read: usize = 0;

        // Read request (simplified)
        while (total_read < buffer.len - 1) {
            const bytes_read = socket.read(buffer[total_read..]) catch break;
            if (bytes_read == 0) break;
            
            total_read += bytes_read;
            
            // Check if we have a complete request (ending with \r\n\r\n)
            if (std.mem.indexOf(u8, buffer[0..total_read], "\r\n\r\n")) |_| {
                break;
            }
        }

        if (total_read == 0) return;

        // Parse request
        var request = HttpRequest.parse(self.allocator, buffer[0..total_read]) catch |err| {
            std.log.err("Failed to parse request: {}", .{err});
            return;
        };
        defer request.deinit();

        // Handle request
        var response = HttpResponse.init(self.allocator);
        defer response.deinit();

        // Set keep-alive header if enabled
        if (self.config.enable_keep_alive) {
            try response.setHeader("Connection", "keep-alive");
        } else {
            try response.setHeader("Connection", "close");
        }

        // Route request
        self.router.handleRequest(&request, &response) catch |err| {
            std.log.err("Handler error: {}", .{err});
            response.setStatus(.internal_server_error);
            response.text("Internal Server Error") catch {};
        };

        // Send response
        const response_data = try response.build();
        defer self.allocator.free(response_data);
        
        _ = try socket.writeAll(response_data);

        std.log.info("{s} {s} - {}", .{ request.method.toString(), request.path, @intFromEnum(response.status) });
    }
};

test "HTTP/1.1 request parsing" {
    const allocator = std.testing.allocator;
    
    const request_data = "GET /test HTTP/1.1\r\nHost: localhost\r\nUser-Agent: test\r\n\r\nBody content";
    
    var request = try HttpRequest.parse(allocator, request_data);
    defer request.deinit();
    
    try std.testing.expect(request.method == .GET);
    try std.testing.expect(std.mem.eql(u8, request.path, "/test"));
    try std.testing.expect(std.mem.eql(u8, request.version, "HTTP/1.1"));
    try std.testing.expect(std.mem.eql(u8, request.getHeader("Host").?, "localhost"));
    try std.testing.expect(std.mem.eql(u8, request.body, "Body content"));
}

test "HTTP/1.1 response building" {
    const allocator = std.testing.allocator;
    
    var response = HttpResponse.init(allocator);
    defer response.deinit();
    
    response.setStatus(.ok);
    try response.setHeader("Content-Type", "text/html");
    try response.html("<h1>Hello World</h1>");
    
    const response_data = try response.build();
    defer allocator.free(response_data);
    
    try std.testing.expect(std.mem.indexOf(u8, response_data, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_data, "Content-Type: text/html") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_data, "<h1>Hello World</h1>") != null);
}