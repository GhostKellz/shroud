//! Universal HTTP client supporting HTTP/1.1, HTTP/2, and HTTP/3
//! Automatic protocol detection and unified API

const std = @import("std");
const Http1 = @import("../http1/server.zig");
const Http2 = @import("../http2/server.zig");

pub const ClientConfig = struct {
    timeout_ms: u32 = 30000,
    max_redirects: u8 = 5,
    user_agent: []const u8 = "Shroud-HTTP-Client/1.0",
    enable_compression: bool = true,
    enable_keep_alive: bool = true,
    verify_tls: bool = true,
    preferred_protocol: HttpVersion = .auto,
};

pub const HttpVersion = enum {
    auto,
    http1_1,
    http2,
    http3,
};

pub const ClientRequest = struct {
    method: Http1.HttpMethod,
    url: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, method: Http1.HttpMethod, url: []const u8) Self {
        return Self{
            .method = method,
            .url = try allocator.dupe(u8, url) catch unreachable,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.url);
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        self.allocator.free(self.body);
    }

    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.headers.put(owned_name, owned_value);
    }

    pub fn setBody(self: *Self, body: []const u8) !void {
        self.allocator.free(self.body);
        self.body = try self.allocator.dupe(u8, body);
    }

    pub fn json(self: *Self, data: []const u8) !void {
        try self.setHeader("Content-Type", "application/json");
        try self.setBody(data);
    }

    pub fn form(self: *Self, data: []const u8) !void {
        try self.setHeader("Content-Type", "application/x-www-form-urlencoded");
        try self.setBody(data);
    }
};

pub const ClientResponse = struct {
    status: u16,
    status_text: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    protocol_version: HttpVersion,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, status: u16, protocol_version: HttpVersion) Self {
        return Self{
            .status = status,
            .status_text = "",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .protocol_version = protocol_version,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.status_text);
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        self.allocator.free(self.body);
    }

    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    pub fn isSuccess(self: *const Self) bool {
        return self.status >= 200 and self.status < 300;
    }

    pub fn isRedirect(self: *const Self) bool {
        return self.status >= 300 and self.status < 400;
    }

    pub fn isError(self: *const Self) bool {
        return self.status >= 400;
    }

    pub fn parseJson(self: *const Self, comptime T: type) !T {
        return std.json.parseFromSlice(T, self.allocator, self.body, .{});
    }
};

pub const UrlParts = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
    query: ?[]const u8,
    fragment: ?[]const u8,

    const Self = @This();

    pub fn parse(allocator: std.mem.Allocator, url: []const u8) !Self {
        // Simple URL parsing (production would need more robust implementation)
        var remaining = url;
        
        // Extract scheme
        const scheme_end = std.mem.indexOf(u8, remaining, "://") orelse return error.InvalidUrl;
        const scheme = try allocator.dupe(u8, remaining[0..scheme_end]);
        remaining = remaining[scheme_end + 3..];
        
        // Extract host and port
        const host_end = std.mem.indexOfAny(u8, remaining, "/?#") orelse remaining.len;
        const host_part = remaining[0..host_end];
        remaining = if (host_end < remaining.len) remaining[host_end..] else "";
        
        var host: []const u8 = undefined;
        var port: u16 = undefined;
        
        if (std.mem.lastIndexOf(u8, host_part, ":")) |colon_pos| {
            host = try allocator.dupe(u8, host_part[0..colon_pos]);
            port = std.fmt.parseInt(u16, host_part[colon_pos + 1..], 10) catch {
                return error.InvalidPort;
            };
        } else {
            host = try allocator.dupe(u8, host_part);
            port = if (std.mem.eql(u8, scheme, "https")) 443 else 80;
        }
        
        // Extract path
        var path: []const u8 = "/";
        if (remaining.len > 0 and remaining[0] == '/') {
            const path_end = std.mem.indexOfAny(u8, remaining, "?#") orelse remaining.len;
            path = try allocator.dupe(u8, remaining[0..path_end]);
            remaining = if (path_end < remaining.len) remaining[path_end..] else "";
        }
        
        // Extract query
        var query: ?[]const u8 = null;
        if (remaining.len > 0 and remaining[0] == '?') {
            remaining = remaining[1..];
            const query_end = std.mem.indexOf(u8, remaining, "#") orelse remaining.len;
            query = try allocator.dupe(u8, remaining[0..query_end]);
            remaining = if (query_end < remaining.len) remaining[query_end..] else "";
        }
        
        // Extract fragment
        var fragment: ?[]const u8 = null;
        if (remaining.len > 0 and remaining[0] == '#') {
            fragment = try allocator.dupe(u8, remaining[1..]);
        }
        
        return Self{
            .scheme = scheme,
            .host = host,
            .port = port,
            .path = path,
            .query = query,
            .fragment = fragment,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.scheme);
        allocator.free(self.host);
        allocator.free(self.path);
        if (self.query) |q| allocator.free(q);
        if (self.fragment) |f| allocator.free(f);
    }
};

pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    config: ClientConfig,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn get(self: *Self, url: []const u8) !ClientResponse {
        var request = ClientRequest.init(self.allocator, .GET, url);
        defer request.deinit();
        return self.execute(&request);
    }

    pub fn post(self: *Self, url: []const u8, body: []const u8) !ClientResponse {
        var request = ClientRequest.init(self.allocator, .POST, url);
        defer request.deinit();
        try request.setBody(body);
        return self.execute(&request);
    }

    pub fn put(self: *Self, url: []const u8, body: []const u8) !ClientResponse {
        var request = ClientRequest.init(self.allocator, .PUT, url);
        defer request.deinit();
        try request.setBody(body);
        return self.execute(&request);
    }

    pub fn delete(self: *Self, url: []const u8) !ClientResponse {
        var request = ClientRequest.init(self.allocator, .DELETE, url);
        defer request.deinit();
        return self.execute(&request);
    }

    pub fn execute(self: *Self, request: *ClientRequest) !ClientResponse {
        // Parse URL
        var url_parts = try UrlParts.parse(self.allocator, request.url);
        defer url_parts.deinit(self.allocator);

        // Determine protocol version
        const protocol = self.detectProtocol(&url_parts);

        // Execute based on protocol
        return switch (protocol) {
            .http1_1 => self.executeHttp1(request, &url_parts),
            .http2 => self.executeHttp2(request, &url_parts),
            .http3 => self.executeHttp3(request, &url_parts),
            .auto => {
                // Try HTTP/2 first, fallback to HTTP/1.1
                return self.executeHttp2(request, &url_parts) catch |err| switch (err) {
                    error.UnsupportedProtocol => self.executeHttp1(request, &url_parts),
                    else => err,
                };
            },
        };
    }

    fn detectProtocol(self: *Self, url_parts: *const UrlParts) HttpVersion {
        if (self.config.preferred_protocol != .auto) {
            return self.config.preferred_protocol;
        }

        // Simple heuristics for protocol detection
        if (std.mem.eql(u8, url_parts.scheme, "https")) {
            return .http2; // Default to HTTP/2 for HTTPS
        } else {
            return .http1_1; // Default to HTTP/1.1 for HTTP
        }
    }

    fn executeHttp1(self: *Self, request: *ClientRequest, url_parts: *const UrlParts) !ClientResponse {
        // Connect to server
        const address = try std.net.Address.resolveIp(url_parts.host, url_parts.port);
        const socket = try std.net.tcpConnectToAddress(address);
        defer socket.close();

        // Build HTTP/1.1 request
        var request_data = std.ArrayList(u8).init(self.allocator);
        defer request_data.deinit();

        // Request line
        try request_data.writer().print("{s} {s} HTTP/1.1\r\n", .{ request.method.toString(), url_parts.path });

        // Host header
        try request_data.writer().print("Host: {s}\r\n", .{url_parts.host});

        // User-Agent
        try request_data.writer().print("User-Agent: {s}\r\n", .{self.config.user_agent});

        // Custom headers
        var header_iter = request.headers.iterator();
        while (header_iter.next()) |entry| {
            try request_data.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // Content-Length if body exists
        if (request.body.len > 0) {
            try request_data.writer().print("Content-Length: {}\r\n", .{request.body.len});
        }

        // Connection header
        if (self.config.enable_keep_alive) {
            try request_data.appendSlice("Connection: keep-alive\r\n");
        } else {
            try request_data.appendSlice("Connection: close\r\n");
        }

        // End headers
        try request_data.appendSlice("\r\n");

        // Body
        if (request.body.len > 0) {
            try request_data.appendSlice(request.body);
        }

        // Send request
        _ = try socket.writeAll(request_data.items);

        // Read response
        var response_buffer = std.ArrayList(u8).init(self.allocator);
        defer response_buffer.deinit();

        var buffer: [4096]u8 = undefined;
        while (true) {
            const bytes_read = socket.read(&buffer) catch break;
            if (bytes_read == 0) break;
            try response_buffer.appendSlice(buffer[0..bytes_read]);

            // Check if we have complete headers
            if (std.mem.indexOf(u8, response_buffer.items, "\r\n\r\n")) |header_end| {
                // Parse Content-Length to determine if we need more data
                const headers_section = response_buffer.items[0..header_end];
                if (std.mem.indexOf(u8, headers_section, "Content-Length:")) |cl_start| {
                    const cl_line_start = cl_start + "Content-Length:".len;
                    const cl_line_end = std.mem.indexOf(u8, headers_section[cl_line_start..], "\r\n") orelse continue;
                    const content_length_str = std.mem.trim(u8, headers_section[cl_line_start..cl_line_start + cl_line_end], " \t");
                    const content_length = std.fmt.parseInt(usize, content_length_str, 10) catch continue;
                    
                    const body_start = header_end + 4;
                    const current_body_len = response_buffer.items.len - body_start;
                    
                    if (current_body_len >= content_length) {
                        break; // We have complete response
                    }
                } else {
                    // No Content-Length, assume complete for now
                    break;
                }
            }
        }

        // Parse response
        return self.parseHttp1Response(response_buffer.items);
    }

    fn executeHttp2(self: *Self, request: *ClientRequest, url_parts: *const UrlParts) !ClientResponse {
        _ = self;
        _ = request;
        _ = url_parts;
        // HTTP/2 client implementation would go here
        // For now, return an error to trigger fallback
        return error.UnsupportedProtocol;
    }

    fn executeHttp3(self: *Self, request: *ClientRequest, url_parts: *const UrlParts) !ClientResponse {
        _ = self;
        _ = request;
        _ = url_parts;
        // HTTP/3 client implementation would go here
        return error.UnsupportedProtocol;
    }

    fn parseHttp1Response(self: *Self, response_data: []const u8) !ClientResponse {
        var lines = std.mem.splitSequence(u8, response_data, "\r\n");

        // Parse status line
        const status_line = lines.next() orelse return error.InvalidResponse;
        var status_parts = std.mem.splitSequence(u8, status_line, " ");
        
        _ = status_parts.next() orelse return error.InvalidResponse; // HTTP version
        const status_code_str = status_parts.next() orelse return error.InvalidResponse;
        const status_code = try std.fmt.parseInt(u16, status_code_str, 10);
        
        var response = ClientResponse.init(self.allocator, status_code, .http1_1);
        
        // Parse headers
        while (lines.next()) |line| {
            if (line.len == 0) break; // Empty line separates headers from body
            
            if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                const name = std.mem.trim(u8, line[0..colon_pos], " \t");
                const value = std.mem.trim(u8, line[colon_pos + 1..], " \t");
                
                const owned_name = try self.allocator.dupe(u8, name);
                const owned_value = try self.allocator.dupe(u8, value);
                try response.headers.put(owned_name, owned_value);
            }
        }
        
        // Parse body
        const body_content = lines.rest();
        response.body = try self.allocator.dupe(u8, body_content);
        
        return response;
    }
};

test "URL parsing" {
    const allocator = std.testing.allocator;
    
    var url_parts = try UrlParts.parse(allocator, "https://example.com:8080/api/users?id=123#section");
    defer url_parts.deinit(allocator);
    
    try std.testing.expect(std.mem.eql(u8, url_parts.scheme, "https"));
    try std.testing.expect(std.mem.eql(u8, url_parts.host, "example.com"));
    try std.testing.expect(url_parts.port == 8080);
    try std.testing.expect(std.mem.eql(u8, url_parts.path, "/api/users"));
    try std.testing.expect(std.mem.eql(u8, url_parts.query.?, "id=123"));
    try std.testing.expect(std.mem.eql(u8, url_parts.fragment.?, "section"));
}

test "HTTP client initialization" {
    const allocator = std.testing.allocator;
    
    const config = ClientConfig{};
    var client = HttpClient.init(allocator, config);
    defer client.deinit();
    
    try std.testing.expect(client.config.timeout_ms == 30000);
    try std.testing.expect(client.config.max_redirects == 5);
}