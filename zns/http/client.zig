const std = @import("std");

/// Simple HTTP client for external API calls
pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) HttpClient {
        return HttpClient{
            .allocator = allocator,
        };
    }
    
    pub const HttpResponse = struct {
        status_code: u16,
        body: []u8,
        
        pub fn deinit(self: *HttpResponse, allocator: std.mem.Allocator) void {
            allocator.free(self.body);
        }
    };
    
    pub const HttpHeader = struct {
        name: []const u8,
        value: []const u8,
    };
    
    pub const RequestOptions = struct {
        headers: ?[]const HttpHeader = null,
        timeout_ms: u32 = 30000,
    };
    
    /// Make HTTP GET request
    pub fn get(self: *HttpClient, url: []const u8, options: RequestOptions) !HttpResponse {
        _ = options;
        
        // Parse URL
        const uri = try std.Uri.parse(url);
        
        // Create HTTP client
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();
        
        // Prepare headers
        var header_buf: [8192]u8 = undefined;
        
        // Create request
        var req = try http_client.open(.GET, uri, .{
            .server_header_buffer = &header_buf,
        });
        defer req.deinit();
        
        // Send request
        try req.send();
        try req.finish();
        try req.wait();
        
        // Read response
        const body = try req.reader().readAllAlloc(self.allocator, 1024 * 1024);
        
        return HttpResponse{
            .status_code = @intFromEnum(req.response.status),
            .body = body,
        };
    }
    
    /// Make HTTP POST request
    pub fn post(self: *HttpClient, url: []const u8, body: []const u8, options: RequestOptions) !HttpResponse {
        _ = options;
        
        // Parse URL
        const uri = try std.Uri.parse(url);
        
        // Create HTTP client
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();
        
        // Prepare headers
        var header_buf: [8192]u8 = undefined;
        
        // Create request with headers
        var req = try http_client.open(.POST, uri, .{
            .server_header_buffer = &header_buf,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        });
        defer req.deinit();
        
        // Send request with body
        try req.send();
        try req.writeAll(body);
        try req.finish();
        try req.wait();
        
        // Read response
        const response_body = try req.reader().readAllAlloc(self.allocator, 1024 * 1024);
        
        return HttpResponse{
            .status_code = @intFromEnum(req.response.status),
            .body = response_body,
        };
    }
};

/// JSON RPC client for Ethereum calls
pub const JsonRpcClient = struct {
    http_client: HttpClient,
    endpoint: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) JsonRpcClient {
        return JsonRpcClient{
            .http_client = HttpClient.init(allocator),
            .endpoint = endpoint,
        };
    }
    
    /// Call Ethereum contract function using raw JSON
    pub fn ethCall(self: *JsonRpcClient, to: []const u8, data: []const u8) ![]u8 {
        // Build JSON-RPC request manually
        const request_json = try std.fmt.allocPrint(self.http_client.allocator,
            \\{{
            \\  "jsonrpc": "2.0",
            \\  "id": 1,
            \\  "method": "eth_call",
            \\  "params": [{{
            \\    "to": "{s}",
            \\    "data": "{s}"
            \\  }}, "latest"]
            \\}}
        , .{ to, data });
        defer self.http_client.allocator.free(request_json);
        
        // Make HTTP request
        var response = try self.http_client.post(self.endpoint, request_json, .{});
        defer response.deinit(self.http_client.allocator);
        
        // Parse response manually to extract result
        const response_str = response.body;
        
        // Look for "result":"0x..."
        if (std.mem.indexOf(u8, response_str, "\"result\":")) |result_start| {
            const value_start = result_start + 10; // Skip "result":"
            if (std.mem.indexOf(u8, response_str[value_start..], "\"")) |quote_pos| {
                const result_value = response_str[value_start..value_start + quote_pos];
                return self.http_client.allocator.dupe(u8, result_value);
            }
        }
        
        // Check for error
        if (std.mem.indexOf(u8, response_str, "\"error\"")) |_| {
            return error.RpcError;
        }
        
        return error.InvalidResponse;
    }
};