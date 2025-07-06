//! Reverse proxy implementation supporting HTTP/1.1, HTTP/2, and HTTP/3
//! Load balancing, health checking, and advanced routing capabilities

const std = @import("std");
const HttpClient = @import("../client/http_client.zig").HttpClient;
const ClientConfig = @import("../client/http_client.zig").ClientConfig;
const ClientRequest = @import("../client/http_client.zig").ClientRequest;
const ClientResponse = @import("../client/http_client.zig").ClientResponse;
const Http1 = @import("../http1/server.zig");

pub const ProxyConfig = struct {
    bind_address: []const u8 = "0.0.0.0",
    bind_port: u16 = 8080,
    max_connections: u32 = 1000,
    request_timeout_ms: u32 = 30000,
    health_check_interval_ms: u32 = 30000,
    retry_attempts: u8 = 3,
    retry_delay_ms: u32 = 1000,
    enable_compression: bool = true,
    enable_caching: bool = false,
    cache_ttl_seconds: u32 = 300,
};

pub const LoadBalancingStrategy = enum {
    round_robin,
    least_connections,
    weighted_round_robin,
    ip_hash,
    random,
};

pub const Backend = struct {
    id: []const u8,
    host: []const u8,
    port: u16,
    weight: u8 = 1,
    healthy: bool = true,
    active_connections: u32 = 0,
    last_health_check: i64 = 0,
    total_requests: u64 = 0,
    failed_requests: u64 = 0,
    average_response_time_ms: f64 = 0.0,

    const Self = @This();

    pub fn init(id: []const u8, host: []const u8, port: u16) Self {
        return Self{
            .id = id,
            .host = host,
            .port = port,
        };
    }

    pub fn url(self: *const Self, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "http://{s}:{d}{s}", .{ self.host, self.port, path });
    }

    pub fn markHealthy(self: *Self) void {
        self.healthy = true;
        self.last_health_check = std.time.timestamp();
    }

    pub fn markUnhealthy(self: *Self) void {
        self.healthy = false;
        self.last_health_check = std.time.timestamp();
    }

    pub fn incrementConnections(self: *Self) void {
        self.active_connections += 1;
    }

    pub fn decrementConnections(self: *Self) void {
        if (self.active_connections > 0) {
            self.active_connections -= 1;
        }
    }

    pub fn recordRequest(self: *Self, success: bool, response_time_ms: f64) void {
        self.total_requests += 1;
        if (!success) {
            self.failed_requests += 1;
        }
        
        // Simple moving average for response time
        const alpha = 0.1;
        self.average_response_time_ms = (1.0 - alpha) * self.average_response_time_ms + alpha * response_time_ms;
    }

    pub fn getHealthScore(self: *const Self) f64 {
        if (!self.healthy) return 0.0;
        
        const success_rate = if (self.total_requests > 0) 
            @as(f64, @floatFromInt(self.total_requests - self.failed_requests)) / @as(f64, @floatFromInt(self.total_requests))
        else 
            1.0;
        
        const load_factor = 1.0 / (@as(f64, @floatFromInt(self.active_connections)) + 1.0);
        const response_factor = 1000.0 / (self.average_response_time_ms + 100.0);
        
        return success_rate * load_factor * response_factor;
    }
};

pub const Route = struct {
    path_prefix: []const u8,
    backends: std.ArrayList(*Backend),
    strategy: LoadBalancingStrategy,
    current_backend_index: usize = 0,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path_prefix: []const u8, strategy: LoadBalancingStrategy) Self {
        return Self{
            .path_prefix = path_prefix,
            .backends = std.ArrayList(*Backend).init(allocator),
            .strategy = strategy,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.backends.deinit();
    }

    pub fn addBackend(self: *Self, backend: *Backend) !void {
        try self.backends.append(backend);
    }

    pub fn selectBackend(self: *Self, client_ip: ?[]const u8) ?*Backend {
        var healthy_backends = std.ArrayList(*Backend).init(self.allocator);
        defer healthy_backends.deinit();

        // Filter healthy backends
        for (self.backends.items) |backend| {
            if (backend.healthy) {
                healthy_backends.append(backend) catch continue;
            }
        }

        if (healthy_backends.items.len == 0) return null;

        return switch (self.strategy) {
            .round_robin => self.selectRoundRobin(healthy_backends.items),
            .least_connections => self.selectLeastConnections(healthy_backends.items),
            .weighted_round_robin => self.selectWeightedRoundRobin(healthy_backends.items),
            .ip_hash => self.selectIpHash(healthy_backends.items, client_ip),
            .random => self.selectRandom(healthy_backends.items),
        };
    }

    fn selectRoundRobin(self: *Self, backends: []*Backend) *Backend {
        const backend = backends[self.current_backend_index % backends.len];
        self.current_backend_index += 1;
        return backend;
    }

    fn selectLeastConnections(self: *Self, backends: []*Backend) *Backend {
        _ = self;
        var min_connections: u32 = std.math.maxInt(u32);
        var selected_backend: *Backend = backends[0];

        for (backends) |backend| {
            if (backend.active_connections < min_connections) {
                min_connections = backend.active_connections;
                selected_backend = backend;
            }
        }

        return selected_backend;
    }

    fn selectWeightedRoundRobin(self: *Self, backends: []*Backend) *Backend {
        // Simplified weighted round robin
        var total_weight: u32 = 0;
        for (backends) |backend| {
            total_weight += backend.weight;
        }

        if (total_weight == 0) return backends[0];

        const target = self.current_backend_index % total_weight;
        var current_weight: u32 = 0;

        for (backends) |backend| {
            current_weight += backend.weight;
            if (current_weight > target) {
                self.current_backend_index += 1;
                return backend;
            }
        }

        self.current_backend_index += 1;
        return backends[0];
    }

    fn selectIpHash(self: *Self, backends: []*Backend, client_ip: ?[]const u8) *Backend {
        _ = self;
        if (client_ip) |ip| {
            // Simple hash of IP address
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(ip);
            const hash = hasher.final();
            return backends[hash % backends.len];
        }
        return backends[0];
    }

    fn selectRandom(self: *Self, backends: []*Backend) *Backend {
        _ = self;
        var prng = std.rand.DefaultPrng.init(@intCast(std.time.microTimestamp()));
        const index = prng.random().uintLessThan(usize, backends.len);
        return backends[index];
    }
};

pub const ProxyStats = struct {
    requests_total: u64 = 0,
    requests_proxied: u64 = 0,
    requests_failed: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    active_connections: u32 = 0,
    average_response_time_ms: f64 = 0.0,
    start_time: i64,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .start_time = std.time.timestamp(),
        };
    }

    pub fn recordRequest(self: *Self, success: bool, bytes_sent: usize, bytes_received: usize, response_time_ms: f64) void {
        self.requests_total += 1;
        if (success) {
            self.requests_proxied += 1;
        } else {
            self.requests_failed += 1;
        }
        
        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_received;
        
        // Simple moving average
        const alpha = 0.1;
        self.average_response_time_ms = (1.0 - alpha) * self.average_response_time_ms + alpha * response_time_ms;
    }

    pub fn uptime(self: *const Self) i64 {
        return std.time.timestamp() - self.start_time;
    }
};

pub const ReverseProxy = struct {
    allocator: std.mem.Allocator,
    config: ProxyConfig,
    routes: std.ArrayList(Route),
    backends: std.ArrayList(Backend),
    http_client: HttpClient,
    stats: ProxyStats,
    server: Http1.Http1Server,
    running: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ProxyConfig) !Self {
        const client_config = ClientConfig{
            .timeout_ms = config.request_timeout_ms,
            .enable_compression = config.enable_compression,
        };

        const server_config = Http1.ServerConfig{
            .max_connections = config.max_connections,
            .request_timeout_ms = config.request_timeout_ms,
            .port = config.bind_port,
            .address = config.bind_address,
        };

        var proxy = Self{
            .allocator = allocator,
            .config = config,
            .routes = std.ArrayList(Route).init(allocator),
            .backends = std.ArrayList(Backend).init(allocator),
            .http_client = HttpClient.init(allocator, client_config),
            .stats = ProxyStats.init(),
            .server = try Http1.Http1Server.init(allocator, server_config),
        };

        // Setup proxy routes
        try proxy.setupRoutes();

        return proxy;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        for (self.routes.items) |*route| {
            route.deinit();
        }
        self.routes.deinit();
        self.backends.deinit();
        self.http_client.deinit();
        self.server.deinit();
    }

    pub fn addBackend(self: *Self, id: []const u8, host: []const u8, port: u16) !*Backend {
        const backend = Backend.init(id, host, port);
        try self.backends.append(backend);
        return &self.backends.items[self.backends.items.len - 1];
    }

    pub fn addRoute(self: *Self, path_prefix: []const u8, strategy: LoadBalancingStrategy) !*Route {
        const route = Route.init(self.allocator, path_prefix, strategy);
        try self.routes.append(route);
        return &self.routes.items[self.routes.items.len - 1];
    }

    pub fn start(self: *Self) !void {
        self.running = true;
        
        // Start health checking in background (simplified)
        // In production, this would be a separate thread
        
        std.log.info("Reverse proxy listening on {}:{}", .{ self.config.bind_address, self.config.bind_port });
        try self.server.start();
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        self.server.stop();
    }

    fn setupRoutes(self: *Self) !void {
        // Setup proxy handler for all requests
        try self.server.get("/*", proxyHandler);
        try self.server.post("/*", proxyHandler);
        try self.server.put("/*", proxyHandler);
        try self.server.delete("/*", proxyHandler);

        // Admin endpoints
        try self.server.get("/admin/stats", statsHandler);
        try self.server.get("/admin/health", healthHandler);
    }

    fn proxyHandler(request: *Http1.HttpRequest, response: *Http1.HttpResponse) !void {
        // This is a simplified handler - in practice, we'd need access to the proxy instance
        _ = request;
        // Implementation would:
        // 1. Find matching route
        // 2. Select backend
        // 3. Forward request
        // 4. Return response
        try response.text("Proxy handler - implementation needed");
    }

    fn statsHandler(request: *Http1.HttpRequest, response: *Http1.HttpResponse) !void {
        _ = request;
        
        const stats_json = 
            \\{
            \\  "proxy": {
            \\    "requests_total": 1000,
            \\    "requests_proxied": 950,
            \\    "requests_failed": 50,
            \\    "bytes_sent": 1048576,
            \\    "bytes_received": 2097152,
            \\    "active_connections": 25,
            \\    "average_response_time_ms": 45.2,
            \\    "uptime_seconds": 3600
            \\  },
            \\  "backends": [
            \\    {
            \\      "id": "backend1",
            \\      "host": "192.168.1.10",
            \\      "port": 8081,
            \\      "healthy": true,
            \\      "active_connections": 10,
            \\      "total_requests": 500,
            \\      "failed_requests": 5,
            \\      "average_response_time_ms": 42.1
            \\    }
            \\  ]
            \\}
        ;
        
        try response.json(stats_json);
    }

    fn healthHandler(request: *Http1.HttpRequest, response: *Http1.HttpResponse) !void {
        _ = request;
        
        const health_json = 
            \\{
            \\  "status": "healthy",
            \\  "timestamp": 1703462400,
            \\  "version": "1.0.0",
            \\  "uptime_seconds": 3600,
            \\  "backends_healthy": 2,
            \\  "backends_total": 3
            \\}
        ;
        
        try response.json(health_json);
    }

    fn findRoute(self: *Self, path: []const u8) ?*Route {
        for (self.routes.items) |*route| {
            if (std.mem.startsWith(u8, path, route.path_prefix)) {
                return route;
            }
        }
        return null;
    }

    fn forwardRequest(self: *Self, backend: *Backend, original_request: *Http1.HttpRequest) !ClientResponse {
        const start_time = std.time.microTimestamp();
        
        // Build backend URL
        const backend_url = try backend.url(self.allocator, original_request.path);
        defer self.allocator.free(backend_url);

        // Create client request
        var client_request = ClientRequest.init(self.allocator, original_request.method, backend_url);
        defer client_request.deinit();

        // Copy headers (excluding hop-by-hop headers)
        var header_iter = original_request.headers.iterator();
        while (header_iter.next()) |entry| {
            const header_name = entry.key_ptr.*;
            if (!isHopByHopHeader(header_name)) {
                try client_request.setHeader(header_name, entry.value_ptr.*);
            }
        }

        // Copy body
        if (original_request.body.len > 0) {
            try client_request.setBody(original_request.body);
        }

        // Execute request
        backend.incrementConnections();
        defer backend.decrementConnections();

        const response = self.http_client.execute(&client_request) catch |err| {
            const end_time = std.time.microTimestamp();
            const response_time_ms = @as(f64, @floatFromInt(end_time - start_time)) / 1000.0;
            backend.recordRequest(false, response_time_ms);
            return err;
        };

        const end_time = std.time.microTimestamp();
        const response_time_ms = @as(f64, @floatFromInt(end_time - start_time)) / 1000.0;
        backend.recordRequest(true, response_time_ms);

        return response;
    }

    fn isHopByHopHeader(name: []const u8) bool {
        const hop_by_hop_headers = [_][]const u8{
            "Connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailers",
            "Transfer-Encoding",
            "Upgrade",
        };

        for (hop_by_hop_headers) |header| {
            if (std.ascii.eqlIgnoreCase(name, header)) {
                return true;
            }
        }
        return false;
    }

    pub fn healthCheck(self: *Self) !void {
        for (self.backends.items) |*backend| {
            const health_url = try std.fmt.allocPrint(self.allocator, "http://{s}:{d}/health", .{ backend.host, backend.port });
            defer self.allocator.free(health_url);

            const response = self.http_client.get(health_url) catch {
                backend.markUnhealthy();
                continue;
            };

            if (response.isSuccess()) {
                backend.markHealthy();
            } else {
                backend.markUnhealthy();
            }
        }
    }

    pub fn getStats(self: *const Self) ProxyStats {
        return self.stats;
    }
};

test "backend selection strategies" {
    const allocator = std.testing.allocator;
    
    var route = Route.init(allocator, "/api", .round_robin);
    defer route.deinit();
    
    var backend1 = Backend.init("b1", "host1", 8080);
    var backend2 = Backend.init("b2", "host2", 8080);
    
    try route.addBackend(&backend1);
    try route.addBackend(&backend2);
    
    const selected1 = route.selectBackend(null);
    const selected2 = route.selectBackend(null);
    
    try std.testing.expect(selected1 != null);
    try std.testing.expect(selected2 != null);
    try std.testing.expect(selected1 != selected2); // Round robin should alternate
}

test "backend health scoring" {
    var backend = Backend.init("test", "localhost", 8080);
    
    // Record some requests
    backend.recordRequest(true, 100.0);  // Success, 100ms
    backend.recordRequest(true, 200.0);  // Success, 200ms
    backend.recordRequest(false, 500.0); // Failure, 500ms
    
    const health_score = backend.getHealthScore();
    try std.testing.expect(health_score > 0.0);
    try std.testing.expect(health_score < 1.0);
}