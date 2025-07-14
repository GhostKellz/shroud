//! Async DNS resolution using zsync
//! Demonstrates zsync patterns for I/O-bound DNS operations

const std = @import("std");
const zsync = @import("zsync");

pub const AsyncResolver = struct {
    allocator: std.mem.Allocator,
    cache: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) AsyncResolver {
        return AsyncResolver{
            .allocator = allocator,
            .cache = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *AsyncResolver) void {
        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.cache.deinit();
    }

    /// Async DNS resolution using GreenThreadsIo for I/O operations
    pub fn resolveAsync(self: *AsyncResolver, domain: []const u8) ![]const u8 {
        const io = zsync.GreenThreadsIo{};
        var future = io.async(resolveWorker, .{ self, domain });
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn resolveWorker(self: *AsyncResolver, domain: []const u8) ![]const u8 {
        // Check cache first
        if (self.cache.get(domain)) |cached| {
            return cached;
        }

        // Yield before I/O operation
        zsync.yieldNow();

        // Simulate DNS resolution
        const resolved = try self.allocator.dupe(u8, "192.168.1.1");
        try self.cache.put(try self.allocator.dupe(u8, domain), resolved);

        return resolved;
    }

    /// Batch async DNS resolution using channels
    pub fn batchResolveAsync(self: *AsyncResolver, domains: []const []const u8) ![][]const u8 {
        const io = zsync.ThreadPoolIo{}; // Use ThreadPool for concurrent resolutions

        var results = std.ArrayList([]const u8).init(self.allocator);
        defer results.deinit();

        // Create channel for work distribution
        const work_channel = try zsync.bounded([]const u8, domains.len);
        defer work_channel.close();

        const result_channel = try zsync.bounded([]const u8, domains.len);
        defer result_channel.close();

        // Send domains to work channel
        for (domains) |domain| {
            var send_future = io.async(sendDomain, .{ work_channel.sender(), domain });
            defer send_future.cancel(io) catch {};
            try send_future.await(io);
        }

        // Process domains concurrently
        for (0..domains.len) |_| {
            var process_future = io.async(processDomain, .{ self, work_channel.receiver(), result_channel.sender() });
            defer process_future.cancel(io) catch {};
            try process_future.await(io);
        }

        // Collect results
        for (0..domains.len) |_| {
            var recv_future = io.async(recvResult, .{result_channel.receiver()});
            defer recv_future.cancel(io) catch {};
            const result = try recv_future.await(io);
            try results.append(result);
        }

        return try results.toOwnedSlice();
    }

    fn sendDomain(sender: zsync.Sender([]const u8), domain: []const u8) !void {
        try sender.send(domain);
    }

    fn processDomain(self: *AsyncResolver, work_receiver: zsync.Receiver([]const u8), result_sender: zsync.Sender([]const u8)) !void {
        const domain = try work_receiver.recv();
        const result = try self.resolveWorker(domain);
        try result_sender.send(result);
    }

    fn recvResult(receiver: zsync.Receiver([]const u8)) ![]const u8 {
        return try receiver.recv();
    }
};

/// Async cache operations using zsync
pub const AsyncCache = struct {
    cache: std.StringHashMap(CacheEntry),
    allocator: std.mem.Allocator,

    const CacheEntry = struct {
        value: []const u8,
        timestamp: i64,
        ttl: i64,
    };

    pub fn init(allocator: std.mem.Allocator) AsyncCache {
        return AsyncCache{
            .cache = std.StringHashMap(CacheEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AsyncCache) void {
        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.value);
        }
        self.cache.deinit();
    }

    /// Async cache get using BlockingIo
    pub fn getAsync(self: *AsyncCache, key: []const u8) !?[]const u8 {
        const io = zsync.BlockingIo{};
        var future = io.async(getWorker, .{ self, key });
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn getWorker(self: *AsyncCache, key: []const u8) !?[]const u8 {
        zsync.yieldNow();

        if (self.cache.get(key)) |entry| {
            const now = std.time.timestamp();
            if (now - entry.timestamp < entry.ttl) {
                return entry.value;
            } else {
                // Entry expired, remove it
                const owned_key = try self.allocator.dupe(u8, key);
                defer self.allocator.free(owned_key);
                _ = self.cache.remove(owned_key);
                self.allocator.free(entry.value);
            }
        }

        return null;
    }

    /// Async cache set using BlockingIo
    pub fn setAsync(self: *AsyncCache, key: []const u8, value: []const u8, ttl: i64) !void {
        const io = zsync.BlockingIo{};
        var future = io.async(setWorker, .{ self, key, value, ttl });
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    fn setWorker(self: *AsyncCache, key: []const u8, value: []const u8, ttl: i64) !void {
        zsync.yieldNow();

        const owned_key = try self.allocator.dupe(u8, key);
        const owned_value = try self.allocator.dupe(u8, value);

        const entry = CacheEntry{
            .value = owned_value,
            .timestamp = std.time.timestamp(),
            .ttl = ttl,
        };

        try self.cache.put(owned_key, entry);
    }
};

test "async DNS resolution" {
    const allocator = std.testing.allocator;

    var resolver = AsyncResolver.init(allocator);
    defer resolver.deinit();

    // Test single resolution
    const result = try resolver.resolveAsync("example.com");
    try std.testing.expectEqualStrings("192.168.1.1", result);

    // Test cached resolution
    const cached_result = try resolver.resolveAsync("example.com");
    try std.testing.expectEqualStrings("192.168.1.1", cached_result);
}

test "async cache operations" {
    const allocator = std.testing.allocator;

    var cache = AsyncCache.init(allocator);
    defer cache.deinit();

    // Test cache set and get
    try cache.setAsync("key1", "value1", 3600);

    const result = try cache.getAsync("key1");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("value1", result.?);

    // Test cache miss
    const miss = try cache.getAsync("nonexistent");
    try std.testing.expect(miss == null);
}
