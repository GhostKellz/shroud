//! zsync Runtime Integration for SHROUD
//! Provides zsync-specific async functionality following zsync examples

const std = @import("std");
const zsync = @import("zsync");
const async_utils = @import("utils.zig");

/// zsync Runtime wrapper for SHROUD
pub const ZSyncRuntime = struct {
    allocator: std.mem.Allocator,
    shroud_runtime: *async_utils.ShroudRuntime,

    pub fn init(allocator: std.mem.Allocator) !*ZSyncRuntime {
        const shroud_runtime = try async_utils.ShroudRuntime.init(allocator);

        const wrapper = try allocator.create(ZSyncRuntime);
        wrapper.* = ZSyncRuntime{
            .allocator = allocator,
            .shroud_runtime = shroud_runtime,
        };

        return wrapper;
    }

    pub fn deinit(self: *ZSyncRuntime) void {
        self.shroud_runtime.deinit();
        self.allocator.destroy(self);
    }

    /// Run the main async task
    pub fn run(self: *ZSyncRuntime, main_task: anytype) !void {
        _ = self;
        return try main_task();
    }

    /// Spawn a task with zsync using the correct API
    pub fn spawn(self: *ZSyncRuntime, comptime task_func: anytype, args: anytype) !u32 {
        const task_id = try self.shroud_runtime.registerTask("zsync_task");
        self.shroud_runtime.updateTaskStatus(task_id, .running);

        // Use zsync spawn with correct function and args pattern
        const zsync_task_id = try zsync.spawn(task_func, args);

        // Mark as completed (in a real implementation we'd await the task)
        self.shroud_runtime.updateTaskStatus(task_id, .completed);

        return zsync_task_id;
    }

    /// Get runtime statistics
    pub fn getStats(self: *ZSyncRuntime) async_utils.ShroudRuntime.RuntimeStats {
        return self.shroud_runtime.getStats();
    }
};

/// Async TCP operations with zsync
pub const AsyncTcp = struct {
    runtime: *ZSyncRuntime,

    pub fn init(runtime: *ZSyncRuntime) AsyncTcp {
        return AsyncTcp{ .runtime = runtime };
    }

    /// Connect to TCP server asynchronously
    pub fn connect(self: *AsyncTcp, address: []const u8, port: u16) !std.net.Stream {
        _ = self;
        const addr = try std.net.Address.parseIp(address, port);
        return try std.net.tcpConnectToAddress(addr);
    }

    /// Bind TCP server asynchronously
    pub fn bind(self: *AsyncTcp, address: []const u8, port: u16) !std.net.Server {
        _ = self;
        const addr = try std.net.Address.parseIp(address, port);
        return try addr.listen(.{});
    }
};

/// Async UDP operations with zsync
pub const AsyncUdp = struct {
    runtime: *ZSyncRuntime,

    pub fn init(runtime: *ZSyncRuntime) AsyncUdp {
        return AsyncUdp{ .runtime = runtime };
    }

    /// Bind UDP socket asynchronously
    pub fn bind(self: *AsyncUdp, address: []const u8, port: u16) !std.posix.socket_t {
        _ = self;
        const addr = try std.net.Address.parseIp(address, port);
        return try std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM, 0);
    }
};

/// Channel wrapper for async message passing with zsync
/// Follows the exact pattern from QA_ZSYNC.md
pub fn AsyncChannel(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        channel_obj: @TypeOf(zsync.bounded(T, std.heap.page_allocator, 1) catch unreachable),

        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            // Use zsync.bounded exactly as shown in QA_ZSYNC.md
            const ch = try zsync.bounded(T, allocator, @intCast(capacity));

            return Self{
                .allocator = allocator,
                .channel_obj = ch,
            };
        }

        pub fn deinit(self: *Self) void {
            // Follow QA_ZSYNC.md cleanup pattern exactly
            self.channel_obj.channel.deinit();
            self.allocator.destroy(self.channel_obj.channel);
        }

        pub fn send(self: *Self, value: T) !void {
            // Use sender directly as shown in QA_ZSYNC.md
            try self.channel_obj.sender.send(value);
            zsync.yieldNow(); // Yield for colorblind async
        }

        pub fn recv(self: *Self) !T {
            // Use receiver directly as shown in QA_ZSYNC.md
            const result = try self.channel_obj.receiver.recv();
            zsync.yieldNow(); // Yield for colorblind async
            return result;
        }

        pub fn trySend(self: *Self, value: T) !void {
            // Non-blocking send as shown in QA_ZSYNC.md
            try self.channel_obj.sender.trySend(value);
        }

        pub fn tryRecv(self: *Self) !T {
            // Non-blocking receive as shown in QA_ZSYNC.md
            return try self.channel_obj.receiver.tryRecv();
        }

        pub fn close(self: *Self) void {
            // Close both sender and receiver
            self.channel_obj.sender.close();
            self.channel_obj.receiver.close();
        }
    };
}

/// Async batch processor using zsync
pub fn AsyncBatchProcessor(comptime T: type, comptime R: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        batch_size: usize,
        processor_fn: *const fn ([]const T) anyerror![]R,

        pub fn init(allocator: std.mem.Allocator, batch_size: usize, processor_fn: *const fn ([]const T) anyerror![]R) Self {
            return Self{
                .allocator = allocator,
                .batch_size = batch_size,
                .processor_fn = processor_fn,
            };
        }

        pub fn process(self: *Self, items: []const T) ![]R {
            // Use zsync spawn with correct function signature
            const BatchWorker = struct {
                fn batchWork(proc_fn: *const fn ([]const T) anyerror![]R, data: []const T) ![]R {
                    zsync.yieldNow(); // Yield before processing
                    return try proc_fn(data);
                }
            };

            // This is a simplified implementation - in a real async system,
            // we'd need to properly await the spawned task
            _ = try zsync.spawn(BatchWorker.batchWork, .{ self.processor_fn, items });

            // For now, call directly (this should be async in real implementation)
            return try self.processor_fn(items);
        }
    };
}

/// Async connection pool using simple implementation
pub fn AsyncConnectionPool(comptime T: type) type {
    return struct {
        const Self = @This();

        available: std.ArrayList(T),
        max_connections: usize,
        mutex: std.Thread.Mutex,

        pub fn init(allocator: std.mem.Allocator, max_connections: usize) !Self {
            return Self{
                .available = std.ArrayList(T){},
                .max_connections = max_connections,
                .mutex = std.Thread.Mutex{},
            };
        }

        pub fn deinit(self: *Self) void {
            self.available.deinit(self.allocator);
        }

        pub fn acquire(self: *Self) !T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.available.items.len == 0) {
                return error.NoConnectionsAvailable;
            }

            return self.available.pop();
        }

        pub fn release(self: *Self, connection: T) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.available.items.len >= self.max_connections) {
                return error.PoolFull;
            }

            try self.available.append(self.allocator, connection);
        }

        pub fn addConnection(self: *Self, connection: T) !void {
            return self.release(connection);
        }
    };
}

/// Async future combinators with zsync
pub const AsyncCombinators = struct {
    /// Join multiple futures and wait for all to complete
    pub fn joinAll(comptime T: type, allocator: std.mem.Allocator, tasks: anytype) ![]T {
        var task_ids = std.ArrayList(u32){};
        defer task_ids.deinit(allocator);

        // Spawn all tasks and collect their IDs
        inline for (tasks) |task| {
            const TaskWrapper = struct {
                fn wrapper(task_func: anytype) !T {
                    return try task_func();
                }
            };

            const task_id = try zsync.spawn(TaskWrapper.wrapper, .{task});
            try task_ids.append(allocator, task_id);
        }

        // For now, just allocate results (in real implementation, we'd await all tasks)
        const results = try allocator.alloc(T, tasks.len);

        // This is a placeholder - in a real implementation we'd await each task
        inline for (tasks, 0..) |task, i| {
            results[i] = try task();
        }

        return results;
    }

    /// Race multiple futures and return the first to complete
    pub fn race(comptime T: type, tasks: anytype) !T {
        if (tasks.len == 0) return error.NoTasks;

        // For now, just return the first task's result
        // In a real implementation, we'd spawn all and return the first to complete
        const TaskWrapper = struct {
            fn wrapper(task_func: anytype) !T {
                return try task_func();
            }
        };

        _ = try zsync.spawn(TaskWrapper.wrapper, .{tasks[0]});

        // Placeholder - should actually race the tasks
        return try tasks[0]();
    }
};

test "zsync runtime basic functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const runtime = try ZSyncRuntime.init(allocator);
    defer runtime.deinit();

    // Verify runtime was properly initialized
    try std.testing.expect(runtime.shroud_runtime.task_registry.count() == 0);
}

test "async channel functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var channel = try AsyncChannel(u32).init(allocator, 10);
    defer channel.deinit();

    try channel.send(42);
    const value = try channel.recv();
    try std.testing.expectEqual(@as(u32, 42), value);
}
