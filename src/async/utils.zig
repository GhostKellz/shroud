//! SHROUD Async Runtime Integration
//! Core async utilities and patterns for zsync integration

const std = @import("std");
const time_utils = @import("../time_utils.zig");

/// SHROUD Async Runtime - Central async coordination point
pub const ShroudRuntime = struct {
    allocator: std.mem.Allocator,
    task_registry: std.ArrayHashMap(u64, TaskInfo, std.array_hash_map.AutoContext(u64), true),
    next_task_id: std.atomic.Value(u64),

    const TaskInfo = struct {
        id: u64,
        name: []const u8,
        start_time: i64,
        status: TaskStatus,

        const TaskStatus = enum {
            pending,
            running,
            completed,
            failed,
            cancelled,
        };
    };

    pub fn init(allocator: std.mem.Allocator) !*ShroudRuntime {
        const runtime = try allocator.create(ShroudRuntime);
        runtime.* = ShroudRuntime{
            .allocator = allocator,
            .task_registry = std.ArrayHashMap(u64, TaskInfo, std.array_hash_map.AutoContext(u64), true).init(allocator),
            .next_task_id = std.atomic.Value(u64).init(1),
        };
        return runtime;
    }

    pub fn deinit(self: *ShroudRuntime) void {
        self.task_registry.deinit();
        self.allocator.destroy(self);
    }

    /// Register a task for tracking
    pub fn registerTask(self: *ShroudRuntime, name: []const u8) !u64 {
        const task_id = self.next_task_id.fetchAdd(1, .monotonic);

        const task_info = TaskInfo{
            .id = task_id,
            .name = name,
            .start_time = time_utils.milliTimestamp(),
            .status = .pending,
        };

        try self.task_registry.put(task_id, task_info);
        return task_id;
    }

    /// Update task status
    pub fn updateTaskStatus(self: *ShroudRuntime, task_id: u64, status: TaskInfo.TaskStatus) void {
        if (self.task_registry.getPtr(task_id)) |info| {
            info.status = status;
        }
    }

    /// Get runtime statistics
    pub fn getStats(self: *ShroudRuntime) RuntimeStats {
        var stats = RuntimeStats{};

        var iterator = self.task_registry.iterator();
        while (iterator.next()) |entry| {
            const task_info = entry.value_ptr.*;
            switch (task_info.status) {
                .pending => stats.pending_tasks += 1,
                .running => stats.running_tasks += 1,
                .completed => stats.completed_tasks += 1,
                .failed => stats.failed_tasks += 1,
                .cancelled => stats.cancelled_tasks += 1,
            }
        }

        return stats;
    }

    const RuntimeStats = struct {
        pending_tasks: u32 = 0,
        running_tasks: u32 = 0,
        completed_tasks: u32 = 0,
        failed_tasks: u32 = 0,
        cancelled_tasks: u32 = 0,
    };
};

/// Async-compatible allocator wrapper
pub const AsyncAllocator = struct {
    base_allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    pub fn init(base_allocator: std.mem.Allocator) AsyncAllocator {
        return AsyncAllocator{
            .base_allocator = base_allocator,
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn alloc(self: *AsyncAllocator, comptime T: type, n: usize) ![]T {
        self.mutex.lock();
        defer self.mutex.unlock();
        return try self.base_allocator.alloc(T, n);
    }

    pub fn free(self: *AsyncAllocator, memory: anytype) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.base_allocator.free(memory);
    }

    pub fn allocator(self: *AsyncAllocator) std.mem.Allocator {
        return self.base_allocator;
    }
};

/// Connection pool for async operations
pub fn ConnectionPool(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        connections: std.ArrayList(*T),
        available: std.ArrayList(bool),
        mutex: std.Thread.Mutex,
        factory: *const fn (allocator: std.mem.Allocator) anyerror!*T,
        destroyer: *const fn (item: *T) void,
        max_size: u32,

        pub fn init(
            allocator: std.mem.Allocator,
            max_size: u32,
            factory: *const fn (allocator: std.mem.Allocator) anyerror!*T,
            destroyer: *const fn (item: *T) void,
        ) !Self {
            return Self{
                .allocator = allocator,
                .connections = std.ArrayList(*T){},
                .available = std.ArrayList(bool){},
                .mutex = std.Thread.Mutex{},
                .factory = factory,
                .destroyer = destroyer,
                .max_size = max_size,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.connections.items) |conn| {
                self.destroyer(conn);
            }
            self.connections.deinit(self.allocator);
            self.available.deinit(self.allocator);
        }

        pub fn acquire(self: *Self) !*T {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Look for available connection
            for (self.available.items, 0..) |available, i| {
                if (available) {
                    self.available.items[i] = false;
                    return self.connections.items[i];
                }
            }

            // Create new if under limit
            if (self.connections.items.len < self.max_size) {
                const conn = try self.factory(self.allocator);
                try self.connections.append(self.allocator, conn);
                try self.available.append(self.allocator, false);
                return conn;
            }

            return error.PoolExhausted;
        }

        pub fn release(self: *Self, item: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            for (self.connections.items, 0..) |conn, i| {
                if (conn == item) {
                    self.available.items[i] = true;
                    break;
                }
            }
        }
    };
}

/// Async utilities and helpers
pub const AsyncUtils = struct {
    /// Simple async delay using std.time
    pub fn delay(duration_ms: u64) void {
        std.Thread.sleep(duration_ms * std.time.ns_per_ms);
    }

    /// Retry with exponential backoff
    pub fn retryWithBackoff(
        comptime max_attempts: u32,
        comptime base_delay_ms: u64,
        operation: anytype,
    ) !@TypeOf(operation()).ErrorUnion.Payload {
        var attempt: u32 = 0;
        var delay_ms = base_delay_ms;

        while (attempt < max_attempts) : (attempt += 1) {
            const result = operation() catch |err| {
                if (attempt == max_attempts - 1) {
                    return err;
                }

                delay(delay_ms);
                delay_ms *= 2;
                continue;
            };

            return result;
        }

        return error.MaxRetriesExceeded;
    }
};

test "runtime basic functionality" {
    const runtime = try ShroudRuntime.init(std.testing.allocator);
    defer runtime.deinit();

    const task_id = try runtime.registerTask("test_task");
    runtime.updateTaskStatus(task_id, .running);
    runtime.updateTaskStatus(task_id, .completed);

    const stats = runtime.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats.completed_tasks);
}

test "async allocator" {
    var async_alloc = AsyncAllocator.init(std.testing.allocator);

    const memory = try async_alloc.alloc(u8, 100);
    defer async_alloc.free(memory);

    try std.testing.expectEqual(@as(usize, 100), memory.len);
}
