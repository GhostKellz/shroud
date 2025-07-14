//! SHROUD Async Module
//! Main entry point for all async functionality in SHROUD 1.0.0
//! Integrates zsync async runtime with SHROUD components

const std = @import("std");

// Re-export core async functionality
pub const utils = @import("utils.zig");
pub const zsync_integration = @import("zsync_integration.zig");

// Core types
pub const ShroudRuntime = utils.ShroudRuntime;
pub const AsyncAllocator = utils.AsyncAllocator;
pub const ConnectionPool = utils.ConnectionPool;
pub const ZSyncRuntime = zsync_integration.ZSyncRuntime;

// Networking primitives
pub const AsyncTcp = zsync_integration.AsyncTcp;
pub const AsyncUdp = zsync_integration.AsyncUdp;

// Channel types
pub const AsyncChannel = zsync_integration.AsyncChannel;

// Connection pools
pub const AsyncConnectionPool = zsync_integration.AsyncConnectionPool;

// Batch processing
pub const AsyncBatchProcessor = zsync_integration.AsyncBatchProcessor;

// Future combinators
pub const AsyncCombinators = zsync_integration.AsyncCombinators;

/// SHROUD Async Runtime - Global singleton
var global_runtime: ?*ZSyncRuntime = null;
var runtime_mutex = std.Thread.Mutex{};

/// Initialize the global SHROUD async runtime
pub fn initGlobalRuntime(allocator: std.mem.Allocator) !*ZSyncRuntime {
    runtime_mutex.lock();
    defer runtime_mutex.unlock();

    if (global_runtime != null) {
        return error.RuntimeAlreadyInitialized;
    }

    global_runtime = try ZSyncRuntime.init(allocator);
    return global_runtime.?;
}

/// Get the global SHROUD async runtime
pub fn getGlobalRuntime() ?*ZSyncRuntime {
    runtime_mutex.lock();
    defer runtime_mutex.unlock();

    return global_runtime;
}

/// Shutdown the global SHROUD async runtime
pub fn shutdownGlobalRuntime() void {
    runtime_mutex.lock();
    defer runtime_mutex.unlock();

    if (global_runtime) |runtime| {
        runtime.deinit();
        global_runtime = null;
    }
}

/// Async task types for SHROUD components
pub const TaskType = enum {
    network_connection,
    contract_execution,
    transaction_processing,
    cache_operation,
    crypto_operation,
    dns_resolution,
    wallet_operation,
    audit_log,
    system_monitoring,
};

/// SHROUD task wrapper with metadata
pub const ShroudTask = struct {
    id: u64,
    task_type: TaskType,
    component: []const u8,
    priority: u8, // 0 = lowest, 255 = highest
    created_at: i64,
    started_at: ?i64 = null,
    completed_at: ?i64 = null,

    pub fn init(task_type: TaskType, component: []const u8, priority: u8) ShroudTask {
        return ShroudTask{
            .id = @intCast(std.time.milliTimestamp()),
            .task_type = task_type,
            .component = component,
            .priority = priority,
            .created_at = std.time.milliTimestamp(),
        };
    }

    pub fn markStarted(self: *ShroudTask) void {
        self.started_at = std.time.milliTimestamp();
    }

    pub fn markCompleted(self: *ShroudTask) void {
        self.completed_at = std.time.milliTimestamp();
    }

    pub fn getDuration(self: *const ShroudTask) ?i64 {
        if (self.started_at == null or self.completed_at == null) return null;
        return self.completed_at.? - self.started_at.?;
    }
};

/// Performance metrics for async operations
pub const AsyncMetrics = struct {
    total_tasks: u64 = 0,
    completed_tasks: u64 = 0,
    failed_tasks: u64 = 0,
    avg_task_duration_ms: f64 = 0.0,
    peak_concurrent_tasks: u32 = 0,
    current_concurrent_tasks: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    tasks_by_type: std.EnumMap(TaskType, u64) = std.EnumMap(TaskType, u64).init(.{}),

    pub fn recordTaskStart(self: *AsyncMetrics, task_type: TaskType) void {
        _ = self.current_concurrent_tasks.fetchAdd(1, .monotonic);
        const current = self.current_concurrent_tasks.load(.monotonic);

        if (current > self.peak_concurrent_tasks) {
            self.peak_concurrent_tasks = current;
        }

        self.total_tasks += 1;
        const current_count = self.tasks_by_type.get(task_type) orelse 0;
        self.tasks_by_type.put(task_type, current_count + 1);
    }

    pub fn recordTaskCompletion(self: *AsyncMetrics, duration_ms: f64, success: bool) void {
        _ = self.current_concurrent_tasks.fetchSub(1, .monotonic);

        if (success) {
            self.completed_tasks += 1;

            // Update rolling average
            const total_completed = @as(f64, @floatFromInt(self.completed_tasks));
            self.avg_task_duration_ms = (self.avg_task_duration_ms * (total_completed - 1.0) + duration_ms) / total_completed;
        } else {
            self.failed_tasks += 1;
        }
    }

    pub fn getSuccessRate(self: *const AsyncMetrics) f64 {
        if (self.total_tasks == 0) return 0.0;
        return @as(f64, @floatFromInt(self.completed_tasks)) / @as(f64, @floatFromInt(self.total_tasks));
    }
};

/// Global metrics instance
var global_metrics = AsyncMetrics{};
var metrics_mutex = std.Thread.Mutex{};

/// Get global async metrics
pub fn getMetrics() AsyncMetrics {
    metrics_mutex.lock();
    defer metrics_mutex.unlock();

    return global_metrics;
}

/// Record task metrics
pub fn recordTaskMetrics(task: *const ShroudTask, success: bool) void {
    metrics_mutex.lock();
    defer metrics_mutex.unlock();

    if (task.getDuration()) |duration| {
        global_metrics.recordTaskCompletion(@as(f64, @floatFromInt(duration)), success);
    }
}

/// Helper function to spawn a tracked SHROUD task
pub fn spawnTask(comptime task_type: TaskType, comptime component: []const u8, priority: u8, task_fn: anytype) !void {
    const runtime = getGlobalRuntime() orelse return error.RuntimeNotInitialized;

    const task_metadata = ShroudTask.init(task_type, component, priority);

    // Record task start metrics
    {
        metrics_mutex.lock();
        defer metrics_mutex.unlock();
        global_metrics.recordTaskStart(task_type);
    }

    // Spawn the actual task
    _ = try runtime.spawn(struct {
        fn wrapper() anyerror!void {
            var task_meta = task_metadata;
            task_meta.markStarted();

            const success = blk: {
                task_fn() catch |err| {
                    std.log.err("Task {} failed: {}", .{ task_meta.id, err });
                    break :blk false;
                };
                break :blk true;
            };

            task_meta.markCompleted();
            recordTaskMetrics(&task_meta, success);
        }
    }.wrapper);
}

/// Async utilities for common SHROUD patterns
pub const ShroudAsync = struct {
    /// Run multiple async operations concurrently and wait for all
    pub fn concurrentAll(comptime T: type, operations: []const fn () anyerror!T) ![]T {
        const runtime = getGlobalRuntime() orelse return error.RuntimeNotInitialized;

        var tasks = std.ArrayList(@TypeOf(try runtime.spawn(operations[0]))).init(runtime.allocator);
        defer tasks.deinit();

        // Spawn all operations
        for (operations) |op| {
            const task = try runtime.spawn(op);
            try tasks.append(task);
        }

        // Collect results
        var results = std.ArrayList(T).init(runtime.allocator);
        defer results.deinit();

        for (tasks.items) |task| {
            const result = try task.await();
            try results.append(result);
        }

        return try results.toOwnedSlice();
    }

    /// Timeout wrapper for any async operation
    pub fn withTimeout(comptime T: type, comptime timeout_ms: u64, operation: fn () anyerror!T) !T {
        const runtime = getGlobalRuntime() orelse return error.RuntimeNotInitialized;

        return try runtime.timeout(timeout_ms, operation());
    }

    /// Retry wrapper for async operations
    pub fn withRetry(comptime T: type, max_attempts: u32, operation: fn () anyerror!T) !T {
        var attempts: u32 = 0;
        var last_error: anyerror = undefined;

        while (attempts < max_attempts) {
            operation() catch |err| {
                last_error = err;
                attempts += 1;

                if (attempts < max_attempts) {
                    // Exponential backoff
                    const delay_ms = @as(u64, 100) * (@as(u64, 1) << @intCast(attempts - 1));
                    std.time.sleep(delay_ms * std.time.ns_per_ms);
                    continue;
                }

                return err;
            };

            return try operation();
        }

        return last_error;
    }
};

test "shroud async module basic functionality" {
    _ = try initGlobalRuntime(std.testing.allocator);
    defer shutdownGlobalRuntime();

    // Test basic runtime functionality
    try std.testing.expect(getGlobalRuntime() != null);

    // Test metrics
    const initial_metrics = getMetrics();
    try std.testing.expectEqual(@as(u64, 0), initial_metrics.total_tasks);
}

test "shroud task metadata" {
    var task = ShroudTask.init(.network_connection, "ghostwire", 128);

    try std.testing.expectEqual(TaskType.network_connection, task.task_type);
    try std.testing.expectEqualStrings("ghostwire", task.component);
    try std.testing.expectEqual(@as(u8, 128), task.priority);

    task.markStarted();
    try std.testing.expect(task.started_at != null);

    std.time.sleep(1 * std.time.ns_per_ms);

    task.markCompleted();
    try std.testing.expect(task.completed_at != null);
    try std.testing.expect(task.getDuration() != null);
    try std.testing.expect(task.getDuration().? > 0);
}

test "async metrics tracking" {
    var metrics = AsyncMetrics{};

    metrics.recordTaskStart(.contract_execution);
    try std.testing.expectEqual(@as(u64, 1), metrics.total_tasks);
    try std.testing.expectEqual(@as(u32, 1), metrics.current_concurrent_tasks.load(.monotonic));

    metrics.recordTaskCompletion(100.0, true);
    try std.testing.expectEqual(@as(u64, 1), metrics.completed_tasks);
    try std.testing.expectEqual(@as(u32, 0), metrics.current_concurrent_tasks.load(.monotonic));
    try std.testing.expectEqual(@as(f64, 100.0), metrics.avg_task_duration_ms);
    try std.testing.expectEqual(@as(f64, 1.0), metrics.getSuccessRate());
}
