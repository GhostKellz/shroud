zsync Integration Guide: Migrating Shroud from tokioZ

A focused checklist and code examples for upgrading Shroud (your cryptography/secrets toolkit) from tokioZ to zsync for async operations.
🚀 Overview

zsync is your modern async runtime for Zig. It supports blocking, green threads, thread pools, and stackless execution—all via a unified API. This makes async secret/key operations seamless, efficient, and future-proof.

Why migrate?

    Native support for Zig 0.15+ “colorblind async”

    Faster, zero-cost abstractions for crypto/key handling

    Full compatibility with new Zig I/O patterns and cancellation

🔄 Quick Migration Steps

    Replace Imports

        Change @import("tokioZ") → @import("zsync") everywhere

    Update Execution Models

        Use the right Io interface:

            BlockingIo for CPU-bound secret operations (keygen, encryption)

            GreenThreadsIo or ThreadPoolIo for I/O-bound secret exchange

const zsync = @import("zsync");
const Io = zsync.BlockingIo; // For most Shroud ops

Update Async Patterns

    Replace:

        tokioZ.spawn → zsync.spawn

        tokioZ.sleep → zsync.sleep

        tokioZ.bounded/unbounded → zsync.bounded/unbounded

    For all async secret/key functions, pass io and use .async() + .await():

    pub fn generateKeyAsync(allocator: std.mem.Allocator) !Key {
        const io = zsync.BlockingIo{};
        var future = io.async(keyGenWorker, .{allocator});
        defer future.cancel(io) catch {};
        return try future.await(io);
    }

    Add Proper Cancellation

        Always defer future.cancel(io) catch {} for cleanup.

    Yield During Long Ops

        In long crypto/keygen loops, call zsync.yieldNow(); for colorblind async compatibility.

🛠️ Example: Async Key Generation in Shroud

const std = @import("std");
const zsync = @import("zsync");

pub fn generateKeyAsync(allocator: std.mem.Allocator) ![32]u8 {
    const io = zsync.BlockingIo{};
    var future = io.async(keyGenWorker, .{allocator});
    defer future.cancel(io) catch {};
    return try future.await(io);
}

fn keyGenWorker(allocator: std.mem.Allocator) ![32]u8 {
    // Simulate heavy work
    for (0..10_000) |_| {
        zsync.yieldNow();
    }
    var key: [32]u8 = undefined;
    try std.crypto.random.bytes(&key);
    return key;
}

✅ Migration Checklist for Shroud

@import("tokioZ") → @import("zsync")

All async/await logic uses the appropriate Io interface

Secret/keygen/crypto ops use BlockingIo (CPU-bound)

Channel usage updated to zsync.bounded/unbounded

Proper cancellation for all async futures

Yield in all long-running secret/crypto ops

Compile & test on Zig 0.15+

    All tests and benchmarks pass

📈 Performance Notes

    Use BlockingIo for CPU-intensive secrets/crypto (almost everything in Shroud).

    Use GreenThreadsIo for secret streaming or async file/network operations.

    Leverage zsync.yieldNow() liberally in loops for best async behavior.