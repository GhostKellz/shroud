//! Async crypto operations using zsync
//! Demonstrates zsync patterns for CPU-intensive cryptographic operations

const std = @import("std");
const zsync = @import("zsync");

/// Async key generation using zsync BlockingIo
pub fn generateKeyAsync(allocator: std.mem.Allocator) ![32]u8 {
    const io = zsync.BlockingIo{};
    var future = io.async(keyGenWorker, .{allocator});
    defer future.cancel(io) catch {};
    return try future.await(io);
}

fn keyGenWorker(allocator: std.mem.Allocator) ![32]u8 {
    _ = allocator; // Not needed for this simple example

    // Simulate heavy cryptographic work with yields for colorblind async
    for (0..10_000) |_| {
        zsync.yieldNow();
    }

    var key: [32]u8 = undefined;
    try std.crypto.random.bytes(&key);
    return key;
}

/// Async hash computation using zsync BlockingIo
pub fn hashDataAsync(data: []const u8) ![32]u8 {
    const io = zsync.BlockingIo{};
    var future = io.async(hashWorker, .{data});
    defer future.cancel(io) catch {};
    return try future.await(io);
}

fn hashWorker(data: []const u8) ![32]u8 {
    // Yield for large data processing
    if (data.len > 1024) {
        zsync.yieldNow();
    }

    var hasher = std.crypto.hash.blake3.Blake3.init(.{});
    hasher.update(data);
    return hasher.final();
}

/// Async signature generation using zsync BlockingIo
pub fn signDataAsync(data: []const u8, private_key: [32]u8) ![64]u8 {
    const io = zsync.BlockingIo{};
    var future = io.async(signWorker, .{ data, private_key });
    defer future.cancel(io) catch {};
    return try future.await(io);
}

fn signWorker(data: []const u8, private_key: [32]u8) ![64]u8 {
    // Yield before expensive signing operation
    zsync.yieldNow();

    const keypair = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(private_key);
    return try keypair.sign(data, null).toBytes();
}

/// Async signature verification using zsync BlockingIo
pub fn verifySignatureAsync(data: []const u8, signature: [64]u8, public_key: [32]u8) !bool {
    const io = zsync.BlockingIo{};
    var future = io.async(verifyWorker, .{ data, signature, public_key });
    defer future.cancel(io) catch {};
    return try future.await(io);
}

fn verifyWorker(data: []const u8, signature: [64]u8, public_key: [32]u8) !bool {
    // Yield before verification
    zsync.yieldNow();

    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    const pub_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key);

    sig.verify(data, pub_key) catch return false;
    return true;
}

/// Batch async processing of crypto operations using zsync channels
pub fn batchProcessAsync(comptime T: type, allocator: std.mem.Allocator, items: []const T, processor: anytype) ![]T {
    const io = zsync.ThreadPoolIo{}; // Use ThreadPool for batch operations

    var results = std.ArrayList(T).init(allocator);
    defer results.deinit();

    // Create a channel for work distribution
    const channel = try zsync.bounded(T, items.len);
    defer channel.close();

    // Send work items
    for (items) |item| {
        var send_future = io.async(sendWork, .{ channel.sender(), item });
        defer send_future.cancel(io) catch {};
        try send_future.await(io);
    }

    // Process results
    for (0..items.len) |_| {
        var recv_future = io.async(recvAndProcess, .{ channel.receiver(), processor });
        defer recv_future.cancel(io) catch {};
        const result = try recv_future.await(io);
        try results.append(result);
    }

    return try results.toOwnedSlice();
}

fn sendWork(comptime T: type, sender: zsync.Sender(T), item: T) !void {
    try sender.send(item);
}

fn recvAndProcess(comptime T: type, receiver: zsync.Receiver(T), processor: anytype) !T {
    const item = try receiver.recv();
    zsync.yieldNow(); // Yield before processing
    return try processor(item);
}

test "async crypto operations" {
    const allocator = std.testing.allocator;

    // Test async key generation
    const key = try generateKeyAsync(allocator);
    try std.testing.expect(key.len == 32);

    // Test async hashing
    const data = "Hello, zsync crypto!";
    const hash = try hashDataAsync(data);
    try std.testing.expect(hash.len == 32);

    // Test async signing and verification
    const signature = try signDataAsync(data, key);
    try std.testing.expect(signature.len == 64);
}
