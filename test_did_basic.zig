const std = @import("std");
const did_resolver = @import("src/did_resolver.zig");

test "basic DID resolver creation" {
    var resolver = did_resolver.DIDResolver.init(std.testing.allocator, 300, 100);
    defer resolver.deinit();

    // Just test creation and cleanup
    try std.testing.expect(resolver.cache_ttl_seconds == 300);
    try std.testing.expect(resolver.max_cache_size == 100);
}

test "transaction context creation" {
    var tx_context = did_resolver.TransactionContext.init(std.testing.allocator, "tx-001", .payment, "did:shroud:alice");
    defer tx_context.deinit();

    tx_context.setAmount(5000, "USD");
    try std.testing.expect(tx_context.amount.? == 5000);
}
