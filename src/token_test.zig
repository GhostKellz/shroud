const std = @import("std");
const testing = std.testing;
const access_token = @import("access_token.zig");
const guardian = @import("guardian.zig");

test "keypair generation from passphrase" {
    const keypair = try access_token.generateKeyPair("test_passphrase");
    
    try testing.expect(keypair.private_key.bytes.len == 32);
    try testing.expect(keypair.public_key.bytes.len == 32);
}

test "ephemeral keypair generation" {
    const keypair1 = try access_token.generateEphemeralKeyPair();
    const keypair2 = try access_token.generateEphemeralKeyPair();
    
    try testing.expect(keypair1.private_key.bytes.len == 32);
    try testing.expect(keypair1.public_key.bytes.len == 32);
    
    // Keys should be different
    try testing.expect(!std.mem.eql(u8, &keypair1.private_key.bytes, &keypair2.private_key.bytes));
}

test "data signing and verification" {
    const keypair = try access_token.generateKeyPair("test_passphrase");
    const test_data = "Hello, Shroud!";
    
    const signature = try access_token.signData(test_data, keypair.private_key);
    const is_valid = access_token.verifyData(signature, test_data, keypair.public_key);
    
    try testing.expect(is_valid);
    
    // Test with different data
    const is_invalid = access_token.verifyData(signature, "Different data", keypair.public_key);
    try testing.expect(!is_invalid);
}

test "access token creation and signing" {
    const keypair = try access_token.generateKeyPair("test_passphrase");
    
    var token = access_token.AccessToken.init(testing.allocator, "user123", 3600);
    defer token.deinit();
    
    try token.addRole("user");
    try token.addPermission(.read);
    try token.addPermission(.write);
    
    try token.sign(keypair.private_key);
    
    try testing.expect(token.verify(keypair.public_key));
}

test "access token expiration" {
    const keypair = try access_token.generateKeyPair("test_passphrase");
    
    var token = access_token.AccessToken.init(testing.allocator, "user123", 0); // Expires immediately
    defer token.deinit();
    
    // Manually set the token to be expired by setting issued_at in the past
    token.issued_at = @as(u64, @intCast(std.time.timestamp())) - 10;
    token.expires_at = token.issued_at; // Already expired
    
    try token.sign(keypair.private_key);
    
    // Token should be expired
    try testing.expect(token.isExpired());
}

test "access token permissions" {
    var token = access_token.AccessToken.init(testing.allocator, "user123", 3600);
    defer token.deinit();
    
    try token.addPermission(.read);
    try token.addPermission(.write);
    
    try testing.expect(token.hasPermission(.read));
    try testing.expect(token.hasPermission(.write));
    try testing.expect(!token.hasPermission(.admin));
}