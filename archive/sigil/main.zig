const std = @import("std");
const realid = @import("root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    try stdout.print("🛡️  RealID: Zero-Trust Identity Framework\n", .{});
    try stdout.print("=========================================\n\n", .{});

    // Demo passphrase
    const passphrase = "my_secure_passphrase_123";
    try stdout.print("📝 Generating identity from passphrase: '{s}'\n", .{passphrase});

    // Generate keypair
    const keypair = try realid.realid_generate_from_passphrase(passphrase);
    try stdout.print("✅ Keypair generated successfully!\n", .{});

    // Display public key
    try stdout.print("🔑 Public Key (hex): ", .{});
    for (keypair.public_key.bytes) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    // Generate QID
    const qid_result = realid.realid_qid_from_pubkey(keypair.public_key);
    try stdout.print("🌐 QID (IPv6): ", .{});
    var qid_buffer: [64]u8 = undefined;
    const qid_str = try realid.qid.qid_to_string(qid_result, &qid_buffer);
    try stdout.print("{s}\n", .{qid_str});

    // Demo signing
    const test_message = "Hello from RealID!";
    try stdout.print("\n📄 Signing message: '{s}'\n", .{test_message});

    const signature = try realid.realid_sign(test_message, keypair.private_key);
    try stdout.print("✍️  Signature (hex): ", .{});
    for (signature.bytes) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    // Verify signature
    const is_valid = realid.realid_verify(signature, test_message, keypair.public_key);
    try stdout.print("✅ Signature verification: {s}\n", .{if (is_valid) "VALID" else "INVALID"});

    // Generate device fingerprint
    try stdout.print("\n🖥️  Generating device fingerprint...\n", .{});
    const device_fp = try realid.generate_device_fingerprint(allocator);
    try stdout.print("🔍 Device Fingerprint (hex): ", .{});
    for (device_fp.bytes) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    // Generate keypair with device fingerprint
    try stdout.print("\n🔐 Generating identity with device binding...\n", .{});
    const device_keypair = try realid.realid_generate_from_passphrase_with_device(passphrase, device_fp);
    try stdout.print("🔑 Device-bound Public Key (hex): ", .{});
    for (device_keypair.public_key.bytes) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    // Generate QID for device-bound identity
    const device_qid = realid.realid_qid_from_pubkey(device_keypair.public_key);
    try stdout.print("🌐 Device-bound QID (IPv6): ", .{});
    const device_qid_str = try realid.qid.qid_to_string(device_qid, &qid_buffer);
    try stdout.print("{s}\n", .{device_qid_str});

    try stdout.print("\n🎉 RealID demo completed successfully!\n", .{});
}
