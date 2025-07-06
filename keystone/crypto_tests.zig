const std = @import("std");
const zledger = @import("root.zig");
const zcrypto = @import("zcrypto");

test "complete cryptographic transaction workflow" {
    const allocator = std.testing.allocator;
    
    // Generate wallet keypair
    var keypair = zledger.WalletKeypair.generate(.ed25519);
    defer keypair.deinit();

    // Create transaction signer
    var signer = zledger.TransactionSigner.init(keypair);
    defer signer.deinit();

    // Create a transaction
    var transaction = try zledger.Transaction.init(allocator, 100000, "USD", "alice", "bob", "Secure payment");
    defer transaction.deinit(allocator);

    // Sign the transaction
    try signer.signTransaction(allocator, &transaction);
    
    // Verify all cryptographic components are present
    try std.testing.expect(transaction.signature != null);
    try std.testing.expect(transaction.integrity_hmac != null);
    try std.testing.expect(transaction.nonce.len == 12);

    // Verify the transaction
    const is_valid = try signer.verifyTransaction(allocator, transaction);
    try std.testing.expect(is_valid);

    // Test that tampering breaks verification
    var tampered_transaction = transaction;
    tampered_transaction.amount = 200000; // Tamper with amount
    
    const tampered_valid = try signer.verifyTransaction(allocator, tampered_transaction);
    try std.testing.expect(!tampered_valid);
}

test "audit trail with HMAC integrity" {
    const allocator = std.testing.allocator;
    
    // Create ledger and journal
    var ledger = zledger.Ledger.init(allocator);
    defer ledger.deinit();
    
    var journal = zledger.Journal.init(allocator, null);
    defer journal.deinit();

    // Create accounts
    try ledger.createAccount("alice", .asset, "USD");
    try ledger.createAccount("bob", .asset, "USD");

    // Create and sign transactions
    var keypair = zledger.WalletKeypair.generate(.ed25519);
    defer keypair.deinit();

    var signer = zledger.TransactionSigner.init(keypair);
    defer signer.deinit();

    // Add multiple transactions
    for (0..5) |i| {
        var tx = try zledger.Transaction.init(allocator, @intCast(10000 * (i + 1)), "USD", "alice", "bob", "Test payment");
        try signer.signTransaction(allocator, &tx);
        try journal.append(tx);
        try ledger.processTransaction(tx);
    }

    // Create auditor with specific key
    var audit_key: [32]u8 = undefined;
    zcrypto.rand.fillBytes(&audit_key);
    
    var auditor = zledger.Auditor.initWithKey(allocator, audit_key);
    
    // Perform audit
    var report = try auditor.auditLedger(&ledger, &journal);
    defer report.deinit(allocator);

    // Verify audit results
    try std.testing.expect(report.integrity_valid);
    try std.testing.expect(report.double_entry_valid);
    try std.testing.expect(report.hmac_valid);
    try std.testing.expect(report.isValid());
    try std.testing.expectEqual(@as(usize, 5), report.total_transactions);
}

test "encrypted storage and retrieval" {
    const allocator = std.testing.allocator;
    
    // Create encrypted storage
    var storage = zledger.EncryptedStorage.init(allocator);
    defer storage.secureWipe();

    // Test sensitive ledger data
    const sensitive_data = 
        \\{
        \\  "account": "alice",
        \\  "balance": 1000000,
        \\  "private_key": "super_secret_key_material",
        \\  "transactions": ["tx1", "tx2", "tx3"]
        \\}
    ;

    // Encrypt the data
    var encrypted = try storage.encryptData(sensitive_data);
    defer encrypted.deinit();

    // Verify it's actually encrypted (different from plaintext)
    try std.testing.expect(!std.mem.eql(u8, encrypted.ciphertext, sensitive_data));

    // Decrypt and verify
    const decrypted = try storage.decryptData(encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(sensitive_data, decrypted);
}

test "secure file operations with password" {
    const allocator = std.testing.allocator;
    
    const test_file = "test_secure_ledger.enc";
    const password = "very_secure_password_123";
    
    // Test data representing a sensitive ledger state
    const ledger_data = 
        \\# Encrypted Ledger Backup
        \\alice:1000000:USD
        \\bob:500000:USD
        \\charlie:250000:USD
        \\# Transaction Log
        \\tx_001:alice->bob:100000:memo_encrypted
        \\tx_002:bob->charlie:50000:memo_encrypted
    ;

    // Save encrypted
    {
        var secure_file = try zledger.SecureFile.init(allocator, test_file, password);
        defer secure_file.deinit();
        
        try secure_file.save(ledger_data);
    }

    // Load and verify
    {
        var secure_file = try zledger.SecureFile.init(allocator, test_file, password);
        defer secure_file.deinit();
        
        const loaded_data = try secure_file.load();
        defer allocator.free(loaded_data);
        
        try std.testing.expectEqualStrings(ledger_data, loaded_data);
    }

    // Test wrong password fails
    {
        var secure_file = try zledger.SecureFile.init(allocator, test_file, "wrong_password");
        defer secure_file.deinit();
        
        // Should fail to decrypt with wrong password
        const result = secure_file.load();
        try std.testing.expectError(error.DecryptionFailed, result);
    }

    // Clean up
    std.fs.cwd().deleteFile(test_file) catch {};
}

test "encrypted journal persistence" {
    const allocator = std.testing.allocator;
    
    const test_file = "test_encrypted_journal.enc";
    const password = "journal_password_456";

    // Create journal with transactions
    {
        var journal = zledger.Journal.init(allocator, null);
        defer journal.deinit();

        var keypair = zledger.WalletKeypair.generate(.secp256k1);
        defer keypair.deinit();

        var signer = zledger.TransactionSigner.init(keypair);
        defer signer.deinit();

        // Add signed transactions
        for (0..3) |i| {
            var tx = try zledger.Transaction.init(allocator, @intCast(25000 * (i + 1)), "BTC", "wallet1", "wallet2", "Encrypted journal test");
            try signer.signTransaction(allocator, &tx);
            try journal.append(tx);
        }

        // Save encrypted
        try journal.saveToEncryptedFile(test_file, password);
    }

    // Load encrypted journal
    {
        var journal2 = zledger.Journal.init(allocator, null);
        defer journal2.deinit();

        try journal2.loadFromEncryptedFile(test_file, password);
        
        try std.testing.expectEqual(@as(usize, 3), journal2.entries.items.len);
        try std.testing.expect(try journal2.verifyIntegrity());
        
        // Verify transactions have signatures
        for (journal2.entries.items) |entry| {
            try std.testing.expect(entry.transaction.signature != null);
            try std.testing.expect(entry.transaction.integrity_hmac != null);
        }
    }

    // Clean up
    std.fs.cwd().deleteFile(test_file) catch {};
}

test "constant-time operations security" {
    const allocator = std.testing.allocator;
    
    // Test that constant-time comparison is working
    var hash1: [32]u8 = undefined;
    var hash2: [32]u8 = undefined;
    
    zcrypto.rand.fillBytes(&hash1);
    hash2 = hash1; // Copy
    
    // Same hashes should compare equal
    try std.testing.expect(zcrypto.util.constantTimeCompare(&hash1, &hash2));
    
    // Different hashes should not compare equal
    hash2[0] ^= 0x01; // Flip one bit
    try std.testing.expect(!zcrypto.util.constantTimeCompare(&hash1, &hash2));

    // Test with transaction hashes
    var tx1 = try zledger.Transaction.init(allocator, 100000, "USD", "alice", "bob", "Test 1");
    defer tx1.deinit(allocator);
    
    var tx2 = try zledger.Transaction.init(allocator, 100000, "USD", "alice", "bob", "Test 1");
    defer tx2.deinit(allocator);

    // Same transaction data should produce same hash (when nonce is same)
    tx2.nonce = tx1.nonce; // Make nonces equal for this test
    
    const hash_1 = try tx1.getHash(allocator);
    const hash_2 = try tx2.getHash(allocator);
    
    try std.testing.expect(zcrypto.util.constantTimeCompare(&hash_1, &hash_2));
}

test "multi-algorithm wallet support" {
    const allocator = std.testing.allocator;
    
    // Test Ed25519 
    {
        var keypair_ed = zledger.WalletKeypair.generate(.ed25519);
        defer keypair_ed.deinit();
        
        var wallet_info = try zledger.WalletInfo.fromKeypair(allocator, keypair_ed);
        defer wallet_info.deinit(allocator);
        
        try std.testing.expect(std.mem.startsWith(u8, wallet_info.address, "zl"));
        try std.testing.expectEqual(zledger.SignatureAlgorithm.ed25519, wallet_info.algorithm);
    }

    // Test secp256k1
    {
        var keypair_secp = zledger.WalletKeypair.generate(.secp256k1);
        defer keypair_secp.deinit();
        
        var wallet_info = try zledger.WalletInfo.fromKeypair(allocator, keypair_secp);
        defer wallet_info.deinit(allocator);
        
        try std.testing.expect(std.mem.startsWith(u8, wallet_info.address, "bc"));
        try std.testing.expectEqual(zledger.SignatureAlgorithm.secp256k1, wallet_info.algorithm);
    }
}

test "comprehensive security validation" {
    const allocator = std.testing.allocator;
    
    // Create complete system with all security features
    var ledger = zledger.Ledger.init(allocator);
    defer ledger.deinit();
    
    var journal = zledger.Journal.init(allocator, null);
    defer journal.deinit();

    try ledger.createAccount("secure_alice", .asset, "USD");
    try ledger.createAccount("secure_bob", .asset, "USD");

    // Generate wallet and signer
    var keypair = zledger.WalletKeypair.generate(.ed25519);
    defer keypair.deinit();

    var signer = zledger.TransactionSigner.init(keypair);
    defer signer.deinit();

    // Create, sign, and process transaction
    var tx = try zledger.Transaction.init(allocator, 500000, "USD", "secure_alice", "secure_bob", "Full security test");
    defer tx.deinit(allocator);

    try signer.signTransaction(allocator, &tx);
    try journal.append(tx);
    try ledger.processTransaction(tx);

    // Audit with HMAC
    var auditor = zledger.Auditor.init(allocator);
    var report = try auditor.auditLedger(&ledger, &journal);
    defer report.deinit(allocator);

    // All security checks should pass
    try std.testing.expect(report.integrity_valid);
    try std.testing.expect(report.double_entry_valid);
    try std.testing.expect(report.hmac_valid);
    try std.testing.expect(report.isValid());

    // Verify transaction signature
    const sig_valid = try signer.verifyTransaction(allocator, tx);
    try std.testing.expect(sig_valid);

    // Test encrypted persistence
    const test_file = "test_complete_security.enc";
    const password = "complete_security_test";
    
    try journal.saveToEncryptedFile(test_file, password);
    
    // Load and verify everything still works
    var journal2 = zledger.Journal.init(allocator, null);
    defer journal2.deinit();
    
    try journal2.loadFromEncryptedFile(test_file, password);
    try std.testing.expect(try journal2.verifyIntegrity());
    
    // Clean up
    std.fs.cwd().deleteFile(test_file) catch {};
}