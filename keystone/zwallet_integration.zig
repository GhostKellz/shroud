const std = @import("std");
const zcrypto = @import("zcrypto");
const tx = @import("tx.zig");

pub const WalletKeypair = struct {
    public_key: [32]u8,
    private_key: [32]u8,
    algorithm: SignatureAlgorithm,

    pub fn generate(algorithm: SignatureAlgorithm) WalletKeypair {
        switch (algorithm) {
            .ed25519 => {
                const keypair = zcrypto.asym.ed25519.generate();
                return WalletKeypair{
                    .public_key = keypair.public_key,
                    .private_key = keypair.private_key,
                    .algorithm = algorithm,
                };
            },
            .secp256k1 => {
                const keypair = zcrypto.asym.secp256k1.generate();
                return WalletKeypair{
                    .public_key = keypair.public_key,
                    .private_key = keypair.private_key,
                    .algorithm = algorithm,
                };
            },
        }
    }

    pub fn fromSeed(seed: [32]u8, algorithm: SignatureAlgorithm) WalletKeypair {
        switch (algorithm) {
            .ed25519 => {
                const keypair = zcrypto.asym.ed25519.fromSeed(seed);
                return WalletKeypair{
                    .public_key = keypair.public_key,
                    .private_key = keypair.private_key,
                    .algorithm = algorithm,
                };
            },
            .secp256k1 => {
                const keypair = zcrypto.asym.secp256k1.fromSeed(seed);
                return WalletKeypair{
                    .public_key = keypair.public_key,
                    .private_key = keypair.private_key,
                    .algorithm = algorithm,
                };
            },
        }
    }

    pub fn deinit(self: *WalletKeypair) void {
        zcrypto.util.secureZero(&self.private_key);
        zcrypto.util.secureZero(&self.public_key);
    }
};

pub const SignatureAlgorithm = enum {
    ed25519,
    secp256k1,
};

pub const TransactionSigner = struct {
    keypair: WalletKeypair,
    hmac_key: [32]u8,

    pub fn init(keypair: WalletKeypair) TransactionSigner {
        return TransactionSigner{
            .keypair = keypair,
            .hmac_key = zcrypto.rand.generateKey(32),
        };
    }

    pub fn initWithHmacKey(keypair: WalletKeypair, hmac_key: [32]u8) TransactionSigner {
        return TransactionSigner{
            .keypair = keypair,
            .hmac_key = hmac_key,
        };
    }

    pub fn signTransaction(self: *TransactionSigner, allocator: std.mem.Allocator, transaction: *tx.Transaction) !void {
        const tx_data = try transaction.getTransactionDataForSigning(allocator);
        defer allocator.free(tx_data);

        switch (self.keypair.algorithm) {
            .ed25519 => {
                const ed_keypair = zcrypto.asym.ed25519.KeyPair{
                    .public_key = self.keypair.public_key,
                    .private_key = self.keypair.private_key,
                };
                transaction.signature = ed_keypair.sign(tx_data);
            },
            .secp256k1 => {
                const secp_keypair = zcrypto.asym.secp256k1.KeyPair{
                    .public_key = self.keypair.public_key,
                    .private_key = self.keypair.private_key,
                };
                transaction.signature = secp_keypair.sign(tx_data);
            },
        }

        // Generate HMAC for integrity
        transaction.integrity_hmac = zcrypto.auth.hmac.sha256(tx_data, &self.hmac_key);
    }

    pub fn verifyTransaction(self: *TransactionSigner, allocator: std.mem.Allocator, transaction: tx.Transaction) !bool {
        if (transaction.signature == null or transaction.integrity_hmac == null) return false;

        const tx_data = try transaction.getTransactionDataForSigning(allocator);
        defer allocator.free(tx_data);

        // Verify HMAC first
        const computed_hmac = zcrypto.auth.hmac.sha256(tx_data, &self.hmac_key);
        if (!zcrypto.util.constantTimeCompare(&transaction.integrity_hmac.?, &computed_hmac)) {
            return false;
        }

        // Verify signature
        switch (self.keypair.algorithm) {
            .ed25519 => {
                const ed_keypair = zcrypto.asym.ed25519.KeyPair{
                    .public_key = self.keypair.public_key,
                    .private_key = undefined, // Not needed for verification
                };
                return ed_keypair.verify(tx_data, transaction.signature.?);
            },
            .secp256k1 => {
                const secp_keypair = zcrypto.asym.secp256k1.KeyPair{
                    .public_key = self.keypair.public_key,
                    .private_key = undefined, // Not needed for verification
                };
                return secp_keypair.verify(tx_data, transaction.signature.?);
            },
        }
    }

    pub fn deinit(self: *TransactionSigner) void {
        self.keypair.deinit();
        zcrypto.util.secureZero(&self.hmac_key);
    }
};

pub const WalletInfo = struct {
    public_key_hex: []const u8,
    algorithm: SignatureAlgorithm,
    address: []const u8,

    pub fn fromKeypair(allocator: std.mem.Allocator, keypair: WalletKeypair) !WalletInfo {
        const public_key_hex = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&keypair.public_key)});
        
        // Generate address based on algorithm
        const address = switch (keypair.algorithm) {
            .ed25519 => try generateEd25519Address(allocator, keypair.public_key),
            .secp256k1 => try generateSecp256k1Address(allocator, keypair.public_key),
        };

        return WalletInfo{
            .public_key_hex = public_key_hex,
            .algorithm = keypair.algorithm,
            .address = address,
        };
    }

    pub fn deinit(self: *WalletInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.public_key_hex);
        allocator.free(self.address);
    }
};

fn generateEd25519Address(allocator: std.mem.Allocator, public_key: [32]u8) ![]u8 {
    var hash: [32]u8 = undefined;
    zcrypto.hash.sha256(&public_key, &hash);
    
    // Take first 20 bytes and encode as hex with prefix
    return try std.fmt.allocPrint(allocator, "zl{x}", .{std.fmt.fmtSliceHexLower(hash[0..20])});
}

fn generateSecp256k1Address(allocator: std.mem.Allocator, public_key: [32]u8) ![]u8 {
    var hash: [32]u8 = undefined;
    zcrypto.hash.sha256(&public_key, &hash);
    
    // Take first 20 bytes and encode as hex with Bitcoin-style prefix
    return try std.fmt.allocPrint(allocator, "bc{x}", .{std.fmt.fmtSliceHexLower(hash[0..20])});
}

pub const HDWallet = struct {
    master_seed: [32]u8,
    current_index: u32,

    pub fn fromMnemonic(allocator: std.mem.Allocator, mnemonic: []const u8, passphrase: []const u8) !HDWallet {
        // This would integrate with zcrypto BIP-39 functionality
        const seed = try zcrypto.bip.bip39.mnemonicToSeed(allocator, mnemonic, passphrase);
        return HDWallet{
            .master_seed = seed,
            .current_index = 0,
        };
    }

    pub fn deriveKeypair(self: *HDWallet, algorithm: SignatureAlgorithm, index: u32) !WalletKeypair {
        // This would use BIP-32 derivation
        const path = try zcrypto.bip.bip44.standardPath(algorithm == .secp256k1, 0, 0, index);
        const derived_key = zcrypto.bip.bip32.deriveKey(self.master_seed, path);
        
        return WalletKeypair.fromSeed(derived_key, algorithm);
    }

    pub fn nextKeypair(self: *HDWallet, algorithm: SignatureAlgorithm) !WalletKeypair {
        const keypair = try self.deriveKeypair(algorithm, self.current_index);
        self.current_index += 1;
        return keypair;
    }

    pub fn deinit(self: *HDWallet) void {
        zcrypto.util.secureZero(&self.master_seed);
    }
};

test "wallet keypair generation and signing" {
    const allocator = std.testing.allocator;
    
    var keypair = WalletKeypair.generate(.ed25519);
    defer keypair.deinit();

    var signer = TransactionSigner.init(keypair);
    defer signer.deinit();

    var transaction = try tx.Transaction.init(allocator, 100000, "USD", "alice", "bob", "Test payment");
    defer transaction.deinit(allocator);

    try signer.signTransaction(allocator, &transaction);
    
    try std.testing.expect(transaction.signature != null);
    try std.testing.expect(transaction.integrity_hmac != null);

    const is_valid = try signer.verifyTransaction(allocator, transaction);
    try std.testing.expect(is_valid);
}

test "wallet info generation" {
    const allocator = std.testing.allocator;
    
    var keypair = WalletKeypair.generate(.ed25519);
    defer keypair.deinit();

    var wallet_info = try WalletInfo.fromKeypair(allocator, keypair);
    defer wallet_info.deinit(allocator);

    try std.testing.expect(wallet_info.public_key_hex.len == 64); // 32 bytes as hex
    try std.testing.expect(std.mem.startsWith(u8, wallet_info.address, "zl"));
}