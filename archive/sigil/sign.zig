const std = @import("std");
const zcrypto = @import("ghostcipher").zcrypto;
const types = @import("types.zig");

const RealIDPrivateKey = types.RealIDPrivateKey;
const RealIDPublicKey = types.RealIDPublicKey;
const RealIDSignature = types.RealIDSignature;
const RealIDError = types.RealIDError;

/// Sign data with a RealID private key
pub fn realid_sign(data: []const u8, private_key: RealIDPrivateKey) RealIDError!RealIDSignature {
    // Use zcrypto's Ed25519 signing
    const signature = zcrypto.asym.signEd25519(data, private_key.bytes) catch {
        return RealIDError.CryptoError;
    };
    return RealIDSignature{ .bytes = signature };
}

/// Verify a signature against data and public key
pub fn realid_verify(signature: RealIDSignature, data: []const u8, public_key: RealIDPublicKey) bool {
    // Use zcrypto's Ed25519 verification
    return zcrypto.asym.verifyEd25519(data, signature.bytes, public_key.bytes);
}

/// Get the public key from a private key
pub fn realid_get_public_key(private_key: RealIDPrivateKey) RealIDError!RealIDPublicKey {
    // Create Ed25519 keypair from private key to get public key
    const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(private_key.bytes) catch {
        return RealIDError.InvalidPrivateKey;
    };
    const keypair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
        return RealIDError.InvalidPrivateKey;
    };

    return RealIDPublicKey{ .bytes = keypair.public_key.bytes };
}
