//! Command-line interface for Zsig cryptographic operations
//! Provides keygen, sign, verify, and key management commands

const std = @import("std");
const zsig = @import("zsig.zig");
const backend = @import("zsig/backend.zig");
const fs = std.fs;
const print = std.debug.print;

const CliError = error{
    InvalidArguments,
    FileNotFound,
    InvalidKeyFormat,
    InvalidSignatureFormat,
    VerificationFailed,
    KeyGenerationFailed,
    FileWriteError,
    FileReadError,
};

const Command = enum {
    keygen,
    sign,
    verify,
    pubkey,
    // New token commands for v0.4.0
    token_create,
    token_verify,
    token_refresh,
    jwt_create,
    jwt_verify,
    // Batch operations for v0.4.0
    batch_sign,
    batch_verify,
    benchmark,
    help,
    version,
};

const Args = struct {
    command: Command,
    input_file: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    signature_file: ?[]const u8 = null,
    public_key_file: ?[]const u8 = null,
    seed: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
    context: ?[]const u8 = null,
    format: []const u8 = "base64", // base64, hex, raw
    inline_mode: bool = false,
    verbose: bool = false,

    // Token-specific args for v0.4.0
    issuer: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    expires_in: ?i64 = null,  // seconds from now
    token_type: []const u8 = "auth",  // auth, session, transaction, etc.
    algorithm: []const u8 = "ed25519",  // ed25519, secp256k1, secp256r1
    claims: ?[]const u8 = null,  // JSON string for custom claims
    token_string: ?[]const u8 = null,  // Token to verify/refresh

    // Batch operation args for v0.4.0
    batch_size: ?usize = null,  // For benchmarks
    iterations: ?usize = null,  // For benchmarks
    input_dir: ?[]const u8 = null,  // Directory of files to process
    output_dir: ?[]const u8 = null,  // Directory for output files
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = std.process.argsAlloc(allocator) catch |err| {
        print("Error: Failed to parse arguments: {}\n", .{err});
        return;
    };
    defer std.process.argsFree(allocator, args);

    const parsed_args = parseArgs(args) catch |err| {
        switch (err) {
            CliError.InvalidArguments => {
                print("Error: Invalid arguments. Use 'zsig help' for usage information.\n", .{});
                return;
            },
            else => {
                print("Error: Failed to parse arguments: {}\n", .{err});
                return;
            },
        }
    };

    switch (parsed_args.command) {
        .keygen => try cmdKeygen(allocator, parsed_args),
        .sign => try cmdSign(allocator, parsed_args),
        .verify => try cmdVerify(allocator, parsed_args),
        .pubkey => try cmdPubkey(allocator, parsed_args),
        // New token commands for v0.4.0
        .token_create => try cmdTokenCreate(allocator, parsed_args),
        .token_verify => try cmdTokenVerify(allocator, parsed_args),
        .token_refresh => try cmdTokenRefresh(allocator, parsed_args),
        .jwt_create => try cmdJwtCreate(allocator, parsed_args),
        .jwt_verify => try cmdJwtVerify(allocator, parsed_args),
        // Batch operations for v0.4.0 (TODO: Implement)
        .batch_sign => {
            print("Error: batch_sign not yet implemented in v0.4.0\n", .{});
            return CliError.InvalidArguments;
        },
        .batch_verify => {
            print("Error: batch_verify not yet implemented in v0.4.0\n", .{});
            return CliError.InvalidArguments;
        },
        .benchmark => {
            print("Error: benchmark not yet implemented in v0.4.0\n", .{});
            return CliError.InvalidArguments;
        },
        .help => cmdHelp(),
        .version => cmdVersion(),
    }
}

fn parseArgs(args: [][:0]u8) !Args {
    if (args.len < 2) return CliError.InvalidArguments;

    const command_str = args[1];
    const command = if (std.mem.eql(u8, command_str, "keygen")) Command.keygen
    else if (std.mem.eql(u8, command_str, "sign")) Command.sign
    else if (std.mem.eql(u8, command_str, "verify")) Command.verify
    else if (std.mem.eql(u8, command_str, "pubkey")) Command.pubkey
    else if (std.mem.eql(u8, command_str, "token_create")) Command.token_create
    else if (std.mem.eql(u8, command_str, "token_verify")) Command.token_verify
    else if (std.mem.eql(u8, command_str, "token_refresh")) Command.token_refresh
    else if (std.mem.eql(u8, command_str, "jwt_create")) Command.jwt_create
    else if (std.mem.eql(u8, command_str, "jwt_verify")) Command.jwt_verify
    else if (std.mem.eql(u8, command_str, "batch_sign")) Command.batch_sign
    else if (std.mem.eql(u8, command_str, "batch_verify")) Command.batch_verify
    else if (std.mem.eql(u8, command_str, "benchmark")) Command.benchmark
    else if (std.mem.eql(u8, command_str, "help")) Command.help
    else if (std.mem.eql(u8, command_str, "version")) Command.version
    else return CliError.InvalidArguments;

    var parsed = Args{ .command = command };

    var i: usize = 2;
    while (i < args.len) : (i += 2) {
        if (i + 1 >= args.len) break;

        const flag = args[i];
        const value = args[i + 1];

        if (std.mem.eql(u8, flag, "--in") or std.mem.eql(u8, flag, "-i")) {
            parsed.input_file = value;
        } else if (std.mem.eql(u8, flag, "--out") or std.mem.eql(u8, flag, "-o")) {
            parsed.output_file = value;
        } else if (std.mem.eql(u8, flag, "--key") or std.mem.eql(u8, flag, "-k")) {
            parsed.key_file = value;
        } else if (std.mem.eql(u8, flag, "--sig") or std.mem.eql(u8, flag, "-s")) {
            parsed.signature_file = value;
        } else if (std.mem.eql(u8, flag, "--pubkey") or std.mem.eql(u8, flag, "-p")) {
            parsed.public_key_file = value;
        } else if (std.mem.eql(u8, flag, "--seed")) {
            parsed.seed = value;
        } else if (std.mem.eql(u8, flag, "--passphrase")) {
            parsed.passphrase = value;
        } else if (std.mem.eql(u8, flag, "--context")) {
            parsed.context = value;
        } else if (std.mem.eql(u8, flag, "--format")) {
            parsed.format = value;
        } else if (std.mem.eql(u8, flag, "--inline")) {
            parsed.inline_mode = true;
            i -= 1; // No value for this flag
        } else if (std.mem.eql(u8, flag, "--verbose")) {
            parsed.verbose = true;
            i -= 1; // No value for this flag
        } else if (std.mem.eql(u8, flag, "--issuer")) {
            parsed.issuer = value;
        } else if (std.mem.eql(u8, flag, "--subject")) {
            parsed.subject = value;
        } else if (std.mem.eql(u8, flag, "--audience")) {
            parsed.audience = value;
        } else if (std.mem.eql(u8, flag, "--expires-in")) {
            const expires_in_value = std.fmt.parseInt(i64, value, 10) catch {
                return CliError.InvalidArguments;
            };
            parsed.expires_in = expires_in_value;
        } else if (std.mem.eql(u8, flag, "--token-type")) {
            parsed.token_type = value;
        } else if (std.mem.eql(u8, flag, "--algorithm")) {
            parsed.algorithm = value;
        } else if (std.mem.eql(u8, flag, "--claims")) {
            parsed.claims = value;
        } else if (std.mem.eql(u8, flag, "--token-string")) {
            parsed.token_string = value;
        }
    }

    return parsed;
}

fn cmdKeygen(allocator: std.mem.Allocator, args: Args) !void {
    // Parse algorithm
    const algorithm = backend.algorithmFromString(args.algorithm) catch {
        print("Error: Unsupported algorithm '{s}'. Supported: ed25519, secp256k1, secp256r1\n", .{args.algorithm});
        return CliError.InvalidArguments;
    };

    if (args.verbose) print("Generating {s} keypair...\n", .{args.algorithm});

    const keypair = if (args.seed) |seed_str| blk: {
        if (seed_str.len != zsig.SEED_SIZE * 2) {
            print("Error: Seed must be exactly {} hex characters\n", .{zsig.SEED_SIZE * 2});
            return CliError.InvalidArguments;
        }
        var seed: [zsig.SEED_SIZE]u8 = undefined;
        _ = std.fmt.hexToBytes(&seed, seed_str) catch {
            print("Error: Invalid hex seed\n", .{});
            return CliError.InvalidArguments;
        };
        break :blk zsig.key.Keypair.fromSeedWithAlgorithm(seed, algorithm);
    } else if (args.passphrase) |passphrase|
        try zsig.key.Keypair.fromPassphraseWithAlgorithm(allocator, passphrase, null, algorithm)
    else
        try zsig.key.Keypair.generateWithAlgorithm(allocator, algorithm);

    // Generate output files
    const base_name = args.output_file orelse "zsig_key";

    // Write private key file (.key)
    const key_filename = try std.fmt.allocPrint(allocator, "{s}.key", .{base_name});
    defer allocator.free(key_filename);

    const key_bundle = try keypair.exportBundle(allocator);
    defer allocator.free(key_bundle);

    try writeFile(key_filename, key_bundle);

    // Write public key file (.pub)
    const pub_filename = try std.fmt.allocPrint(allocator, "{s}.pub", .{base_name});
    defer allocator.free(pub_filename);

    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);

    try writeFile(pub_filename, pub_hex);

    if (args.verbose) {
        print("Generated {s} keypair:\n", .{backend.algorithmToString(algorithm)});
        print("  Private key: {s}\n", .{key_filename});
        print("  Public key: {s}\n", .{pub_filename});
        print("  Public key (hex): {s}\n", .{pub_hex});
    } else {
        print("{s} keypair generated: {s}.key, {s}.pub\n", .{ backend.algorithmToString(algorithm), base_name, base_name });
    }
}

fn cmdSign(allocator: std.mem.Allocator, args: Args) !void {
    const input_file = args.input_file orelse {
        print("Error: Input file required (--in)\n", .{});
        return CliError.InvalidArguments;
    };

    const key_file = args.key_file orelse {
        print("Error: Key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    };

    if (args.verbose) print("Reading message from {s}...\n", .{input_file});
    const message = readFile(allocator, input_file) catch |err| {
        print("Error reading input file: {}\n", .{err});
        return CliError.FileReadError;
    };
    defer allocator.free(message);

    if (args.verbose) print("Loading keypair from {s}...\n", .{key_file});
    const keypair = try loadKeypair(allocator, key_file);

    if (args.verbose) print("Signing message...\n", .{});
    const signature = if (args.context) |context|
        try zsig.signWithContext(message, context, keypair)
    else
        try zsig.signMessage(message, keypair);

    // Output signature
    if (args.inline_mode) {
        const inline_sig = try zsig.signInline(allocator, message, keypair);
        defer allocator.free(inline_sig);

        const output_file = args.output_file orelse "signed_message";
        try writeFile(output_file, inline_sig);

        if (args.verbose) {
            print("Inline signature written to {s}\n", .{output_file});
        } else {
            print("Signed: {s}\n", .{output_file});
        }
    } else {
        const sig_data = if (std.mem.eql(u8, args.format, "hex"))
            try signature.toHex(allocator)
        else if (std.mem.eql(u8, args.format, "base64"))
            try signature.toBase64(allocator)
        else if (std.mem.eql(u8, args.format, "raw"))
            try allocator.dupe(u8, &signature.bytes)
        else {
            print("Error: Invalid format. Use hex, base64, or raw\n", .{});
            return CliError.InvalidArguments;
        };
        defer allocator.free(sig_data);

        const output_file = args.output_file orelse
            try std.fmt.allocPrint(allocator, "{s}.sig", .{input_file});
        defer if (args.output_file == null) allocator.free(output_file);

        try writeFile(output_file, sig_data);

        if (args.verbose) {
            print("Signature ({s}) written to {s}\n", .{ args.format, output_file });
        } else {
            print("Signed: {s}\n", .{output_file});
        }
    }
}

fn cmdVerify(allocator: std.mem.Allocator, args: Args) !void {
    if (args.inline_mode) {
        const input_file = args.input_file orelse {
            print("Error: Input file required (--in)\n", .{});
            return CliError.InvalidArguments;
        };

        const public_key_file = args.public_key_file orelse {
            print("Error: Public key file required (--pubkey)\n", .{});
            return CliError.InvalidArguments;
        };

        const signed_message = try readFile(allocator, input_file);
        defer allocator.free(signed_message);

        const public_key = try loadPublicKey(allocator, public_key_file);

        const is_valid = zsig.verifyInline(signed_message, &public_key);

        if (is_valid) {
            print("✓ Signature valid\n", .{});
            if (args.verbose) {
                const extracted = zsig.verify.extractMessage(signed_message);
                print("Message: {s}\n", .{extracted});
            }
        } else {
            print("✗ Signature invalid\n", .{});
            return CliError.VerificationFailed;
        }
    } else {
        const input_file = args.input_file orelse {
            print("Error: Input file required (--in)\n", .{});
            return CliError.InvalidArguments;
        };

        const signature_file = args.signature_file orelse {
            print("Error: Signature file required (--sig)\n", .{});
            return CliError.InvalidArguments;
        };

        const public_key_file = args.public_key_file orelse {
            print("Error: Public key file required (--pubkey)\n", .{});
            return CliError.InvalidArguments;
        };

        const message = try readFile(allocator, input_file);
        defer allocator.free(message);

        const signature_data = try readFile(allocator, signature_file);
        defer allocator.free(signature_data);

        const public_key = try loadPublicKey(allocator, public_key_file);

        // Decode signature based on format (auto-detect or use format flag)
        const decoded_signature = blk: {
            if (signature_data.len == zsig.SIGNATURE_SIZE) {
                // Raw signature data
                break :blk signature_data;
            } else if (signature_data.len == zsig.SIGNATURE_SIZE * 2) {
                // Hex format
                var sig_bytes: [zsig.SIGNATURE_SIZE]u8 = undefined;
                _ = std.fmt.hexToBytes(&sig_bytes, signature_data) catch {
                    print("Error: Invalid hex signature format\n", .{});
                    return CliError.InvalidSignatureFormat;
                };
                break :blk sig_bytes[0..];
            } else {
                // Try base64 format
                const decoder = std.base64.standard.Decoder;
                var sig_bytes: [zsig.SIGNATURE_SIZE]u8 = undefined;
                decoder.decode(&sig_bytes, signature_data) catch {
                    print("Error: Invalid signature format (not raw, hex, or base64)\n", .{});
                    return CliError.InvalidSignatureFormat;
                };
                break :blk sig_bytes[0..];
            }
        };

        const is_valid = if (args.context) |context|
            zsig.verifyWithContext(message, context, decoded_signature, &public_key)
        else
            zsig.verifySignature(message, decoded_signature, &public_key);

        if (is_valid) {
            print("✓ Signature valid\n", .{});
        } else {
            print("✗ Signature invalid\n", .{});
            return CliError.VerificationFailed;
        }
    }
}

fn cmdPubkey(allocator: std.mem.Allocator, args: Args) !void {
    const key_file = args.key_file orelse {
        print("Error: Key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    };

    const keypair = try loadKeypair(allocator, key_file);
    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);

    if (args.output_file) |output| {
        try writeFile(output, pub_hex);
        print("Public key written to {s}\n", .{output});
    } else {
        print("{s}\n", .{pub_hex});
    }
}

fn cmdHelp() void {
    print(
        \\Zsig v{s} - Cryptographic Signing Engine for the GhostChain Ecosystem
        \\Multi-algorithm support: Ed25519 (default), ML-DSA-65 (post-quantum), Hybrid
        \\
        \\USAGE:
        \\    zsig <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    keygen         Generate a new cryptographic keypair
        \\    sign           Sign a message or file
        \\    verify         Verify a signature
        \\    pubkey         Extract public key from private key file
        \\    token_create   Create a new Ghost token (v0.4.0)
        \\    token_verify   Verify a Ghost token (v0.4.0)
        \\    token_refresh  Refresh an existing token (v0.4.0)
        \\    jwt_create     Create a JWT-compatible token (v0.4.0)
        \\    jwt_verify     Verify a JWT-compatible token (v0.4.0)
        \\    help           Show this help message
        \\    version        Show version information
        \\
        \\GLOBAL OPTIONS:
        \\    --algorithm <alg>   Algorithm: ed25519 (default), ml_dsa_65, hybrid
        \\    --verbose           Enable verbose output
        \\
        \\KEYGEN OPTIONS:
        \\    --out <file>        Output filename prefix (default: zsig_key)
        \\    --seed <hex>        Use specific 64-char hex seed (deterministic)
        \\    --passphrase <str>  Generate from passphrase (deterministic)
        \\
        \\SIGN OPTIONS:
        \\    --in <file>         Input file to sign
        \\    --key <file>        Private key file (.key)
        \\    --out <file>        Output signature file (default: input.sig)
        \\    --context <str>     Additional context for domain separation
        \\    --format <fmt>      Output format: base64, hex, raw (default: base64)
        \\    --inline            Create inline signature (message + signature)
        \\
        \\VERIFY OPTIONS:
        \\    --in <file>         Input file (message or inline signature)
        \\    --sig <file>        Signature file (not needed with --inline)
        \\    --pubkey <file>     Public key file (.pub)
        \\    --context <str>     Context used during signing
        \\    --inline            Verify inline signature
        \\
        \\TOKEN COMMANDS (v0.4.0):
        \\    token_create   Create a new Ghost token
        \\    token_verify   Verify a Ghost token
        \\    token_refresh  Refresh an existing token
        \\    jwt_create     Create a JWT-compatible token
        \\    jwt_verify     Verify a JWT-compatible token
        \\
        \\TOKEN OPTIONS:
        \\    --key <file>        Private key file for signing
        \\    --pubkey <file>     Public key file for verification
        \\    --issuer <str>      Token issuer (iss claim)
        \\    --subject <str>     Token subject (sub claim)
        \\    --audience <str>    Token audience (aud claim)
        \\    --expires-in <sec>  Expiration time in seconds from now
        \\    --token-type <type> Token type: auth, session, transaction, etc.
        \\    --claims <json>     Custom claims as JSON string
        \\    --token-string <tok> Token string to verify/refresh
        \\
        \\EXAMPLES:
        \\    # Multi-algorithm key generation
        \\    zsig keygen --out alice                          # Ed25519 (default)
        \\    zsig keygen --algorithm ml_dsa_65 --out pq_key   # Post-quantum
        \\    zsig keygen --algorithm hybrid --out hybrid_key  # Hybrid classical+PQ
        \\    
        \\    # Signing and verification
        \\    zsig sign --in message.txt --key alice.key
        \\    zsig verify --in message.txt --sig message.txt.sig --pubkey alice.pub
        \\    zsig sign --in tx.json --key alice.key --context "transaction-v1"
        \\    
        \\    # Token examples (quantum-safe)
        \\    zsig token_create --algorithm ml_dsa_65 --key pq.key --issuer ghostd --expires-in 3600
        \\    zsig token_verify --pubkey pq.pub --token-string <token>
        \\    zsig jwt_create --key alice.key --issuer "GhostChain" --subject "user123"
        \\
    , .{zsig.version});
}

fn cmdVersion() void {
    print("Zsig v{s}\n", .{zsig.version});
    print("Ed25519 cryptographic signing engine for Zig\n", .{});
    print("Author: {s}\n", .{zsig.info.author});
    print("License: {s}\n", .{zsig.info.license});
}

// Utility functions

fn readFile(allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
    const file = fs.cwd().openFile(filename, .{}) catch return CliError.FileNotFound;
    defer file.close();

    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    _ = try file.readAll(contents);

    return contents;
}

fn writeFile(filename: []const u8, data: []const u8) !void {
    const file = fs.cwd().createFile(filename, .{}) catch return CliError.FileWriteError;
    defer file.close();

    try file.writeAll(data);
}

fn loadKeypair(allocator: std.mem.Allocator, filename: []const u8) !zsig.Keypair {
    const contents = try readFile(allocator, filename);
    defer allocator.free(contents);

    // Parse the key bundle format
    const private_start = "Private: ";
    const private_start_idx = std.mem.indexOf(u8, contents, private_start) orelse
        return CliError.InvalidKeyFormat;

    const private_data_start = private_start_idx + private_start.len;
    const private_end_idx = std.mem.indexOf(u8, contents[private_data_start..], "\n") orelse
        return CliError.InvalidKeyFormat;

    const private_b64 = contents[private_data_start .. private_data_start + private_end_idx];

    return zsig.Keypair.fromPrivateKeyBase64(private_b64) catch CliError.InvalidKeyFormat;
}

fn loadPublicKey(allocator: std.mem.Allocator, filename: []const u8) ![zsig.PUBLIC_KEY_SIZE]u8 {
    const contents = try readFile(allocator, filename);
    defer allocator.free(contents);

    // Remove newlines and whitespace
    var clean_hex = std.ArrayList(u8).init(allocator);
    defer clean_hex.deinit();

    for (contents) |char| {
        if (std.ascii.isAlphanumeric(char)) {
            try clean_hex.append(char);
        }
    }

    return zsig.Keypair.publicKeyFromHex(clean_hex.items) catch CliError.InvalidKeyFormat;
}

// Token Commands for v0.4.0

fn cmdTokenCreate(allocator: std.mem.Allocator, args: Args) !void {
    const token_mod = @import("zsig/token.zig");
    
    if (args.key_file == null) {
        print("Error: Private key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    }
    
    if (args.verbose) print("Creating Ghost token...\n", .{});
    
    // Load keypair
    const keypair = try loadKeypair(allocator, args.key_file.?);
    
    // Parse algorithm
    const algorithm = token_mod.Algorithm.fromString(args.algorithm) orelse {
        print("Error: Unsupported algorithm '{s}'. Supported: ed25519, secp256k1, secp256r1\n", .{args.algorithm});
        return CliError.InvalidArguments;
    };
    
    // TODO: Add token type support when token.zig is updated
    _ = args.token_type; // Suppress unused warning
    
    // Build payload
    const now = std.time.timestamp();
    var payload = token_mod.TokenPayload{
        .issued_at = now,
        .issuer = args.issuer,
        .subject = args.subject,
        .audience = args.audience,
    };
    
    if (args.expires_in) |expires_in| {
        payload.expires_at = now + expires_in;
    }
    
    // Parse custom claims if provided (TODO: implement proper JSON claim parsing)
    if (args.claims) |_| {
        print("Warning: Custom claims not yet implemented in CLI\n", .{});
    }
    
    // Create token
    const token = token_mod.GhostToken.create(allocator, payload, keypair, algorithm) catch |err| {
        print("Error creating token: {}\n", .{err});
        return;
    };
    defer token.deinitCreated(allocator);
    
    const token_string = try token.encode(allocator);
    defer allocator.free(token_string);
    
    if (args.output_file) |output| {
        try writeFile(output, token_string);
        if (args.verbose) print("Token written to: {s}\n", .{output});
    } else {
        print("{s}\n", .{token_string});
    }
}

fn cmdTokenVerify(allocator: std.mem.Allocator, args: Args) !void {
    const token_mod = @import("zsig/token.zig");
    
    if (args.public_key_file == null) {
        print("Error: Public key file required (--pubkey)\n", .{});
        return CliError.InvalidArguments;
    }
    
    const token_string = if (args.token_string) |ts| ts else if (args.input_file) |file| blk: {
        const contents = try readFile(allocator, file);
        defer allocator.free(contents);
        // Remove newlines
        const trimmed = std.mem.trim(u8, contents, " \n\r\t");
        break :blk try allocator.dupe(u8, trimmed);
    } else {
        print("Error: Token string required (--token-string or --in)\n", .{});
        return CliError.InvalidArguments;
    };
    defer if (args.input_file != null) allocator.free(token_string);
    
    if (args.verbose) print("Verifying Ghost token...\n", .{});
    
    // Load public key
    const public_key = try loadPublicKey(allocator, args.public_key_file.?);
    
    // Decode token (just to check format and get payload info)
    const token = token_mod.GhostToken.decode(allocator, token_string) catch |err| {
        print("Error: Invalid token format: {}\n", .{err});
        return;
    };
    defer token.deinit(allocator);
    
    // Verify token using static method
    const payload = token_mod.GhostToken.verify(allocator, token_string, public_key) catch |err| {
        print("Error: Token verification failed: {}\n", .{err});
        return;
    };
    defer {
        // Free payload strings manually since it's not a full token
        if (payload.issuer) |iss| allocator.free(iss);
        if (payload.subject) |sub| allocator.free(sub);
        if (payload.audience) |aud| allocator.free(aud);
        if (payload.jwt_id) |jti| allocator.free(jti);
        if (payload.node_id) |nid| allocator.free(nid);
        if (payload.wallet_id) |wid| allocator.free(wid);
        if (payload.identity_hash) |ih| allocator.free(ih);
        if (payload.permissions) |perms| allocator.free(perms);
        if (payload.session_id) |sid| allocator.free(sid);
        if (payload.nonce) |nonce| allocator.free(nonce);
    }
    
    // Check expiration
    if (payload.isExpired()) {
        print("Warning: Token is expired\n", .{});
    }
    
    if (!payload.isValidYet()) {
        print("Warning: Token not valid yet (nbf)\n", .{});
    }
    
    print("Token verification successful!\n", .{});
    
    if (args.verbose) {
        print("Algorithm: {s}\n", .{token.header.algorithm.toString()});
        print("Type: {s}\n", .{token.header.token_type.toString()});
        if (payload.issuer) |iss| print("Issuer: {s}\n", .{iss});
        if (payload.subject) |sub| print("Subject: {s}\n", .{sub});
        if (payload.expires_at) |exp| print("Expires: {}\n", .{exp});
    }
}

fn cmdTokenRefresh(allocator: std.mem.Allocator, args: Args) !void {
    const token_mod = @import("zsig/token.zig");
    
    if (args.key_file == null) {
        print("Error: Private key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    }
    
    const token_string = if (args.token_string) |ts| ts else if (args.input_file) |file| blk: {
        const contents = try readFile(allocator, file);
        defer allocator.free(contents);
        break :blk std.mem.trim(u8, contents, " \n\r\t");
    } else {
        print("Error: Token string required (--token-string or --in)\n", .{});
        return CliError.InvalidArguments;
    };
    
    if (args.verbose) print("Refreshing Ghost token...\n", .{});
    
    // Load keypair
    const keypair = try loadKeypair(allocator, args.key_file.?);
    
    // Decode existing token
    var token = token_mod.GhostToken.decode(allocator, token_string) catch |err| {
        print("Error: Invalid token format: {}\n", .{err});
        return;
    };
    defer token.deinit(allocator);
    
    // Update expiration
    const now = std.time.timestamp();
    if (args.expires_in) |expires_in| {
        token.payload.expires_at = now + expires_in;
    } else {
        // Default to 1 hour extension
        token.payload.expires_at = now + 3600;
    }
    
    // Re-sign with new expiration
    const new_token = token_mod.GhostToken.create(allocator, token.payload, keypair, token.header.algorithm) catch |err| {
        print("Error refreshing token: {}\n", .{err});
        return;
    };
    defer new_token.deinitCreated(allocator);
    
    const new_token_string = try new_token.encode(allocator);
    defer allocator.free(new_token_string);
    
    if (args.output_file) |output| {
        try writeFile(output, new_token_string);
        if (args.verbose) print("Refreshed token written to: {s}\n", .{output});
    } else {
        print("{s}\n", .{new_token_string});
    }
}

fn cmdJwtCreate(allocator: std.mem.Allocator, args: Args) !void {
    const token_mod = @import("zsig/token.zig");
    
    if (args.key_file == null) {
        print("Error: Private key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    }
    
    if (args.verbose) print("Creating JWT-compatible token...\n", .{});
    
    // Load keypair
    const keypair = try loadKeypair(allocator, args.key_file.?);
    
    // Build standard JWT claims
    var claims = std.json.ObjectMap.init(allocator);
    defer claims.deinit();
    
    const now = std.time.timestamp();
    try claims.put("iat", std.json.Value{ .integer = now });
    
    if (args.issuer) |iss| try claims.put("iss", std.json.Value{ .string = iss });
    if (args.subject) |sub| try claims.put("sub", std.json.Value{ .string = sub });
    if (args.audience) |aud| try claims.put("aud", std.json.Value{ .string = aud });
    if (args.expires_in) |expires_in| {
        try claims.put("exp", std.json.Value{ .integer = now + expires_in });
    }
    
    // Parse custom claims if provided (TODO: implement proper JSON claim parsing)
    if (args.claims) |_| {
        print("Warning: Custom claims not yet implemented in CLI\n", .{});
    }
    
    const jwt = token_mod.JwtCompat.createJWT(allocator, std.json.Value{ .object = claims }, keypair) catch |err| {
        print("Error creating JWT: {}\n", .{err});
        return;
    };
    defer allocator.free(jwt);
    
    if (args.output_file) |output| {
        try writeFile(output, jwt);
        if (args.verbose) print("JWT written to: {s}\n", .{output});
    } else {
        print("{s}\n", .{jwt});
    }
}

fn cmdJwtVerify(allocator: std.mem.Allocator, args: Args) !void {
    const token_mod = @import("zsig/token.zig");
    
    if (args.public_key_file == null) {
        print("Error: Public key file required (--pubkey)\n", .{});
        return CliError.InvalidArguments;
    }
    
    const jwt_string = if (args.token_string) |ts| ts else if (args.input_file) |file| blk: {
        const contents = try readFile(allocator, file);
        defer allocator.free(contents);
        break :blk std.mem.trim(u8, contents, " \n\r\t");
    } else {
        print("Error: JWT string required (--token-string or --in)\n", .{});
        return CliError.InvalidArguments;
    };
    
    if (args.verbose) print("Verifying JWT...\n", .{});
    
    // Load public key
    const public_key = try loadPublicKey(allocator, args.public_key_file.?);
    
    // Verify JWT
    const claims = token_mod.JwtCompat.verifyJWT(allocator, jwt_string, public_key) catch |err| {
        print("Error: JWT verification failed: {}\n", .{err});
        return;
    };
    // Note: JSON cleanup is handled automatically by std.json
    
    print("JWT verification successful!\n", .{});
    
    if (args.verbose) {
        const claims_json = std.json.stringifyAlloc(allocator, claims, .{ .whitespace = .indent_2 }) catch "{}";
        defer allocator.free(claims_json);
        print("Claims:\n{s}\n", .{claims_json});
    }
}
