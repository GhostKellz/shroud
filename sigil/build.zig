//! RealID: Zero-Trust Identity Framework Build Configuration
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the RealID library
    const realid_lib = b.addStaticLibrary(.{
        .name = "realid",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Install the library
    b.installArtifact(realid_lib);

    // Add zcrypto dependency
    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });
    const zcrypto_mod = zcrypto_dep.module("zcrypto");

    // Export the realid module for other projects to import
    const realid_module = b.addModule("realid", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    realid_module.addImport("zcrypto", zcrypto_mod);

    // Create the demo executable
    const exe = b.addExecutable(.{
        .name = "realid-demo",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add zcrypto imports to both library and executable
    realid_lib.root_module.addImport("zcrypto", zcrypto_mod);
    exe.root_module.addImport("zcrypto", zcrypto_mod);

    // Install the executable
    b.installArtifact(exe);

    // Create run step for the demo
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the RealID demo");
    run_step.dependOn(&run_cmd.step);

    // Create tests
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.root_module.addImport("zcrypto", zcrypto_mod);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_unit_tests.root_module.addImport("zcrypto", zcrypto_mod);

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);

    // Create C header generation step
    const header_step = b.step("header", "Generate C header file");
    const generate_header = b.addWriteFiles();
    _ = generate_header.add("realid.h",
        \\#ifndef REALID_H
        \\#define REALID_H
        \\
        \\#ifdef __cplusplus
        \\extern "C" {
        \\#endif
        \\
        \\#include <stdint.h>
        \\#include <stddef.h>
        \\
        \\// RealID types
        \\typedef struct {
        \\    uint8_t bytes[64];
        \\} RealIDPrivateKey;
        \\
        \\typedef struct {
        \\    uint8_t bytes[32];
        \\} RealIDPublicKey;
        \\
        \\typedef struct {
        \\    RealIDPrivateKey private_key;
        \\    RealIDPublicKey public_key;
        \\} RealIDKeyPair;
        \\
        \\typedef struct {
        \\    uint8_t bytes[64];
        \\} RealIDSignature;
        \\
        \\typedef struct {
        \\    uint8_t bytes[16];
        \\} QID;
        \\
        \\typedef struct {
        \\    uint8_t bytes[32];
        \\} DeviceFingerprint;
        \\
        \\// Result codes
        \\#define REALID_SUCCESS 0
        \\#define REALID_ERROR_INVALID_PASSPHRASE -1
        \\#define REALID_ERROR_INVALID_SIGNATURE -2
        \\#define REALID_ERROR_INVALID_KEY -3
        \\#define REALID_ERROR_CRYPTO -4
        \\#define REALID_ERROR_MEMORY -5
        \\#define REALID_ERROR_BUFFER_TOO_SMALL -6
        \\
        \\// Function declarations
        \\int realid_generate_from_passphrase_c(
        \\    const uint8_t* passphrase,
        \\    size_t passphrase_len,
        \\    RealIDKeyPair* keypair_out
        \\);
        \\
        \\int realid_generate_from_passphrase_with_device_c(
        \\    const uint8_t* passphrase,
        \\    size_t passphrase_len,
        \\    const DeviceFingerprint* device_fingerprint,
        \\    RealIDKeyPair* keypair_out
        \\);
        \\
        \\int realid_sign_c(
        \\    const uint8_t* data,
        \\    size_t data_len,
        \\    const RealIDPrivateKey* private_key,
        \\    RealIDSignature* signature_out
        \\);
        \\
        \\int realid_verify_c(
        \\    const RealIDSignature* signature,
        \\    const uint8_t* data,
        \\    size_t data_len,
        \\    const RealIDPublicKey* public_key
        \\);
        \\
        \\int realid_qid_from_pubkey_c(
        \\    const RealIDPublicKey* public_key,
        \\    QID* qid_out
        \\);
        \\
        \\int realid_generate_device_fingerprint_c(
        \\    DeviceFingerprint* fingerprint_out
        \\);
        \\
        \\int realid_get_public_key_c(
        \\    const RealIDPrivateKey* private_key,
        \\    RealIDPublicKey* public_key_out
        \\);
        \\
        \\int realid_qid_to_string_c(
        \\    const QID* qid,
        \\    uint8_t* buffer,
        \\    size_t buffer_len,
        \\    size_t* written_len
        \\);
        \\
        \\#ifdef __cplusplus
        \\}
        \\#endif
        \\
        \\#endif // REALID_H
        \\
    );
    header_step.dependOn(&generate_header.step);
}
