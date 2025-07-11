//! Build configuration for FFI libraries
//!
//! Generates C-compatible shared/static libraries for Rust integration

const std = @import("std");

pub fn buildFfi(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    // Create the main modules
    const ghostwire_mod = b.addModule("ghostwire", .{
        .root_source_file = b.path("ghostwire/root.zig"),
        .target = target,
    });

    const ghostcipher_mod = b.addModule("ghostcipher", .{
        .root_source_file = b.path("ghostcipher/root.zig"),
        .target = target,
    });

    const zns_mod = b.addModule("zns", .{
        .root_source_file = b.path("zns/root.zig"),
        .target = target,
    });
    _ = zns_mod; // Mark as used

    // ZQUIC FFI Library
    const zquic_ffi_lib = b.addSharedLibrary(.{
        .name = "zquic",
        .root_source_file = b.path("ghostwire/zquic/ffi/zquic_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zquic_ffi_lib.root_module.addImport("ghostwire", ghostwire_mod);
    zquic_ffi_lib.linkLibC();
    b.installArtifact(zquic_ffi_lib);

    // Static version for linking
    const zquic_ffi_static = b.addStaticLibrary(.{
        .name = "zquic",
        .root_source_file = b.path("ghostwire/zquic/ffi/zquic_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zquic_ffi_static.root_module.addImport("ghostwire", ghostwire_mod);
    zquic_ffi_static.linkLibC();
    b.installArtifact(zquic_ffi_static);

    // ZCrypto FFI Library
    const zcrypto_ffi_lib = b.addSharedLibrary(.{
        .name = "zcrypto",
        .root_source_file = b.path("ghostwire/zquic/ffi/zcrypto_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zcrypto_ffi_lib.root_module.addImport("ghostcipher", ghostcipher_mod);
    zcrypto_ffi_lib.linkLibC();
    b.installArtifact(zcrypto_ffi_lib);

    // ZCrypto static version
    const zcrypto_ffi_static = b.addStaticLibrary(.{
        .name = "zcrypto",
        .root_source_file = b.path("ghostwire/zquic/ffi/zcrypto_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zcrypto_ffi_static.root_module.addImport("ghostcipher", ghostcipher_mod);
    zcrypto_ffi_static.linkLibC();
    b.installArtifact(zcrypto_ffi_static);

    // GhostBridge FFI Library
    const ghostbridge_ffi_lib = b.addSharedLibrary(.{
        .name = "ghostbridge",
        .root_source_file = b.path("ghostwire/zquic/ffi/ghostbridge_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    ghostbridge_ffi_lib.root_module.addImport("ghostwire", ghostwire_mod);
    ghostbridge_ffi_lib.linkLibC();
    b.installArtifact(ghostbridge_ffi_lib);

    // GhostBridge static version
    const ghostbridge_ffi_static = b.addStaticLibrary(.{
        .name = "ghostbridge",
        .root_source_file = b.path("ghostwire/zquic/ffi/ghostbridge_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    ghostbridge_ffi_static.root_module.addImport("ghostwire", ghostwire_mod);
    ghostbridge_ffi_static.linkLibC();
    b.installArtifact(ghostbridge_ffi_static);

    // FFI Libraries are complete - no test or header generation needed
}
