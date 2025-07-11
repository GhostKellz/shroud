# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2025-07-11

### Fixed
- Fixed Blake3 hash function implementation to use `final()` instead of deprecated `finalResult()`
- Fixed SHA-256, SHA-512, SHA3-256, and SHA3-512 hash functions to use proper `final()` method signatures
- Fixed deprecated `std.mem.split` usage throughout codebase, replaced with `splitSequence`
- Fixed `@ptrCast` type errors in FFI bridge implementations
- Fixed Ed25519 key size constants (corrected from 32 to 64 bytes for private keys)
- Fixed ArrayList operations replacing deprecated `popOrNull()` with proper iteration
- Fixed string format specifiers adding missing `{s}` for string formatting
- Fixed const qualifier issues with memory reallocation
- Fixed missing ServiceType member issues in gRPC service implementations
- Removed missing test file dependencies from FFI build configuration

### Changed
- Updated version number from 0.4.0 to 0.5.0
- Improved FFI library build process with proper static/shared library generation
- Enhanced cryptographic hash function implementations for production use
- Updated gRPC client and server implementations with proper connection pooling

### Technical Details
- All hash functions now use consistent `final(&result)` pattern
- FFI libraries (zquic, zcrypto, ghostbridge) now build successfully
- Eliminated all stub implementations in favor of production-ready code
- Improved memory management and type safety throughout the codebase

## [0.4.0] - Previous Release
- Initial modular architecture implementation
- Basic FFI interface for Rust integration
- Core cryptographic primitives