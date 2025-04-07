# Changelog

All notable changes to the SecureTrack Crypto Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2023-07-15

### Added

- Hardware-bound key derivation for multi-factor security
- Secure memory containers with automatic wiping (SecretBytes)
- SIV-mode encryption for misuse resistance
- Key sharing/splitting for secure backup
- Comprehensive error handling with unique error codes
- Password strength measurement using Shannon entropy
- WebAssembly (WASM) integration with full JavaScript bindings
- Performance benchmarking suite
- Android integration via WasmEdge

### Changed

- Improved Argon2id parameters for better security/performance balance
- Enhanced constant-time operations for better side-channel resistance
- Optimized WASM build configuration

### Fixed

- Memory leaks in cryptographic operations
- Timing vulnerabilities in verification functions
- Proper error propagation in WebAssembly context

## [1.1.0] - 2023-05-01

### Added

- Argon2id key derivation support
- HMAC-SHA256 signing and verification
- Comprehensive test coverage
- Basic WebAssembly support

### Changed

- Improved AES-GCM implementation with better IV handling
- Enhanced error messages

## [1.0.0] - 2023-03-15

### Added

- Initial release
- AES-256-GCM authenticated encryption
- PBKDF2 key derivation
- Basic key management
- Random key generation
