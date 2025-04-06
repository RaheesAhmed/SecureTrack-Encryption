# SecureTrack Crypto Library Documentation

This document provides a comprehensive overview of the SecureTrack crypto library, a Rust-based cryptographic module designed for the SecureTrack anti-theft application with WebAssembly (WASM) compatibility.

## Table of Contents

1. [Library Overview](#library-overview)
2. [Configuration (config.rs)](#configuration-configrs)
3. [Encryption (encryption.rs)](#encryption-encryptionrs)
4. [Error Handling (errors.rs)](#error-handling-errorsrs)
5. [Key Derivation (key_derivation.rs)](#key-derivation-key_derivationrs)
6. [Key Sharing (key_sharing.rs)](#key-sharing-key_sharingrs)
7. [Library Interface (lib.rs)](#library-interface-librs)
8. [Signing (signing.rs)](#signing-signingrs)
9. [Utilities (utils.rs)](#utilities-utilsrs)
10. [Test Suite (tests.rs)](#test-suite-testsrs)
11. [Security Considerations](#security-considerations)
12. [WASM Integration](#wasm-integration)

## Library Overview

The SecureTrack crypto library provides a comprehensive set of cryptographic primitives specifically designed for anti-theft applications. It implements industry-standard algorithms with a focus on security, performance, and cross-platform compatibility through WebAssembly.

**Key Features:**

- AES-256-GCM for authenticated encryption
- Simulated AES-256-SIV mode for misuse-resistant encryption
- Argon2id and PBKDF2 for secure key derivation
- Hardware-bound key generation for multi-factor security
- HMAC-SHA256 for command signing and verification
- Shamir's Secret Sharing for secure key backup and recovery
- Secure memory containers with automatic wiping
- Constant-time operations to prevent timing attacks
- Enhanced error handling with detailed diagnostics
- Entropy measurement for password strength assessment
- Full WASM compatibility for cross-platform use

## Configuration (config.rs)

This module defines security parameters for cryptographic operations.

**Core Components:**

- `SecurityConfig` struct: Configurable parameters for cryptographic operations

  - `pbkdf2_iterations`: Number of iterations for PBKDF2 (default: 100,000)
  - `salt_length`: Salt length in bytes (default: 16)
  - `key_length`: Key length in bytes (default: 32 for AES-256)

- `Argon2Config` struct: Configuration for Argon2id key derivation
  - `memory_size_kib`: Memory cost in KiB (default: 65536 = 64 MiB)
  - `iterations`: Number of passes (default: 3)
  - `parallelism`: Parallelism factor (default: 4)
  - `output_length`: Output key length (default: 32 bytes)
  - `salt_length`: Salt length (default: 16 bytes)

**Security Constants:**

- AES-GCM nonce size: 12 bytes (96 bits as recommended by NIST)
- AES-GCM tag size: 16 bytes (128 bits)
- HMAC-SHA256 output size: 32 bytes (256 bits)

The configuration system enforces minimum security thresholds while allowing customization for different performance/security trade-offs.

## Encryption (encryption.rs)

This module implements AES-256-GCM authenticated encryption with additional features.

**Core Functions:**

- `encrypt_data`: Encrypts data with AES-256-GCM and a random nonce
- `decrypt_data`: Decrypts and authenticates AES-256-GCM ciphertext
- `encrypt_string`: Convenience wrapper for string encryption
- `decrypt_to_string`: Decrypts data and converts to UTF-8 string
- `encrypt_data_siv`: Simplified SIV-mode encryption (currently AES-GCM based)
- `decrypt_data_siv`: Decrypts data encrypted with SIV mode
- `encrypt_data_with_ad`: Encrypts with additional authenticated data
- `decrypt_data_with_ad`: Decrypts with additional authenticated data verification

**Security Features:**

- Uses AES-256-GCM which provides both confidentiality and integrity
- Random 12-byte nonce for each encryption operation
- Authenticated encryption to detect tampering
- Proper nonce and key validation
- Support for additional authenticated data (AAD)

The implementation follows NIST recommendations for AES-GCM, using 96-bit nonces and 128-bit authentication tags.

## Error Handling (errors.rs)

This module provides a standardized error handling system with enhanced diagnostics.

**Core Components:**

- `SecureTrackError` enum: Specific error types for cryptographic operations
- `Result<T>` type: Custom result type for error handling
- `log_crypto_error`: Safe error logging that avoids exposing sensitive data
- `get_error_code`: Maps error types to unique numerical codes
- `debug_error_details`: Detailed error information for debugging
- WASM integration for structured error conversion to JavaScript

**Error Types:**

- `KeyDerivationError`: Issues with key derivation
- `EncryptionError`: Encryption failures
- `DecryptionError`: Decryption or authentication failures
- `SigningError`: Issues with digital signatures
- `VerificationError`: Signature verification failures
- `KeySplittingError`: Problems with key sharing
- `KeyCombiningError`: Issues with share reconstruction
- `InvalidInputError`: Invalid parameters or inputs
- `WeakPasswordError`: Password strength below required threshold
- `MemoryProtectionError`: Memory security operation failures
- `HardwareBindingError`: Issues with hardware-bound keys
- `SystemRandomnessError`: Insufficient entropy problems
- `TamperingDetectedError`: Security breach detection

The error system is designed to provide informative errors without revealing sensitive cryptographic details, while enabling detailed diagnostics for legitimate applications.

## Key Derivation (key_derivation.rs)

This module implements multiple key derivation functions for different security needs.

**Core Functions:**

- `derive_key`: Derives a key from user ID, biometric hash, and sensor pattern (PBKDF2)
- `derive_key_with_salt`: Regenerates a key using a stored salt (PBKDF2)
- `derive_key_argon2id`: State-of-the-art key derivation using Argon2id
- `derive_key_hardware_bound`: Combines passwords with hardware and biometric factors
- `get_key_from_key_result`/`get_salt_from_key_result`: Extract components from key results

**Security Features:**

- Argon2id for memory-hard, highly resistant key derivation
- PBKDF2 with HMAC-SHA256 for computationally intensive key derivation
- Configurable parameters for both algorithms
- Random salt generation
- Multi-factor input combining user ID, biometric data, and device-specific patterns
- Hardware binding for device-specific keys

The implementation provides modern key derivation methods that resist dedicated hardware attacks, with configurable memory, computation, and parallelism parameters.

## Key Sharing (key_sharing.rs)

This module implements key splitting for secure backup and recovery.

**Core Functions:**

- `split_key`: Splits a key into n shares requiring all n shares for reconstruction
- `combine_key`: Recombines shares to recover the original key

**Security Features:**

- XOR-based secret sharing (all shares required for reconstruction)
- Secure serialization format for shares
- Input validation for security parameters

The module provides a simple and reliable XOR-based secret sharing implementation that requires all shares to reconstruct the original key. This approach is cryptographically secure when all shares are stored separately and securely, making it suitable for backup scenarios. Unlike traditional Shamir's Secret Sharing, this implementation does not support arbitrary k-of-n thresholds where k<n, but instead enforces that all shares must be present for reconstruction (n-of-n).

## Library Interface (lib.rs)

This is the main entry point for the library, exposing a unified API.

**Core Components:**

- Module exports and re-exports for simplified API
- WebAssembly initialization
- Version information (1.2.0)
- Documentation test helpers
- Comprehensive documentation

The library is designed for both direct Rust usage and WASM integration, with a focus on providing a consistent, secure API across platforms.

## Signing (signing.rs)

This module implements digital signatures using HMAC-SHA256.

**Core Functions:**

- `sign_command`: Signs a command string with HMAC-SHA256
- `verify_command`: Verifies a command signature
- `sign_data`: Signs arbitrary binary data
- `verify_data`: Verifies a data signature

**Security Features:**

- HMAC-SHA256 for secure authentication
- Constant-time verification to prevent timing attacks
- Input validation for security parameters

The module provides a lightweight alternative to asymmetric cryptography for device command authentication within a controlled environment.

## Utilities (utils.rs)

This module provides cryptographic utility functions with enhanced security capabilities.

**Core Components:**

- `SecretBytes`: Secure container for sensitive data with automatic wiping
- Memory protection functions for secure key handling

**Core Functions:**

- `generate_random_key`: Creates a secure random key of specified length
- `create_secret_container`: Wraps sensitive data in auto-wiping containers
- `constant_time_eq`: Timing-attack resistant comparison
- `secure_zero`: Securely erases sensitive data from memory
- `hex_to_bytes`/`bytes_to_hex`: Hexadecimal conversion utilities
- `measure_entropy`: Evaluates password/data strength using Shannon entropy

**Security Features:**

- Memory-protected containers for sensitive data
- Automatic secure wiping when data is no longer needed
- Cryptographically secure random number generation
- Volatile memory operations to prevent compiler optimization
- Constant-time operations to prevent timing attacks
- Password strength assessment

These utilities provide essential building blocks for implementing secure cryptographic operations with enhanced memory protection.

## Test Suite (tests.rs)

Comprehensive test coverage for all cryptographic functions.

**Test Categories:**

- Key derivation testing (PBKDF2 and Argon2id)
- Encryption/decryption testing (including SIV mode and AAD)
- Digital signature testing
- Key sharing testing
- Error handling testing
- Secure memory handling testing
- Utility function testing
- Edge case testing (empty inputs, large data)
- Entropy measurement testing

The test suite validates both functionality and security properties, ensuring that the library behaves correctly under various conditions.

## Security Considerations

The SecureTrack crypto library implements several best practices for cryptographic security:

1. **Algorithm Selection**:

   - AES-256-GCM for authenticated encryption
   - Argon2id for state-of-the-art key derivation
   - PBKDF2 with HMAC-SHA256 for legacy compatibility
   - HMAC-SHA256 for signatures and authentication

2. **Implementation Techniques**:
   - Memory-protected containers with automatic wiping
   - Constant-time operations to prevent timing attacks
   - Secure memory wiping to minimize exposure of sensitive data
   - Input validation to prevent misuse
3. **Multi-Factor Security**:

   - Hardware-bound key derivation
   - Biometric factor integration
   - Knowledge factor (password) enhancement

4. **Security Diagnostics**:
   - Detailed but safe error reporting
   - Password strength measurement
   - Unique error codes for auditing
5. **Configuration Enforcement**:
   - Minimum security thresholds are enforced
   - Safe defaults with configurable parameters

## WASM Integration

The library is fully compatible with WebAssembly through wasm-bindgen:

1. **JS/TS Interoperability**: All functions are exported with appropriate types
2. **Error Handling**: Custom errors are properly converted to structured JavaScript objects
3. **Memory Management**: Proper ownership transfer between Rust and JavaScript
4. **Initialization**: Sets up panic hooks for better debugging in WASM environments

This enables seamless integration with web applications and Kotlin/Android via WasmEdge with enhanced security features not typically available in JavaScript cryptographic libraries.
