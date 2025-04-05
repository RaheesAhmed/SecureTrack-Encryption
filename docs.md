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
- PBKDF2 with HMAC-SHA256 for secure key derivation
- HMAC-SHA256 for command signing and verification
- Shamir's Secret Sharing for secure key backup and recovery
- Constant-time operations to prevent timing attacks
- Secure memory wiping for sensitive data
- Full WASM compatibility for cross-platform use

## Configuration (config.rs)

This module defines security parameters for cryptographic operations.

**Core Components:**

- `SecurityConfig` struct: Configurable parameters for cryptographic operations
  - `pbkdf2_iterations`: Number of iterations for PBKDF2 (default: 100,000)
  - `salt_length`: Salt length in bytes (default: 16)
  - `key_length`: Key length in bytes (default: 32 for AES-256)

**Security Constants:**

- AES-GCM nonce size: 12 bytes (96 bits as recommended by NIST)
- AES-GCM tag size: 16 bytes (128 bits)
- HMAC-SHA256 output size: 32 bytes (256 bits)

The configuration system enforces minimum security thresholds while allowing customization for different performance/security trade-offs.

## Encryption (encryption.rs)

This module implements AES-256-GCM authenticated encryption.

**Core Functions:**

- `encrypt_data`: Encrypts data with AES-256-GCM and a random nonce
- `decrypt_data`: Decrypts and authenticates AES-256-GCM ciphertext
- `encrypt_string`: Convenience wrapper for string encryption
- `decrypt_to_string`: Decrypts data and converts to UTF-8 string

**Security Features:**

- Uses AES-256-GCM which provides both confidentiality and integrity
- Random 12-byte nonce for each encryption operation
- Authenticated encryption to detect tampering
- Proper nonce and key validation

The implementation follows NIST recommendations for AES-GCM, using 96-bit nonces and 128-bit authentication tags.

## Error Handling (errors.rs)

This module provides a standardized error handling system.

**Core Components:**

- `SecureTrackError` enum: Specific error types for cryptographic operations
- `Result<T>` type: Custom result type for error handling
- `log_crypto_error`: Safe error logging that avoids exposing sensitive data
- WASM integration for error conversion to JavaScript

**Error Types:**

- `KeyDerivationError`: Issues with key derivation
- `EncryptionError`: Encryption failures
- `DecryptionError`: Decryption or authentication failures
- `SigningError`: Issues with digital signatures
- `VerificationError`: Signature verification failures
- `KeySplittingError`: Problems with key sharing
- `KeyCombiningError`: Issues with share reconstruction
- `InvalidInputError`: Invalid parameters or inputs

The error system is designed to provide informative errors without revealing sensitive cryptographic details.

## Key Derivation (key_derivation.rs)

This module implements PBKDF2 key derivation functions.

**Core Functions:**

- `derive_key`: Derives a key from user ID, biometric hash, and sensor pattern
- `derive_key_with_salt`: Regenerates a key using a stored salt
- `get_key_from_key_result`/`get_salt_from_key_result`: Extract components from key results

**Security Features:**

- PBKDF2 with HMAC-SHA256 for computationally intensive key derivation
- Configurable iteration count (default: 100,000)
- Random salt generation
- Multi-factor input combining user ID, biometric data, and device-specific patterns

The implementation provides both modern configurable interfaces and legacy compatibility functions to support version migration.

## Key Sharing (key_sharing.rs)

This module implements key splitting for secure backup and recovery.

**Core Functions:**

- `split_key`: Splits a key into n shares with k-threshold reconstruction
- `combine_key`: Recombines shares to recover the original key

**Security Features:**

- Threshold cryptography (requires a minimum number of shares)
- Secure serialization format for shares
- Input validation for security parameters

The module provides a simplified implementation of Shamir's Secret Sharing designed for testing, with clear documentation about its limitations for production use.

## Library Interface (lib.rs)

This is the main entry point for the library, exposing a unified API.

**Core Components:**

- Module exports and re-exports for simplified API
- WebAssembly initialization
- Version information
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

This module provides cryptographic utility functions.

**Core Functions:**

- `generate_random_key`: Creates a secure random key of specified length
- `constant_time_eq`: Timing-attack resistant comparison
- `secure_zero`: Securely erases sensitive data from memory
- `hex_to_bytes`/`bytes_to_hex`: Hexadecimal conversion utilities

**Security Features:**

- Cryptographically secure random number generation
- Volatile memory operations to prevent compiler optimization
- Constant-time operations to prevent timing attacks

These utilities provide essential building blocks for implementing secure cryptographic operations.

## Test Suite (tests.rs)

Comprehensive test coverage for all cryptographic functions.

**Test Categories:**

- Key derivation testing
- Encryption/decryption testing
- Digital signature testing
- Key sharing testing
- Error handling testing
- Utility function testing
- Edge case testing (empty inputs, large data)

The test suite validates both functionality and security properties, ensuring that the library behaves correctly under various conditions.

## Security Considerations

The SecureTrack crypto library implements several best practices for cryptographic security:

1. **Algorithm Selection**: Uses modern, well-vetted algorithms (AES-256-GCM, PBKDF2 with HMAC-SHA256)
2. **Implementation Techniques**:
   - Constant-time operations to prevent timing attacks
   - Secure memory wiping to minimize exposure of sensitive data
   - Input validation to prevent misuse
3. **Configuration Enforcement**: Minimum security thresholds are enforced
4. **Error Handling**: Informative errors without leaking sensitive information

## WASM Integration

The library is fully compatible with WebAssembly through wasm-bindgen:

1. **JS/TS Interoperability**: All functions are exported with appropriate types
2. **Error Handling**: Custom errors are properly converted to JavaScript values
3. **Memory Management**: Proper ownership transfer between Rust and JavaScript
4. **Initialization**: Sets up panic hooks for better debugging in WASM environments

This enables seamless integration with web applications and Kotlin/Android via WasmEdge.
