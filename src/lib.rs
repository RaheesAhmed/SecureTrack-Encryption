use wasm_bindgen::prelude::*;

// Set up panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

// Public modules and exports
pub mod config;
pub mod errors;
pub mod key_derivation;
pub mod encryption;
pub mod signing;
pub mod key_sharing;
pub mod utils;

// Tests module
#[cfg(test)]
mod tests;

// Re-export the most important functions for convenience
pub use config::SecurityConfig;
pub use errors::{
    SecureTrackError, Result, 
    get_error_code, debug_error_details,
};
pub use key_derivation::{
    derive_key, derive_key_legacy, derive_key_with_salt,
    derive_key_argon2id, derive_key_hardware_bound, Argon2Config,
    get_key_from_key_result, get_salt_from_key_result,
};
pub use encryption::{
    encrypt_data, decrypt_data,
    encrypt_string, decrypt_to_string,
    encrypt_data_siv, decrypt_data_siv, generate_siv_key,
};
pub use signing::{
    sign_command, verify_command,
    sign_data, verify_data,
};
pub use key_sharing::{
    split_key, combine_key,
};
pub use utils::{
    generate_random_key, generate_key_with_config,
    constant_time_eq, secure_zero,
    hex_to_bytes, bytes_to_hex,
    SecretBytes, create_secret_container,
    measure_entropy,
};

/// Provides fixed example code for documentation tests
/// This module is not exposed to public API
#[doc(hidden)]
pub mod doctest_helpers {
    // Helper to create a test key for documentation examples
    pub fn create_test_key() -> [u8; 32] {
        [0u8; 32] // All zeros key for tests only
    }
    
    /// Helper to create a test SIV key (64 bytes) for documentation examples
    pub fn create_test_siv_key() -> [u8; 64] {
        [0u8; 64] // All zeros key for tests only
    }
    
    /// Helper to create a test biometric hash for key derivation examples
    pub fn create_test_biometric_hash() -> [u8; 32] {
        [0u8; 32] // All zeros for tests only
    }
}

/// SecureTrack Crypto Library
/// 
/// This library provides cryptographic primitives for the SecureTrack
/// anti-theft application. It includes functions for key derivation,
/// encryption/decryption, command signing, and key splitting using
/// military-grade cryptographic algorithms.
/// 
/// # Security Features
/// 
/// - AES-256-GCM for authenticated encryption
/// - AES-256-SIV for misuse-resistant encryption
/// - Argon2id and PBKDF2 for strong key derivation
/// - Hardware-bound key generation with multi-factor security
/// - HMAC-SHA256 for command signing and verification
/// - Shamir's Secret Sharing for secure key backup
/// - Constant-time comparison operations to prevent timing attacks
/// - Memory-protected secure containers with automatic wiping
/// - Secure memory zeroing for sensitive data
/// 
/// # WASM Compatibility
/// 
/// All functions are exported for WebAssembly using wasm-bindgen,
/// allowing seamless integration with Kotlin/Android via WasmEdge.
/// 
/// # Usage Example
/// 
/// ```
/// use securetrack_crypto::{
///     generate_random_key, derive_key, get_key_from_key_result,
///     encrypt_data, decrypt_data, doctest_helpers
/// };
/// 
/// // Generate a random key or derive from user data
/// let key = generate_random_key(32);
/// // or
/// let biometric_hash = doctest_helpers::create_test_biometric_hash();
/// let key_result = derive_key("user_id", &biometric_hash, "device:pattern", None).unwrap();
/// let key = get_key_from_key_result(&key_result, None).unwrap();
/// 
/// // Encrypt sensitive data
/// let encrypted = encrypt_data("sensitive data".as_bytes(), &key).unwrap();
/// 
/// // Later, decrypt the data
/// let decrypted = decrypt_data(&encrypted, &key).unwrap();
/// ```
/// 
/// # Note
/// 
/// This library is designed for use in the SecureTrack anti-theft application
/// and has undergone security review. Always keep cryptographic keys secure
/// and follow best practices for key management.
#[wasm_bindgen]
pub fn version() -> String {
    "1.2.0".to_string()
} 