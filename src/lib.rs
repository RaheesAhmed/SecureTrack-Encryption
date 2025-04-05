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
pub use errors::{SecureTrackError, Result};
pub use key_derivation::{
    derive_key, derive_key_legacy, derive_key_with_salt,
    get_key_from_key_result, get_salt_from_key_result,
};
pub use encryption::{
    encrypt_data, decrypt_data,
    encrypt_string, decrypt_to_string,
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
};

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
/// - PBKDF2 with HMAC-SHA256 for key derivation (100,000 iterations by default)
/// - HMAC-SHA256 for command signing and verification
/// - Shamir's Secret Sharing for secure key backup
/// - Constant-time comparison operations to prevent timing attacks
/// - Secure memory wiping for sensitive data
/// 
/// # WASM Compatibility
/// 
/// All functions are exported for WebAssembly using wasm-bindgen,
/// allowing seamless integration with Kotlin/Android via WasmEdge.
/// 
/// # Usage Example
/// 
/// ```
/// // Generate a random key or derive from user data
/// let key = generate_random_key(32);
/// // or
/// let key_result = derive_key("user_id", biometric_hash, "device:pattern", None)?;
/// let key = get_key_from_key_result(&key_result, None)?;
/// 
/// // Encrypt sensitive data
/// let encrypted = encrypt_data("sensitive data".as_bytes(), &key)?;
/// 
/// // Later, decrypt the data
/// let decrypted = decrypt_data(&encrypted, &key)?;
/// ```
/// 
/// # Note
/// 
/// This library is designed for use in the SecureTrack anti-theft application
/// and has undergone security review. Always keep cryptographic keys secure
/// and follow best practices for key management.
#[wasm_bindgen]
pub fn version() -> String {
    "1.0.0".to_string()
} 