use crate::config::SecurityConfig;
use crate::errors::{Result, SecureTrackError, log_crypto_error};
use rand::{RngCore, rngs::OsRng};
use wasm_bindgen::prelude::*;
use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, Zeroizing};

/// A secure container for sensitive data that will be wiped on drop
/// 
/// # Security
/// SecretBytes holds sensitive data (like keys, passwords) in memory
/// and automatically zeros out memory when dropped using the zeroize crate,
/// which ensures memory is properly cleared even with compiler optimizations.
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Create a new secure container with the given data
    pub fn new(data: &[u8]) -> Self {
        let mut bytes = vec![0u8; data.len()];
        bytes.copy_from_slice(data);
        Self { bytes: Zeroizing::new(bytes) }
    }
    
    /// Generate random bytes for this container
    pub fn random(length: usize) -> Self {
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes: Zeroizing::new(bytes) }
    }
    
    /// Convert to a boxed slice (does not zero original memory)
    pub fn into_boxed_slice(&self) -> Box<[u8]> {
        self.bytes.to_vec().into_boxed_slice()
    }
    
    /// Convert to a boxed slice, securely zeroing the original memory
    /// Note: The memory will still be zeroed when self is dropped,
    /// but this method can be used when you want to control the exact timing.
    pub fn into_boxed_slice_secure(&mut self) -> Box<[u8]> {
        let result = self.bytes.to_vec().into_boxed_slice();
        // The memory will be zeroed when bytes is dropped
        self.bytes = Zeroizing::new(Vec::new());
        result
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

// Note: DerefMut is still provided but should be used carefully since it could
// lead to unzeroized copies. Consider direct methods instead when possible.
impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

// Don't show the secret bytes when debug printing
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes, content hidden)", self.bytes.len())
    }
}

/// Generates a secure random key for encryption or signing
///
/// # Security
/// Generates a cryptographically secure random key using the system's
/// random number generator. For AES-256, use a 32-byte key.
///
/// # Parameters
/// * `length` - Length of the key in bytes (typically 32 for 256-bit security)
///
/// # Returns
/// * Random key as a boxed slice
#[wasm_bindgen]
pub fn generate_random_key(length: usize) -> Box<[u8]> {
    let mut key = vec![0u8; length];
    OsRng.fill_bytes(&mut key);
    key.into_boxed_slice()
}

/// Creates a secure container for sensitive data
///
/// # Security
/// This function creates a container for sensitive data that will be
/// automatically zeroed when it goes out of scope using the zeroize crate,
/// which ensures memory is properly cleared even with compiler optimizations.
///
/// # Parameters
/// * `data` - The sensitive data to protect
///
/// # Returns
/// * The data cloned into a secure container
pub fn create_secret_container(data: &[u8]) -> SecretBytes {
    SecretBytes::new(data)
}

/// Generates a secure random key according to the security configuration
///
/// # Parameters
/// * `config` - Optional security configuration (uses default if None)
///
/// # Returns
/// * Random key of the configured length as a boxed slice
#[wasm_bindgen]
pub fn generate_key_with_config(config: Option<SecurityConfig>) -> Box<[u8]> {
    let config = config.unwrap_or_default();
    generate_random_key(config.key_length)
}

/// Constant-time comparison of two sequences
///
/// # Security
/// This function helps prevent timing attacks by ensuring that
/// the comparison takes the same amount of time regardless of
/// where the first difference occurs.
///
/// # Parameters
/// * `a` - First sequence
/// * `b` - Second sequence
///
/// # Returns
/// * true if the sequences are equal, false otherwise
#[wasm_bindgen]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    
    result == 0
}

/// Securely zeros out sensitive data
///
/// # Security
/// This function helps prevent sensitive data from lingering in memory
/// by explicitly overwriting it with zeros using the zeroize crate,
/// which ensures memory is properly cleared even with compiler optimizations.
///
/// # Parameters
/// * `data` - Data to zero out
#[wasm_bindgen]
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Converts a hexadecimal string to bytes
///
/// # Parameters
/// * `hex` - Hexadecimal string (with or without 0x prefix)
///
/// # Returns
/// * Bytes as a boxed slice or an error if the input is invalid
#[wasm_bindgen]
pub fn hex_to_bytes(hex: &str) -> Result<Box<[u8]>> {
    let hex = hex.trim();
    let hex = if hex.starts_with("0x") { &hex[2..] } else { hex };
    
    if hex.len() % 2 != 0 {
        log_crypto_error("hex_to_bytes", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    let mut result = Vec::with_capacity(hex.len() / 2);
    
    for i in (0..hex.len()).step_by(2) {
        if i + 2 > hex.len() {
            break;
        }
        
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|_| {
                log_crypto_error("hex_to_bytes", &SecureTrackError::InvalidInputError);
                SecureTrackError::InvalidInputError
            })?;
        
        result.push(byte);
    }
    
    Ok(result.into_boxed_slice())
}

/// Converts bytes to a hexadecimal string
///
/// # Parameters
/// * `bytes` - Bytes to convert
/// * `with_prefix` - Whether to include 0x prefix
///
/// # Returns
/// * Hexadecimal string
#[wasm_bindgen]
pub fn bytes_to_hex(bytes: &[u8], with_prefix: bool) -> String {
    let mut result = if with_prefix { String::from("0x") } else { String::new() };
    
    for b in bytes {
        result.push_str(&format!("{:02x}", b));
    }
    
    result
}

/// Performs entropy measurement on a provided passphrase or data
/// 
/// # Security
/// Estimates the bits of entropy in the input data, used for detecting
/// weak passphrases or inputs.
/// 
/// # Parameters
/// * `data` - Data to measure entropy on
/// 
/// # Returns
/// * Estimated bits of entropy
#[wasm_bindgen]
pub fn measure_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    // Count frequencies of each byte
    let mut frequencies = [0u32; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }
    
    // Calculate Shannon entropy
    let mut entropy = 0.0;
    let len = data.len() as f64;
    
    for &count in frequencies.iter() {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }
    
    // Return bits of entropy
    entropy * len
} 