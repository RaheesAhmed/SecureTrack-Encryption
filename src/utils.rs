use crate::config::SecurityConfig;
use rand::{RngCore, rngs::OsRng};
use wasm_bindgen::prelude::*;

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
/// by explicitly overwriting it with zeros. Note that Rust's compiler
/// optimizations can sometimes interfere with this, but we do our best.
///
/// # Parameters
/// * `data` - Mutable slice of data to zero out
#[wasm_bindgen]
pub fn secure_zero(data: &mut [u8]) {
    // Use volatile writes to prevent compiler optimization
    for byte in data.iter_mut() {
        volatile_write(byte, 0);
    }
}

// Helper function for volatile writes to prevent compiler optimization
fn volatile_write(ptr: &mut u8, value: u8) {
    unsafe {
        std::ptr::write_volatile(ptr, value);
    }
}

/// Converts a hex string to bytes
///
/// # Parameters
/// * `hex` - Hexadecimal string
///
/// # Returns
/// * Byte array as a boxed slice, or None if invalid hex
#[wasm_bindgen]
pub fn hex_to_bytes(hex: &str) -> Option<Box<[u8]>> {
    // Ensure even length
    if hex.len() % 2 != 0 {
        return None;
    }
    
    let mut result = Vec::with_capacity(hex.len() / 2);
    
    for i in (0..hex.len()).step_by(2) {
        if let (Some(high), Some(low)) = (
            from_hex_char(hex.chars().nth(i).unwrap()),
            from_hex_char(hex.chars().nth(i + 1).unwrap())
        ) {
            result.push((high << 4) | low);
        } else {
            return None;
        }
    }
    
    Some(result.into_boxed_slice())
}

/// Converts bytes to a hex string
///
/// # Parameters
/// * `bytes` - Byte array
///
/// # Returns
/// * Hexadecimal string representation
#[wasm_bindgen]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    
    for &byte in bytes {
        result.push(to_hex_char((byte >> 4) & 0xF));
        result.push(to_hex_char(byte & 0xF));
    }
    
    result
}

// Helper function to convert a hex character to its value
fn from_hex_char(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

// Helper function to convert a nibble to a hex character
fn to_hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!(),
    }
} 