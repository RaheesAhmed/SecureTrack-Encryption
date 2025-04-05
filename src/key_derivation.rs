use crate::config::SecurityConfig;
use crate::errors::{Result, SecureTrackError};
use hmac::{Hmac};
use pbkdf2::pbkdf2;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

/// Derives a cryptographic key from user identifiers and biometric data
///
/// # Security
/// Uses PBKDF2 with HMAC-SHA256 and a configurable number of iterations (default: 100,000)
/// with a configurable-length random salt (default: 16 bytes) to derive a cryptographically strong key.
/// The use of biometric_hash and sensor_pattern adds additional entropy that enhances
/// security against brute force attacks.
///
/// # Parameters
/// * `uid` - User identifier string
/// * `biometric_hash` - 32-byte hash derived from biometric data
/// * `sensor_pattern` - Device-specific sensor pattern string
/// * `config` - Optional security configuration (uses default if None)
///
/// # Returns
/// * A boxed slice containing the derived key followed by the salt
///
/// # Example
/// ```
/// let key_result = derive_key("user123", biometric_hash, "sensor:pattern", None)?;
/// let key = get_key_from_key_result(&key_result)?;
/// let salt = get_salt_from_key_result(&key_result)?;
/// ```
#[wasm_bindgen]
pub fn derive_key(
    uid: &str,
    biometric_hash: Vec<u8>,
    sensor_pattern: &str,
    config: Option<SecurityConfig>,
) -> Result<Box<[u8]>> {
    // Use provided config or default
    let config = config.unwrap_or_default();
    
    // Validate inputs
    if biometric_hash.len() != 32 {
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Generate a random salt of configured length
    let mut salt = vec![0u8; config.salt_length];
    OsRng.fill_bytes(&mut salt);
    
    // Combine inputs for added entropy
    let combined_input = [
        uid.as_bytes(),
        &biometric_hash,
        sensor_pattern.as_bytes(),
    ].concat();
    
    // Derive key using PBKDF2 with HMAC-SHA256 and configured iterations
    let mut derived_key = vec![0u8; config.key_length];
    let _ = pbkdf2::<Hmac<Sha256>>(
        &combined_input,
        &salt,
        config.pbkdf2_iterations,
        &mut derived_key,
    );
    
    // Return key and salt
    let mut result = Vec::with_capacity(derived_key.len() + salt.len());
    result.extend_from_slice(&derived_key);
    result.extend_from_slice(&salt);
    
    Ok(result.into_boxed_slice())
}

/// Legacy version of derive_key for backward compatibility
///
/// Uses default security parameters (100,000 iterations, 16-byte salt, 32-byte key)
#[wasm_bindgen]
pub fn derive_key_legacy(
    uid: &str,
    biometric_hash: Vec<u8>,
    sensor_pattern: &str,
) -> Result<Box<[u8]>> {
    derive_key(uid, biometric_hash, sensor_pattern, None)
}

/// Retrieves the salt from the derive_key result
///
/// # Parameters
/// * `key_result` - The result from a call to derive_key
/// * `config` - Optional security configuration (uses default if None)
///
/// # Returns
/// * The salt as a boxed slice
#[wasm_bindgen]
pub fn get_salt_from_key_result(
    key_result: &[u8],
    config: Option<SecurityConfig>,
) -> Result<Box<[u8]>> {
    let config = config.unwrap_or_default();
    let expected_length = config.key_length + config.salt_length;
    
    if key_result.len() != expected_length {
        return Err(SecureTrackError::InvalidInputError);
    }
    
    let salt = key_result[config.key_length..].to_vec();
    Ok(salt.into_boxed_slice())
}

/// Legacy version of get_salt_from_key_result for backward compatibility
///
/// Assumes 32-byte key and 16-byte salt
#[wasm_bindgen]
pub fn get_salt_from_key_result_legacy(key_result: &[u8]) -> Result<Box<[u8]>> {
    if key_result.len() != 48 { // 32 bytes key + 16 bytes salt
        return Err(SecureTrackError::InvalidInputError);
    }
    
    let salt = key_result[32..].to_vec();
    Ok(salt.into_boxed_slice())
}

/// Retrieves the key from the derive_key result
///
/// # Parameters
/// * `key_result` - The result from a call to derive_key
/// * `config` - Optional security configuration (uses default if None)
///
/// # Returns
/// * The derived key as a boxed slice
#[wasm_bindgen]
pub fn get_key_from_key_result(
    key_result: &[u8],
    config: Option<SecurityConfig>,
) -> Result<Box<[u8]>> {
    let config = config.unwrap_or_default();
    let expected_length = config.key_length + config.salt_length;
    
    if key_result.len() != expected_length {
        return Err(SecureTrackError::InvalidInputError);
    }
    
    let key = key_result[..config.key_length].to_vec();
    Ok(key.into_boxed_slice())
}

/// Legacy version of get_key_from_key_result for backward compatibility
///
/// Assumes 32-byte key and 16-byte salt
#[wasm_bindgen]
pub fn get_key_from_key_result_legacy(key_result: &[u8]) -> Result<Box<[u8]>> {
    if key_result.len() != 48 { // 32 bytes key + 16 bytes salt
        return Err(SecureTrackError::InvalidInputError);
    }
    
    let key = key_result[..32].to_vec();
    Ok(key.into_boxed_slice())
}

/// Derives a key using a previously generated salt
///
/// # Security
/// This allows recreating a key with the same salt, useful for key recovery
/// scenarios. Uses configurable number of iterations for security.
///
/// # Parameters
/// * `uid` - User identifier string
/// * `biometric_hash` - 32-byte hash derived from biometric data
/// * `sensor_pattern` - Device-specific sensor pattern string
/// * `salt` - Salt previously generated by derive_key
/// * `config` - Optional security configuration (uses default if None)
///
/// # Returns
/// * The derived key as a boxed slice
#[wasm_bindgen]
pub fn derive_key_with_salt(
    uid: &str,
    biometric_hash: Vec<u8>,
    sensor_pattern: &str,
    salt: &[u8],
    config: Option<SecurityConfig>,
) -> Result<Box<[u8]>> {
    let config = config.unwrap_or_default();
    
    // Validate inputs
    if biometric_hash.len() != 32 {
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Combine inputs for added entropy
    let combined_input = [
        uid.as_bytes(),
        &biometric_hash,
        sensor_pattern.as_bytes(),
    ].concat();
    
    // Derive key using PBKDF2 with HMAC-SHA256 and configured iterations
    let mut derived_key = vec![0u8; config.key_length];
    let _ = pbkdf2::<Hmac<Sha256>>(
        &combined_input,
        salt,
        config.pbkdf2_iterations,
        &mut derived_key,
    );
    
    Ok(derived_key.into_boxed_slice())
}

/// Legacy version of derive_key_with_salt for backward compatibility
///
/// Uses default security parameters (100,000 iterations, 32-byte key)
#[wasm_bindgen]
pub fn derive_key_with_salt_legacy(
    uid: &str,
    biometric_hash: Vec<u8>,
    sensor_pattern: &str,
    salt: &[u8],
) -> Result<Box<[u8]>> {
    // Validate inputs
    if biometric_hash.len() != 32 || salt.len() != 16 {
        return Err(SecureTrackError::InvalidInputError);
    }
    
    derive_key_with_salt(uid, biometric_hash, sensor_pattern, salt, None)
} 