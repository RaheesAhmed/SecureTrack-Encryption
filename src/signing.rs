use crate::config::constants::HMAC_SHA256_SIZE;
use crate::errors::{Result, SecureTrackError, log_crypto_error};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

/// Signs a command using HMAC-SHA256
///
/// # Security
/// Uses HMAC-SHA256 to create a secure signature that verifies both
/// the authenticity and integrity of the command. This prevents tampering
/// with commands sent to the device.
///
/// # Parameters
/// * `command` - Command string to sign
/// * `key` - 32-byte signing key
///
/// # Returns
/// * 32-byte HMAC signature as a boxed slice
///
/// # Example
/// ```
/// let signature = sign_command("LOCK_DEVICE", &key)?;
/// ```
#[wasm_bindgen]
pub fn sign_command(command: &str, key: &[u8]) -> Result<Box<[u8]>> {
    // Validate inputs
    if key.len() != 32 {
        log_crypto_error("sign_command", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create HMAC-SHA256 instance
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| {
            log_crypto_error("sign_command", &SecureTrackError::SigningError);
            SecureTrackError::SigningError
        })?;
    
    // Update with command data
    mac.update(command.as_bytes());
    
    // Finalize and get result
    let result = mac.finalize().into_bytes();
    
    // Verify signature size matches our constant
    debug_assert_eq!(result.len(), HMAC_SHA256_SIZE);
    
    Ok(result.to_vec().into_boxed_slice())
}

/// Signs arbitrary data using HMAC-SHA256
///
/// Similar to sign_command but accepts any binary data
///
/// # Parameters
/// * `data` - Data to sign
/// * `key` - 32-byte signing key
///
/// # Returns
/// * 32-byte HMAC signature as a boxed slice
#[wasm_bindgen]
pub fn sign_data(data: &[u8], key: &[u8]) -> Result<Box<[u8]>> {
    // Validate inputs
    if key.len() != 32 {
        log_crypto_error("sign_data", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create HMAC-SHA256 instance
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| {
            log_crypto_error("sign_data", &SecureTrackError::SigningError);
            SecureTrackError::SigningError
        })?;
    
    // Update with data
    mac.update(data);
    
    // Finalize and get result
    let result = mac.finalize().into_bytes();
    
    Ok(result.to_vec().into_boxed_slice())
}

/// Verifies a command signature using HMAC-SHA256
///
/// # Security
/// Verifies that a command has not been tampered with by checking
/// its HMAC-SHA256 signature. Provides protection against unauthorized
/// command execution.
///
/// # Parameters
/// * `command` - Command string to verify
/// * `signature` - 32-byte HMAC signature to check
/// * `key` - 32-byte verification key
///
/// # Returns
/// * Boolean indicating if the signature is valid
///
/// # Example
/// ```
/// let is_valid = verify_command("LOCK_DEVICE", &signature, &key)?;
/// ```
#[wasm_bindgen]
pub fn verify_command(command: &str, signature: &[u8], key: &[u8]) -> Result<bool> {
    verify_data(command.as_bytes(), signature, key)
}

/// Verifies a data signature using HMAC-SHA256
///
/// # Parameters
/// * `data` - Data to verify
/// * `signature` - 32-byte HMAC signature to check
/// * `key` - 32-byte verification key
///
/// # Returns
/// * Boolean indicating if the signature is valid
#[wasm_bindgen]
pub fn verify_data(data: &[u8], signature: &[u8], key: &[u8]) -> Result<bool> {
    // Validate inputs
    if key.len() != 32 || signature.len() != HMAC_SHA256_SIZE {
        log_crypto_error("verify_data", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create HMAC-SHA256 instance
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| {
            log_crypto_error("verify_data", &SecureTrackError::VerificationError);
            SecureTrackError::VerificationError
        })?;
    
    // Update with data
    mac.update(data);
    
    // Verify signature
    match mac.verify_slice(signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
} 