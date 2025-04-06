use crate::errors::{Result, SecureTrackError, log_crypto_error};
use wasm_bindgen::prelude::*;
use rand::{RngCore, rngs::OsRng};

/// Splits a cryptographic key into n shares, requiring k shares for reconstruction
///
/// # Security
/// This implementation uses an XOR-based secret sharing scheme that requires
/// all shares to reconstruct the secret, which is suitable for backup scenarios
/// but does not support a threshold less than the total number of shares.
///
/// # Parameters
/// * `key` - Key to split (typically 32 bytes)
/// * `n` - Total number of shares to create
/// * `k` - Threshold of shares required for reconstruction (must equal n for this implementation)
///
/// # Returns
/// * Serialized shares as a boxed slice
///
/// # Example
/// ```
/// let shares = split_key(&key, 3, 3)?; // 3 shares, need all 3 to reconstruct
/// ```
#[wasm_bindgen]
pub fn split_key(key: &[u8], n: u8, k: u8) -> Result<Box<[u8]>> {
    // Validate inputs
    if k != n {
        log_crypto_error("split_key", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    if n < 2 {
        log_crypto_error("split_key", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Empty key edge case
    if key.is_empty() {
        let mut result = vec![k, n];
        
        // Create empty shares
        for i in 0..n {
            result.push(1); // length 1 (just the index)
            result.push(i + 1); // Share index
        }
        
        return Ok(result.into_boxed_slice());
    }
    
    // Format: [k, n, share1_len, share1_data, share2_len, share2_data, ...]
    let mut result = Vec::with_capacity(2 + n as usize * (key.len() + 1));
    result.push(k);
    result.push(n);
    
    // Generate n-1 random shares
    let mut shares = Vec::with_capacity(n as usize);
    
    for _ in 0..(n-1) {
        let mut share = vec![0u8; key.len()];
        OsRng.fill_bytes(&mut share);
        
        // Store share index (1-based) and data
        let share_len = key.len() as u8;
        result.push(share_len);
        result.extend_from_slice(&share);
        
        shares.push(share);
    }
    
    // Create the final share such that XOR of all shares equals the original key
    let mut last_share = vec![0u8; key.len()];
    
    for i in 0..key.len() {
        // Start with the original key
        last_share[i] = key[i];
        
        // XOR with all previously generated shares
        for j in 0..(n-1) as usize {
            last_share[i] ^= shares[j][i];
        }
    }
    
    // Add the final share to the result
    result.push(key.len() as u8);
    result.extend_from_slice(&last_share);
    
    Ok(result.into_boxed_slice())
}

/// Reconstructs a key from all shares
///
/// # Security
/// This implementation requires all shares to reconstruct the secret.
///
/// # Parameters
/// * `shares` - Serialized shares from split_key
///
/// # Returns
/// * Reconstructed key as a boxed slice
///
/// # Example
/// ```
/// let key = combine_key(&shares)?;
/// ```
#[wasm_bindgen]
pub fn combine_key(shares: &[u8]) -> Result<Box<[u8]>> {
    if shares.len() < 2 {
        log_crypto_error("combine_key", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Extract k and n from the serialized data
    let k = shares[0];
    let n = shares[1];
    
    if k != n || n < 2 {
        log_crypto_error("combine_key", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Special case: empty key case
    if n * 2 + 2 == shares.len() as u8 {
        // This is the special format we used for empty keys
        return Ok(Vec::new().into_boxed_slice());
    }
    
    // Parse shares
    let mut parsed_shares = Vec::new();
    let mut offset = 2; // Skip k and n
    let mut share_size = 0;
    
    while offset < shares.len() {
        if offset >= shares.len() {
            break;
        }
        
        let share_len = shares[offset] as usize;
        offset += 1;
        
        if offset + share_len > shares.len() {
            log_crypto_error("combine_key", &SecureTrackError::InvalidInputError);
            return Err(SecureTrackError::InvalidInputError);
        }
        
        let share_data = shares[offset..offset + share_len].to_vec();
        
        // Ensure all shares have the same size
        if parsed_shares.is_empty() {
            share_size = share_len;
        } else if share_len != share_size {
            log_crypto_error("combine_key", &SecureTrackError::KeyCombiningError);
            return Err(SecureTrackError::KeyCombiningError);
        }
        
        parsed_shares.push(share_data);
        offset += share_len;
    }
    
    // Check if we have all shares
    if parsed_shares.len() != n as usize {
        log_crypto_error("combine_key", &SecureTrackError::KeyCombiningError);
        return Err(SecureTrackError::KeyCombiningError);
    }
    
    // XOR all shares together to recover the secret
    let mut result = vec![0u8; share_size];
    
    for i in 0..share_size {
        for share in &parsed_shares {
            result[i] ^= share[i];
        }
    }
    
    Ok(result.into_boxed_slice())
} 