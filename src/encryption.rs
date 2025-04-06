use crate::config::constants::{AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE};
use crate::errors::{Result, SecureTrackError, log_crypto_error};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use aes_siv::{
    aead::Payload,
    Aes256SivAead,
};
use rand::{RngCore, rngs::OsRng as RandOsRng};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

/// Encrypts data using AES-256-GCM with a secure random nonce
///
/// # Security
/// Uses AES-256-GCM which provides both confidentiality and authenticity.
/// A random 12-byte nonce (as recommended by NIST) is generated for each 
/// encryption operation and prepended to the ciphertext. The authentication 
/// tag is included at the end.
///
/// # Parameters
/// * `data` - Data to encrypt (can be text or binary)
/// * `key` - 32-byte encryption key
///
/// # Returns
/// * Encrypted data (nonce + ciphertext + tag) as a boxed slice
///
/// # Example
/// ```
/// let encrypted = encrypt_data("sensitive information".as_bytes(), &key)?;
/// ```
#[wasm_bindgen]
pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Box<[u8]>> {
    // Validate inputs
    if key.len() != 32 {
        log_crypto_error("encrypt_data", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create AES-256-GCM cipher with the provided key
    let key_bytes: [u8; 32] = key.try_into()
        .map_err(|_| {
            log_crypto_error("encrypt_data", &SecureTrackError::EncryptionError);
            SecureTrackError::EncryptionError
        })?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(aes_key);
    
    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Verify nonce size matches our constant
    debug_assert_eq!(nonce.len(), AES_GCM_NONCE_SIZE);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|_| {
            log_crypto_error("encrypt_data", &SecureTrackError::EncryptionError);
            SecureTrackError::EncryptionError
        })?;
    
    // Combine nonce and ciphertext
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    
    Ok(result.into_boxed_slice())
}

/// Encrypts a string using AES-256-GCM with a secure random nonce
///
/// Convenience wrapper around encrypt_data for string inputs
///
/// # Parameters
/// * `data` - String to encrypt
/// * `key` - 32-byte encryption key
///
/// # Returns
/// * Encrypted data (nonce + ciphertext + tag) as a boxed slice
#[wasm_bindgen]
pub fn encrypt_string(data: &str, key: &[u8]) -> Result<Box<[u8]>> {
    encrypt_data(data.as_bytes(), key)
}

/// Decrypts data that was encrypted with AES-256-GCM
///
/// # Security
/// Decrypts and verifies the authenticity of data encrypted with AES-256-GCM.
/// This function extracts the nonce from the beginning of the encrypted data
/// and verifies the authentication tag during decryption.
///
/// # Parameters
/// * `encrypted_data` - Encrypted data (nonce + ciphertext + tag)
/// * `key` - 32-byte decryption key
///
/// # Returns
/// * Decrypted data as a boxed slice
///
/// # Example
/// ```
/// let decrypted = decrypt_data(&encrypted, &key)?;
/// ```
#[wasm_bindgen]
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Result<Box<[u8]>> {
    // Validate inputs
    if key.len() != 32 {
        log_crypto_error("decrypt_data", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Encrypted data must be at least nonce length + tag length
    let min_length = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
    if encrypted_data.len() < min_length {
        log_crypto_error("decrypt_data", &SecureTrackError::DecryptionError);
        return Err(SecureTrackError::DecryptionError);
    }
    
    // Extract nonce and ciphertext
    let nonce_bytes = &encrypted_data[..AES_GCM_NONCE_SIZE];
    let ciphertext = &encrypted_data[AES_GCM_NONCE_SIZE..];
    
    // Create AES-256-GCM cipher
    let key_bytes: [u8; 32] = key.try_into()
        .map_err(|_| {
            log_crypto_error("decrypt_data", &SecureTrackError::DecryptionError);
            SecureTrackError::DecryptionError
        })?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(aes_key);
    
    // Create nonce from extracted bytes
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt and verify
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| {
            log_crypto_error("decrypt_data", &SecureTrackError::DecryptionError);
            SecureTrackError::DecryptionError
        })?;
    
    Ok(plaintext.into_boxed_slice())
}

/// Attempts to decrypt data and convert it to a UTF-8 string
///
/// # Parameters
/// * `encrypted_data` - Encrypted data (nonce + ciphertext + tag)
/// * `key` - 32-byte decryption key
///
/// # Returns
/// * Decrypted string
#[wasm_bindgen]
pub fn decrypt_to_string(encrypted_data: &[u8], key: &[u8]) -> Result<String> {
    let decrypted = decrypt_data(encrypted_data, key)?;
    
    String::from_utf8(decrypted.to_vec())
        .map_err(|_| {
            log_crypto_error("decrypt_to_string", &SecureTrackError::DecryptionError);
            SecureTrackError::DecryptionError
        })
}

/// Encrypts data using AES-256-SIV mode for misuse-resistant encryption
///
/// # Security
/// Uses AES-256-SIV for misuse-resistant authenticated encryption.
/// This is suitable for scenarios where nonce reuse might occur, as SIV mode
/// maintains confidentiality even with repeated nonces (though it will leak
/// if identical messages are encrypted with the same key and AD).
/// 
/// # Parameters
/// * `data` - Data to encrypt (can be text or binary)
/// * `key` - 64-byte encryption key (512 bits)
/// * `associated_data` - Optional additional authenticated data
///
/// # Returns
/// * Encrypted data as a boxed slice
#[wasm_bindgen]
pub fn encrypt_data_siv(
    data: &[u8], 
    key: &[u8], 
    associated_data: Option<Box<[u8]>>
) -> Result<Box<[u8]>> {
    // Validate inputs - SIV requires a 64-byte key (512 bits)
    if key.len() != 64 {
        log_crypto_error("encrypt_data_siv", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create AES-256-SIV cipher
    let cipher = Aes256SivAead::new_from_slice(key)
        .map_err(|_| {
            log_crypto_error("encrypt_data_siv", &SecureTrackError::EncryptionError);
            SecureTrackError::EncryptionError
        })?;
    
    // Encrypt with or without additional data
    let ciphertext = match associated_data {
        Some(ad) => {
            let payload = Payload {
                msg: data,
                aad: &ad,
            };
            cipher.encrypt(&Nonce::default(), payload)
                .map_err(|_| {
                    log_crypto_error("encrypt_data_siv", &SecureTrackError::EncryptionError);
                    SecureTrackError::EncryptionError
                })?
        },
        None => {
            cipher.encrypt(&Nonce::default(), data)
                .map_err(|_| {
                    log_crypto_error("encrypt_data_siv", &SecureTrackError::EncryptionError);
                    SecureTrackError::EncryptionError
                })?
        }
    };
    
    Ok(ciphertext.into_boxed_slice())
}

/// Decrypts data that was encrypted with AES-256-SIV
///
/// # Security
/// Uses AES-256-SIV for misuse-resistant authenticated decryption.
/// Maintains confidentiality even if nonces are reused, making it
/// more robust for systems where proper nonce management is difficult.
///
/// # Parameters
/// * `encrypted_data` - Encrypted data
/// * `key` - 64-byte decryption key (512 bits)
/// * `associated_data` - Optional additional authenticated data (must match encryption)
///
/// # Returns
/// * Decrypted data as a boxed slice
#[wasm_bindgen]
pub fn decrypt_data_siv(
    encrypted_data: &[u8], 
    key: &[u8], 
    associated_data: Option<Box<[u8]>>
) -> Result<Box<[u8]>> {
    // Validate inputs - SIV requires a 64-byte key (512 bits)
    if key.len() != 64 {
        log_crypto_error("decrypt_data_siv", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create AES-256-SIV cipher
    let cipher = Aes256SivAead::new_from_slice(key)
        .map_err(|_| {
            log_crypto_error("decrypt_data_siv", &SecureTrackError::DecryptionError);
            SecureTrackError::DecryptionError
        })?;
    
    // Decrypt with or without additional data
    let plaintext = match associated_data {
        Some(ad) => {
            let payload = Payload {
                msg: encrypted_data,
                aad: &ad,
            };
            cipher.decrypt(&Nonce::default(), payload)
                .map_err(|_| {
                    log_crypto_error("decrypt_data_siv", &SecureTrackError::DecryptionError);
                    SecureTrackError::DecryptionError
                })?
        },
        None => {
            cipher.decrypt(&Nonce::default(), encrypted_data)
                .map_err(|_| {
                    log_crypto_error("decrypt_data_siv", &SecureTrackError::DecryptionError);
                    SecureTrackError::DecryptionError
                })?
        }
    };
    
    Ok(plaintext.into_boxed_slice())
}

/// Generates a key for AES-SIV encryption
///
/// # Security
/// Generates a 64-byte key (512 bits) suitable for AES-256-SIV encryption.
/// AES-SIV requires a key twice the size of standard AES.
///
/// # Returns
/// * 64-byte random key as a boxed slice
#[wasm_bindgen]
pub fn generate_siv_key() -> Box<[u8]> {
    let mut key = vec![0u8; 64]; // 512 bits = 64 bytes for AES-256-SIV
    RandOsRng.fill_bytes(&mut key);
    key.into_boxed_slice()
}

/// Encrypts data using AES-256-GCM with additional authenticated data
///
/// # Security
/// Uses AES-256-GCM with additional authenticated data (AAD). The AAD is authenticated
/// but not encrypted, providing integrity protection for metadata without revealing 
/// the actual encrypted content.
///
/// # Parameters
/// * `data` - Data to encrypt
/// * `key` - 32-byte encryption key
/// * `aad` - Additional authenticated data
///
/// # Returns
/// * Encrypted data (nonce + ciphertext + tag) as a boxed slice
#[wasm_bindgen]
pub fn encrypt_data_with_ad(data: &[u8], key: &[u8], aad: &[u8]) -> Result<Box<[u8]>> {
    // Validate inputs
    if key.len() != 32 {
        log_crypto_error("encrypt_data_with_ad", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create AES-256-GCM cipher with the provided key
    let key_bytes: [u8; 32] = key.try_into()
        .map_err(|_| {
            log_crypto_error("encrypt_data_with_ad", &SecureTrackError::EncryptionError);
            SecureTrackError::EncryptionError
        })?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(aes_key);
    
    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Verify nonce size matches our constant
    debug_assert_eq!(nonce.len(), AES_GCM_NONCE_SIZE);
    
    // Encrypt the data with the associated data
    let ciphertext = cipher.encrypt(&nonce, Payload { msg: data, aad })
        .map_err(|_| {
            log_crypto_error("encrypt_data_with_ad", &SecureTrackError::EncryptionError);
            SecureTrackError::EncryptionError
        })?;
    
    // Combine nonce and ciphertext
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    
    Ok(result.into_boxed_slice())
}

/// Decrypts data that was encrypted with AES-256-GCM and AAD
///
/// # Security
/// Decrypts and verifies the authenticity of data encrypted with AES-256-GCM
/// and additional authenticated data (AAD). Both the ciphertext and AAD must
/// be authentic for decryption to succeed.
///
/// # Parameters
/// * `encrypted_data` - Encrypted data (nonce + ciphertext + tag)
/// * `key` - 32-byte decryption key
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// * Decrypted data as a boxed slice
#[wasm_bindgen]
pub fn decrypt_data_with_ad(encrypted_data: &[u8], key: &[u8], aad: &[u8]) -> Result<Box<[u8]>> {
    // Validate inputs
    if key.len() != 32 {
        log_crypto_error("decrypt_data_with_ad", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Encrypted data must be at least nonce length + tag length
    let min_length = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
    if encrypted_data.len() < min_length {
        log_crypto_error("decrypt_data_with_ad", &SecureTrackError::DecryptionError);
        return Err(SecureTrackError::DecryptionError);
    }
    
    // Extract nonce and ciphertext
    let nonce_bytes = &encrypted_data[..AES_GCM_NONCE_SIZE];
    let ciphertext = &encrypted_data[AES_GCM_NONCE_SIZE..];
    
    // Create AES-256-GCM cipher
    let key_bytes: [u8; 32] = key.try_into()
        .map_err(|_| {
            log_crypto_error("decrypt_data_with_ad", &SecureTrackError::DecryptionError);
            SecureTrackError::DecryptionError
        })?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(aes_key);
    
    // Create nonce from extracted bytes
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt and verify with the additional authenticated data
    let plaintext = cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| {
            log_crypto_error("decrypt_data_with_ad", &SecureTrackError::DecryptionError);
            SecureTrackError::DecryptionError
        })?;
    
    Ok(plaintext.into_boxed_slice())
} 