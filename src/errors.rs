use std::fmt;
use wasm_bindgen::prelude::*;

/// Custom error type for SecureTrack crypto operations
#[derive(Debug)]
pub enum SecureTrackError {
    KeyDerivationError,
    EncryptionError,
    DecryptionError,
    SigningError,
    VerificationError,
    KeySplittingError,
    KeyCombiningError,
    InvalidInputError,
}

impl fmt::Display for SecureTrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecureTrackError::KeyDerivationError => write!(f, "Key derivation failed"),
            SecureTrackError::EncryptionError => write!(f, "Encryption failed"),
            SecureTrackError::DecryptionError => write!(f, "Decryption failed"),
            SecureTrackError::SigningError => write!(f, "Signing operation failed"),
            SecureTrackError::VerificationError => write!(f, "Verification failed"),
            SecureTrackError::KeySplittingError => write!(f, "Key splitting failed"),
            SecureTrackError::KeyCombiningError => write!(f, "Key combining failed"),
            SecureTrackError::InvalidInputError => write!(f, "Invalid input provided"),
        }
    }
}

impl std::error::Error for SecureTrackError {}

// Add conversion from SecureTrackError to JsValue for wasm-bindgen
impl From<SecureTrackError> for JsValue {
    fn from(error: SecureTrackError) -> JsValue {
        JsValue::from_str(&error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SecureTrackError>;

/// Log crypto errors safely (without exposing sensitive data)
/// 
/// In WASM environment, this will log to browser console
/// In native environment, this will use standard error logging
pub fn log_crypto_error(operation: &str, error: &SecureTrackError) {
    #[cfg(target_arch = "wasm32")]
    {
        // Safe logging for WASM environment
        web_sys::console::warn_1(
            &format!("Crypto operation failed: {} - {}", operation, error).into()
        );
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Standard logging for native environment
        eprintln!("Crypto operation failed: {} - {}", operation, error);
    }
}

/// Macro to handle errors with logging
#[macro_export]
macro_rules! log_err {
    ($operation:expr, $result:expr) => {
        $result.map_err(|e| {
            $crate::errors::log_crypto_error($operation, &e);
            e
        })
    };
} 