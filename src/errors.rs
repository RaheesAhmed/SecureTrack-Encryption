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
    WeakPasswordError,
    MemoryProtectionError,
    HardwareBindingError,
    SystemRandomnessError,
    TamperingDetectedError,
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
            SecureTrackError::WeakPasswordError => write!(f, "Password is too weak"),
            SecureTrackError::MemoryProtectionError => write!(f, "Memory protection failed"),
            SecureTrackError::HardwareBindingError => write!(f, "Hardware binding failed"),
            SecureTrackError::SystemRandomnessError => write!(f, "System randomness failure"),
            SecureTrackError::TamperingDetectedError => write!(f, "Tampering detected"),
        }
    }
}

/// Get a unique error code for each error type
/// 
/// Used for consistent error reporting across platforms
pub fn get_error_code(error: &SecureTrackError) -> u32 {
    match error {
        SecureTrackError::KeyDerivationError => 1001,
        SecureTrackError::EncryptionError => 1002,
        SecureTrackError::DecryptionError => 1003,
        SecureTrackError::SigningError => 1004,
        SecureTrackError::VerificationError => 1005,
        SecureTrackError::KeySplittingError => 1006,
        SecureTrackError::KeyCombiningError => 1007,
        SecureTrackError::InvalidInputError => 1008,
        SecureTrackError::WeakPasswordError => 1009,
        SecureTrackError::MemoryProtectionError => 1010,
        SecureTrackError::HardwareBindingError => 1011,
        SecureTrackError::SystemRandomnessError => 1012,
        SecureTrackError::TamperingDetectedError => 1013,
    }
}

impl std::error::Error for SecureTrackError {}

// Add conversion from SecureTrackError to JsValue for wasm-bindgen
impl From<SecureTrackError> for JsValue {
    fn from(error: SecureTrackError) -> JsValue {
        let code = get_error_code(&error);
        let error_obj = js_sys::Object::new();
        js_sys::Reflect::set(&error_obj, &"code".into(), &code.into())
            .expect("Setting property should not fail");
        js_sys::Reflect::set(&error_obj, &"message".into(), &error.to_string().into())
            .expect("Setting property should not fail");
        error_obj.into()
    }
}

pub type Result<T> = std::result::Result<T, SecureTrackError>;

/// Log crypto errors safely (without exposing sensitive data)
/// 
/// In WASM environment, this will log to browser console
/// In native environment, this will use standard error logging
pub fn log_crypto_error(operation: &str, error: &SecureTrackError) {
    let error_code = get_error_code(error);
    
    #[cfg(target_arch = "wasm32")]
    {
        // Safe logging for WASM environment
        web_sys::console::warn_1(
            &format!("Crypto operation failed: {} - {} (code: {})", 
                    operation, error, error_code).into()
        );
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Standard logging for native environment
        eprintln!("Crypto operation failed: {} - {} (code: {})", 
                 operation, error, error_code);
    }
}

/// Generate a detailed error message for debugging
/// 
/// # Warning
/// This function should only be used in debug mode or secure development
/// environments. It contains more detailed information about the error
/// that might be sensitive in production.
pub fn debug_error_details(operation: &str, error: &SecureTrackError) -> String {
    let error_code = get_error_code(error);
    
    let details = match error {
        SecureTrackError::KeyDerivationError => 
            "Key derivation failed. Possible causes: insufficient memory, weak input parameters.",
        SecureTrackError::EncryptionError => 
            "Encryption failed. Possible causes: invalid key, memory allocation failure.",
        SecureTrackError::DecryptionError => 
            "Decryption failed. Possible causes: wrong key, data tampering, corrupted ciphertext.",
        SecureTrackError::SigningError => 
            "Signing operation failed. Possible causes: invalid key, memory allocation failure.",
        SecureTrackError::VerificationError => 
            "Verification failed. Possible causes: wrong key, data tampering, corrupted signature.",
        SecureTrackError::KeySplittingError => 
            "Key splitting failed. Possible causes: invalid threshold parameters, memory allocation failure.",
        SecureTrackError::KeyCombiningError => 
            "Key combining failed. Possible causes: insufficient shares, corrupted shares.",
        SecureTrackError::InvalidInputError => 
            "Invalid input provided. Possible causes: null input, wrong length, invalid format.",
        SecureTrackError::WeakPasswordError => 
            "Password is too weak. Requirements: minimum 12 chars with mixed case, numbers, and symbols.",
        SecureTrackError::MemoryProtectionError => 
            "Memory protection failed. Possible causes: OS security restrictions, memory access violation.",
        SecureTrackError::HardwareBindingError => 
            "Hardware binding failed. Possible causes: missing or incompatible biometric/hardware data.",
        SecureTrackError::SystemRandomnessError => 
            "System randomness failure. Possible causes: insufficient entropy sources.",
        SecureTrackError::TamperingDetectedError => 
            "Tampering detected. Security breach detected in data or execution environment.",
    };
    
    format!("[{:04}] {} in operation '{}': {}", 
            error_code, error, operation, details)
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