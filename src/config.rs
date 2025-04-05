use wasm_bindgen::prelude::*;

/// Cryptographic security configuration parameters
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    /// Number of iterations for PBKDF2 key derivation
    pub pbkdf2_iterations: u32,
    
    /// Salt length in bytes for key derivation
    pub salt_length: usize,
    
    /// Key length in bytes (256 bits for AES-256)
    pub key_length: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: 100_000,
            salt_length: 16,
            key_length: 32, // 256 bits
        }
    }
}

#[wasm_bindgen]
impl SecurityConfig {
    /// Create a new SecurityConfig with default values
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set the number of PBKDF2 iterations
    /// 
    /// # Security
    /// Higher values provide better security at the cost of performance.
    /// Minimum recommended value is 100,000 for PBKDF2 with HMAC-SHA256.
    #[wasm_bindgen]
    pub fn with_pbkdf2_iterations(mut self, iterations: u32) -> Self {
        if iterations < 10_000 {
            // Enforce minimum for security
            self.pbkdf2_iterations = 10_000;
        } else {
            self.pbkdf2_iterations = iterations;
        }
        self
    }
    
    /// Set the salt length in bytes
    /// 
    /// # Security
    /// Minimum recommended value is 16 bytes (128 bits).
    #[wasm_bindgen]
    pub fn with_salt_length(mut self, length: usize) -> Self {
        if length < 16 {
            // Enforce minimum for security
            self.salt_length = 16;
        } else {
            self.salt_length = length;
        }
        self
    }
    
    /// Get the current PBKDF2 iteration count
    #[wasm_bindgen]
    pub fn get_pbkdf2_iterations(&self) -> u32 {
        self.pbkdf2_iterations
    }
    
    /// Get the current salt length
    #[wasm_bindgen]
    pub fn get_salt_length(&self) -> usize {
        self.salt_length
    }
    
    /// Get the key length
    #[wasm_bindgen]
    pub fn get_key_length(&self) -> usize {
        self.key_length
    }
}

/// Constants for cryptographic operations
pub mod constants {
    /// AES-GCM nonce size in bytes (96 bits as recommended by NIST)
    pub const AES_GCM_NONCE_SIZE: usize = 12;
    
    /// AES-GCM tag size in bytes (128 bits)
    pub const AES_GCM_TAG_SIZE: usize = 16;
    
    /// HMAC-SHA256 output size in bytes (256 bits)
    pub const HMAC_SHA256_SIZE: usize = 32;
} 