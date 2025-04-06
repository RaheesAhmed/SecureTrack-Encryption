use crate::config::SecurityConfig;
use crate::errors::{Result, SecureTrackError, log_crypto_error};
use crate::utils::SecretBytes;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use argon2::{Argon2, Algorithm, Version, Params};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

/// Argon2 security configuration parameters
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Argon2Config {
    /// Memory size in KiB (default: 65536 KiB = 64 MiB)
    pub memory_size_kib: u32,
    
    /// Number of iteration passes (default: 3)
    pub iterations: u32,
    
    /// Degree of parallelism (default: 4)
    pub parallelism: u32,
    
    /// Output length in bytes (default: 32)
    pub output_length: u32,
    
    /// Salt length in bytes (default: 16)
    pub salt_length: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_size_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 4,
            output_length: 32,
            salt_length: 16,
        }
    }
}

#[wasm_bindgen]
impl Argon2Config {
    /// Create a new Argon2Config with default values
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set memory size in KiB
    #[wasm_bindgen]
    pub fn with_memory_size(mut self, memory_kib: u32) -> Self {
        // Minimum 16 MiB for security
        if memory_kib < 16384 {
            self.memory_size_kib = 16384;
        } else {
            self.memory_size_kib = memory_kib;
        }
        self
    }
    
    /// Set iterations
    #[wasm_bindgen]
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        // Minimum 2 iterations
        if iterations < 2 {
            self.iterations = 2;
        } else {
            self.iterations = iterations;
        }
        self
    }
    
    /// Set parallelism
    #[wasm_bindgen]
    pub fn with_parallelism(mut self, parallelism: u32) -> Self {
        // Minimum 1, maximum 16
        if parallelism < 1 {
            self.parallelism = 1;
        } else if parallelism > 16 {
            self.parallelism = 16;
        } else {
            self.parallelism = parallelism;
        }
        self
    }
}

/// Derives a cryptographic key using Argon2id (recommended for high-security scenarios)
///
/// # Security
/// Uses Argon2id, the state-of-the-art key derivation function that won the 
/// Password Hashing Competition. Argon2id is highly resistant to both side-channel
/// attacks and dedicated cracking hardware, making it the best choice for
/// high-value key derivation.
///
/// # Parameters
/// * `password` - Password or passphrase
/// * `salt` - Optional salt (generates random salt if None)
/// * `config` - Optional Argon2 configuration (uses default if None)
///
/// # Returns
/// * A boxed slice containing the derived key followed by the salt
///
/// # Example
/// ```
/// use securetrack_crypto::{derive_key_argon2id, get_key_from_key_result};
/// 
/// let key_result = derive_key_argon2id("strong_password", None, None).unwrap();
/// let key = get_key_from_key_result(&key_result, None).unwrap();
/// ```
#[wasm_bindgen]
pub fn derive_key_argon2id(
    password: &str, 
    salt: Option<Box<[u8]>>, 
    config: Option<Argon2Config>
) -> Result<Box<[u8]>> {
    // Get or create configuration
    let config = config.unwrap_or_default();
    
    // Get or generate salt
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => {
            let mut salt = vec![0u8; config.salt_length as usize];
            OsRng.fill_bytes(&mut salt);
            salt
        }
    };
    
    // Validate salt length
    if salt_bytes.len() < 8 {
        log_crypto_error("derive_key_argon2id", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create Argon2id context
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            config.memory_size_kib,
            config.iterations,
            config.parallelism,
            Some(config.output_length as usize)
        ).map_err(|_| {
            log_crypto_error("derive_key_argon2id", &SecureTrackError::KeyDerivationError);
            SecureTrackError::KeyDerivationError
        })?
    );
    
    // Derive key
    let mut output = SecretBytes::new(&vec![0u8; config.output_length as usize]);
    argon2.hash_password_into(
        password.as_bytes(),
        &salt_bytes,
        &mut output
    ).map_err(|_| {
        log_crypto_error("derive_key_argon2id", &SecureTrackError::KeyDerivationError);
        SecureTrackError::KeyDerivationError
    })?;
    
    // Create result (key + salt)
    let mut result = Vec::with_capacity(output.len() + salt_bytes.len());
    result.extend_from_slice(&output);
    result.extend_from_slice(&salt_bytes);
    
    Ok(result.into_boxed_slice())
}

/// Enhanced key derivation with hardware binding factors
///
/// # Security
/// Uses Argon2id combined with device-specific hardware information to create
/// keys that are bound to both knowledge factors (password) and hardware
/// factors (biometrics and sensors).
///
/// # Parameters
/// * `password` - Password or passphrase
/// * `biometric_factor` - Hash of biometric data (e.g., fingerprint)
/// * `hardware_id` - Device hardware identifiers
/// * `config` - Optional Argon2 configuration
///
/// # Returns
/// * A boxed slice containing the derived key followed by the salt
#[wasm_bindgen]
pub fn derive_key_hardware_bound(
    password: &str,
    biometric_factor: &[u8],
    hardware_id: &str,
    config: Option<Argon2Config>
) -> Result<Box<[u8]>> {
    // Generate a salt if not provided in config
    let config = config.unwrap_or_default();
    let mut salt = vec![0u8; config.salt_length as usize];
    OsRng.fill_bytes(&mut salt);
    
    // First derive an intermediate key from the password
    let mut hmac_key = [0u8; 32];
    let _ = pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        &salt,
        10000, // Use a reasonable number of iterations for this step
        &mut hmac_key
    ).map_err(|_| {
        log_crypto_error("derive_key_hardware_bound", &SecureTrackError::KeyDerivationError);
        SecureTrackError::KeyDerivationError
    })?;
    
    // Use the intermediate key to create an HMAC of the biometric factor
    let mut mac = Hmac::<Sha256>::new_from_slice(&hmac_key)
        .map_err(|_| {
            log_crypto_error("derive_key_hardware_bound", &SecureTrackError::KeyDerivationError);
            SecureTrackError::KeyDerivationError
        })?;
    
    mac.update(biometric_factor);
    mac.update(hardware_id.as_bytes());
    
    // Get the HMAC result
    let combined_factor_hash = mac.finalize().into_bytes();
    
    // Use Argon2id for the final key derivation with the combined factors
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            config.memory_size_kib,
            config.iterations,
            config.parallelism,
            Some(config.output_length as usize)
        ).map_err(|_| {
            log_crypto_error("derive_key_hardware_bound", &SecureTrackError::KeyDerivationError);
            SecureTrackError::KeyDerivationError
        })?
    );
    
    // Derive the final key using the HMAC result as the password
    let mut output = SecretBytes::new(&vec![0u8; config.output_length as usize]);
    argon2.hash_password_into(
        &combined_factor_hash,
        &salt,
        &mut output
    ).map_err(|_| {
        log_crypto_error("derive_key_hardware_bound", &SecureTrackError::KeyDerivationError);
        SecureTrackError::KeyDerivationError
    })?;
    
    // Create result (key + salt)
    let mut result = Vec::with_capacity(output.len() + salt.len());
    result.extend_from_slice(&output);
    result.extend_from_slice(&salt);
    
    Ok(result.into_boxed_slice())
}

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
/// use securetrack_crypto::{derive_key, get_key_from_key_result, doctest_helpers};
/// 
/// let biometric_hash = doctest_helpers::create_test_biometric_hash();
/// let key_result = derive_key("user123", &biometric_hash, "sensor:pattern", None).unwrap();
/// let key = get_key_from_key_result(&key_result, None).unwrap();
/// let salt = get_salt_from_key_result(&key_result, None).unwrap();
/// ```
#[wasm_bindgen]
pub fn derive_key(
    uid: &str,
    biometric_hash: &[u8],
    sensor_pattern: &str,
    config: Option<SecurityConfig>,
) -> Result<Box<[u8]>> {
    // Use provided config or default
    let config = config.unwrap_or_default();
    
    // Validate inputs
    if biometric_hash.len() != 32 {
        log_crypto_error("derive_key", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Create or get salt
    let mut salt = vec![0u8; config.salt_length];
    OsRng.fill_bytes(&mut salt);
    
    derive_key_with_salt(uid, biometric_hash, sensor_pattern, &salt, Some(config))
}

/// Legacy key derivation function for backward compatibility
/// 
/// This function is maintained only for backward compatibility.
/// New code should use derive_key() instead.
#[wasm_bindgen]
pub fn derive_key_legacy(
    uid: &str,
    biometric_hash: &[u8],
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

/// Derives a key using a provided salt and security factors
///
/// # Security
/// Uses a structured approach to combine multiple security factors
/// (user ID, biometric data, sensor pattern) to generate a strong key.
/// The factors are combined using HMAC to prevent collisions.
///
/// # Parameters
/// * `uid` - User identifier string
/// * `biometric_hash` - 32-byte hash derived from biometric data
/// * `sensor_pattern` - Device-specific sensor pattern string
/// * `salt` - Salt for key derivation
/// * `config` - Optional security configuration (uses default if None)
///
/// # Returns
/// * A boxed slice containing the derived key followed by the salt
#[wasm_bindgen]
pub fn derive_key_with_salt(
    uid: &str,
    biometric_hash: &[u8],
    sensor_pattern: &str,
    salt: &[u8],
    config: Option<SecurityConfig>,
) -> Result<Box<[u8]>> {
    // Use provided config or default
    let config = config.unwrap_or_default();
    
    // Validate inputs
    if biometric_hash.len() != 32 {
        log_crypto_error("derive_key_with_salt", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    if salt.len() < 16 {
        log_crypto_error("derive_key_with_salt", &SecureTrackError::InvalidInputError);
        return Err(SecureTrackError::InvalidInputError);
    }
    
    // Combine factors securely using HMAC to prevent collisions
    // First create an HMAC key from the uid
    let mut initial_key = [0u8; 32];
    let _ = pbkdf2::<Hmac<Sha256>>(
        uid.as_bytes(),
        salt,
        1000, // Fewer iterations for this initial step
        &mut initial_key
    ).map_err(|_| {
        log_crypto_error("derive_key_with_salt", &SecureTrackError::KeyDerivationError);
        SecureTrackError::KeyDerivationError
    })?;
    
    // Use the initial key to create a secure combination of the biometric_hash and sensor_pattern
    let mut mac = Hmac::<Sha256>::new_from_slice(&initial_key)
        .map_err(|_| {
            log_crypto_error("derive_key_with_salt", &SecureTrackError::KeyDerivationError);
            SecureTrackError::KeyDerivationError
        })?;
    
    mac.update(biometric_hash);
    mac.update(sensor_pattern.as_bytes());
    
    let combined_hash = mac.finalize().into_bytes();
    
    // Derive the final key using PBKDF2 with the combined factors
    let mut key = SecretBytes::new(&vec![0u8; config.key_length]);
    let _ = pbkdf2::<Hmac<Sha256>>(
        &combined_hash,
        salt,
        config.pbkdf2_iterations,
        &mut key
    ).map_err(|_| {
        log_crypto_error("derive_key_with_salt", &SecureTrackError::KeyDerivationError);
        SecureTrackError::KeyDerivationError
    })?;
    
    // Combine key and salt for the result
    let mut result = Vec::with_capacity(key.len() + salt.len());
    result.extend_from_slice(&key);
    result.extend_from_slice(salt);
    
    Ok(result.into_boxed_slice())
}

/// Legacy function for backwards compatibility
/// 
/// This function is maintained only for backward compatibility.
/// New code should use derive_key_with_salt() instead.
#[wasm_bindgen]
pub fn derive_key_with_salt_legacy(
    uid: &str,
    biometric_hash: &[u8],
    sensor_pattern: &str,
    salt: &[u8],
) -> Result<Box<[u8]>> {
    derive_key_with_salt(uid, biometric_hash, sensor_pattern, salt, None)
} 