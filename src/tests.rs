#[cfg(test)]
mod tests {
    use crate::config::SecurityConfig;
    use crate::encryption::{encrypt_data, decrypt_data, encrypt_string, decrypt_to_string};
    use crate::key_derivation::{
        derive_key, derive_key_with_salt, get_key_from_key_result, get_salt_from_key_result
    };
    use crate::key_sharing::{split_key, combine_key};
    use crate::signing::{sign_command, verify_command, sign_data, verify_data};
    use crate::utils::{
        generate_random_key, constant_time_eq, secure_zero, hex_to_bytes, bytes_to_hex
    };
    use wasm_bindgen_test::*;
    
    wasm_bindgen_test_configure!(run_in_browser);
    
    // Helper function to generate test data
    fn generate_test_key() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        for i in 0..key.len() {
            key[i] = i as u8;
        }
        key
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_derivation() {
        let uid = "test_user";
        let biometric_hash = [0u8; 32].to_vec();
        let sensor_pattern = "test_sensor_pattern";
        
        // Test with default config
        let result = derive_key(uid, biometric_hash.clone(), sensor_pattern, None);
        assert!(result.is_ok());
        
        let key_result = result.unwrap();
        let key = get_key_from_key_result(&key_result, None).unwrap();
        let salt = get_salt_from_key_result(&key_result, None).unwrap();
        
        assert_eq!(key.len(), 32);
        assert_eq!(salt.len(), 16);
        
        // Test with custom config
        let config = SecurityConfig {
            pbkdf2_iterations: 10_000,
            salt_length: 24,
            key_length: 32,
        };
        
        let result = derive_key(uid, biometric_hash.clone(), sensor_pattern, Some(config.clone()));
        assert!(result.is_ok());
        
        let key_result = result.unwrap();
        let key = get_key_from_key_result(&key_result, Some(config.clone())).unwrap();
        let salt = get_salt_from_key_result(&key_result, Some(config)).unwrap();
        
        assert_eq!(key.len(), 32);
        assert_eq!(salt.len(), 24);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_derive_key_with_salt() {
        let uid = "test_user";
        let biometric_hash = [0u8; 32].to_vec();
        let sensor_pattern = "test_sensor_pattern";
        let salt = [1u8; 16];
        
        // Test with default config
        let key1 = derive_key_with_salt(uid, biometric_hash.clone(), sensor_pattern, &salt, None).unwrap();
        let key2 = derive_key_with_salt(uid, biometric_hash.clone(), sensor_pattern, &salt, None).unwrap();
        
        // Same inputs should produce same key
        assert_eq!(&key1[..], &key2[..]);
        
        // Test with different patterns
        let key3 = derive_key_with_salt(uid, biometric_hash.clone(), "different_pattern", &salt, None).unwrap();
        assert_ne!(&key1[..], &key3[..]);
        
        // Test with custom config
        let config = SecurityConfig {
            pbkdf2_iterations: 10_000,
            salt_length: 16,
            key_length: 64, // Longer key
        };
        
        let key4 = derive_key_with_salt(uid, biometric_hash, sensor_pattern, &salt, Some(config)).unwrap();
        assert_eq!(key4.len(), 64);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_encryption_decryption() {
        let test_data = b"This is a test message for encryption and decryption";
        let key = generate_random_key(32);
        
        // Encrypt the data
        let encrypted = encrypt_data(test_data, &key).unwrap();
        
        // Verify encrypted data is longer than original (nonce + data + tag)
        assert!(encrypted.len() > test_data.len());
        
        // Decrypt the data
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        // Verify decrypted data matches original
        assert_eq!(decrypted.as_ref(), test_data);
        
        // Test string version
        let test_string = "This is a test string for encryption and decryption";
        let encrypted_string = encrypt_string(test_string, &key).unwrap();
        let decrypted_string = decrypt_to_string(&encrypted_string, &key).unwrap();
        
        assert_eq!(decrypted_string, test_string);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_encryption_with_invalid_inputs() {
        let test_data = b"This is a test message";
        
        // Test with invalid key length
        let invalid_key = [0u8; 16]; // Wrong key size (should be 32)
        let result = encrypt_data(test_data, &invalid_key);
        assert!(result.is_err());
        
        // Test decryption with valid key but invalid data
        let valid_key = [0u8; 32];
        let invalid_data = [0u8; 10]; // Too short for nonce + tag
        let result = decrypt_data(&invalid_data, &valid_key);
        assert!(result.is_err());
        
        // Test decryption with wrong key
        let key1 = generate_random_key(32);
        let key2 = generate_random_key(32);
        let encrypted = encrypt_data(test_data, &key1).unwrap();
        
        // Decryption with wrong key should fail with authentication error
        let result = decrypt_data(&encrypted, &key2);
        assert!(result.is_err());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_sign_verify_command() {
        let command = "LOCK_DEVICE";
        let key = generate_random_key(32);
        
        // Sign the command
        let signature = sign_command(command, &key).unwrap();
        
        // Signature should be HMAC-SHA256 size (32 bytes)
        assert_eq!(signature.len(), 32);
        
        // Verify the signature
        let is_valid = verify_command(command, &signature, &key).unwrap();
        assert!(is_valid);
        
        // Verify with wrong command
        let is_invalid = verify_command("UNLOCK_DEVICE", &signature, &key).unwrap();
        assert!(!is_invalid);
        
        // Test general data signing
        let data = b"Some binary data to sign";
        let data_signature = sign_data(data, &key).unwrap();
        
        let data_valid = verify_data(data, &data_signature, &key).unwrap();
        assert!(data_valid);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_splitting_combining() {
        let original_key = generate_test_key();
        let n = 5;
        let k = 3;
        
        // Split the key
        let split_result = split_key(&original_key, n, k).unwrap();
        
        // Combine the key
        let recovered_key = combine_key(&split_result).unwrap();
        
        // Verify recovered key matches original
        assert_eq!(recovered_key.len(), original_key.len());
        assert_eq!(recovered_key.as_ref(), original_key.as_slice());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_splitting_threshold() {
        // Verify that k shares are needed, not more
        let original_key = generate_test_key();
        let n = 5;
        let k = 3;
        
        // Split the key
        let split_result = split_key(&original_key, n, k).unwrap();
        
        // Modify the result to pretend we only have 2 shares (by changing k value)
        // This should fail because we need at least k=3 shares
        let mut modified_result = split_result.to_vec();
        modified_result[0] = 4; // k value
        
        let result = combine_key(&modified_result);
        assert!(result.is_err());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_invalid_inputs() {
        // Test invalid key length for encryption
        let result = encrypt_data(b"test", &[0u8; 16]);
        assert!(result.is_err());
        
        // Test invalid key length for decryption
        let result = decrypt_data(&[0u8; 32], &[0u8; 16]);
        assert!(result.is_err());
        
        // Test invalid biometric hash length
        let result = derive_key("user", vec![0u8; 16], "pattern", None);
        assert!(result.is_err());
        
        // Test invalid k, n values for key splitting
        let result = split_key(&[0u8; 32], 5, 6);
        assert!(result.is_err());
        
        // Test invalid share data for key combining
        let result = combine_key(&[1, 2]);
        assert!(result.is_err());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_random_key_generation() {
        let key1 = generate_random_key(32);
        let key2 = generate_random_key(32);
        
        // Keys should be the correct length
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        
        // Two generated keys should be different
        assert_ne!(&key1[..], &key2[..]);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        let d = [1, 2, 3];
        
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_secure_zero() {
        let mut data = [1, 2, 3, 4, 5];
        secure_zero(&mut data);
        
        for &byte in &data {
            assert_eq!(byte, 0);
        }
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_hex_conversion() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        
        // Test bytes to hex conversion
        let hex = bytes_to_hex(&bytes, false);
        assert_eq!(hex, "0123456789abcdef");
        
        // Test with prefix
        let hex_with_prefix = bytes_to_hex(&bytes, true);
        assert_eq!(hex_with_prefix, "0x0123456789abcdef");
        
        // Test hex to bytes conversion
        let converted = hex_to_bytes(&hex).expect("Valid hex should convert correctly");
        assert_eq!(&converted[..], &bytes[..]);
        
        // Test hex to bytes with 0x prefix
        let converted_with_prefix = hex_to_bytes(&hex_with_prefix).expect("Valid hex with prefix should convert correctly");
        assert_eq!(&converted_with_prefix[..], &bytes[..]);
        
        // Test invalid inputs
        let invalid_result = hex_to_bytes("invalid");
        assert!(invalid_result.is_err());
        
        let invalid_char_result = hex_to_bytes("0123456g");
        assert!(invalid_char_result.is_err());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_empty_inputs() {
        // Test encryption with empty data
        let key = generate_random_key(32);
        let encrypted = encrypt_data(&[], &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        assert_eq!(decrypted.len(), 0);
        
        // Test key splitting with empty key
        let empty_key: Vec<u8> = vec![];
        let split_result = split_key(&empty_key, 3, 2).unwrap();
        let recovered = combine_key(&split_result).unwrap();
        assert_eq!(recovered.len(), 0);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_large_data() {
        // Test with large data (1KB)
        let key = generate_random_key(32);
        let large_data = vec![0xAA; 1024];
        
        let encrypted = encrypt_data(&large_data, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        assert_eq!(decrypted.len(), large_data.len());
        assert_eq!(&decrypted[..], &large_data[..]);
    }
} 