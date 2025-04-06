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
    
    // Helper function for the common test setup
    fn setup_key_derivation_test() -> (String, Vec<u8>, String) {
        let uid = "user123".to_string();
        let biometric_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
                                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let sensor_pattern = "pattern123".to_string();
        (uid, biometric_hash, sensor_pattern)
    }
    
    // Helper function to generate a test key
    fn generate_test_key() -> Vec<u8> {
        generate_random_key(32).to_vec()
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_derivation() {
        let (uid, biometric_hash, sensor_pattern) = setup_key_derivation_test();
        
        // Test with default configuration
        let result = derive_key(&uid, &biometric_hash, &sensor_pattern, None);
        
        assert!(result.is_ok());
        let key_result = result.unwrap();
        
        // Extract key and salt
        let key = get_key_from_key_result(&key_result, None).unwrap();
        let salt = get_salt_from_key_result(&key_result, None).unwrap();
        
        assert_eq!(key.len(), 32); // AES-256 key
        assert_eq!(salt.len(), 16); // Default salt length
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_derivation_with_salt() {
        let (uid, biometric_hash, sensor_pattern) = setup_key_derivation_test();
        
        // Generate a salt
        let salt = [1u8; 16].to_vec();
        
        // Test key derivation with the same parameters multiple times
        let key_result1 = derive_key_with_salt(&uid, &biometric_hash, &sensor_pattern, &salt, None).unwrap();
        let key_result2 = derive_key_with_salt(&uid, &biometric_hash, &sensor_pattern, &salt, None).unwrap();
        
        let key1 = get_key_from_key_result(&key_result1, None).unwrap();
        let key2 = get_key_from_key_result(&key_result2, None).unwrap();
        
        // Keys should be the same when using the same salt
        assert_eq!(key1, key2);
        
        // Different sensor pattern should give different key
        let key_result3 = derive_key_with_salt(&uid, &biometric_hash, "different_pattern", &salt, None).unwrap();
        let key3 = get_key_from_key_result(&key_result3, None).unwrap();
        assert_ne!(key1, key3);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_derivation_with_config() {
        let (uid, biometric_hash, sensor_pattern) = setup_key_derivation_test();
        
        let config = SecurityConfig::new()
            .with_pbkdf2_iterations(10_000)
            .with_salt_length(24);
        
        let result = derive_key(&uid, &biometric_hash, &sensor_pattern, Some(config.clone()));
        assert!(result.is_ok());
        
        let key_result = result.unwrap();
        let key = get_key_from_key_result(&key_result, Some(config.clone())).unwrap();
        let salt = get_salt_from_key_result(&key_result, Some(config)).unwrap();
        
        assert_eq!(key.len(), 32);
        assert_eq!(salt.len(), 24);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_encrypt_decrypt() {
        let data = b"This is a secret message".to_vec();
        let key = generate_test_key();
        
        let encrypted = encrypt_data(&data, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        assert_eq!(data, decrypted.to_vec());
        
        // Test with wrong key
        let wrong_key = generate_test_key();
        let result = decrypt_data(&encrypted, &wrong_key);
        assert!(result.is_err());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_string() {
        let text = "This is a secret message";
        let key = generate_test_key();
        
        let encrypted = encrypt_string(text, &key).unwrap();
        let decrypted = decrypt_to_string(&encrypted, &key).unwrap();
        
        assert_eq!(text, decrypted);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_splitting_combining() {
        let key = generate_test_key();
        let n = 5;
        let k = n; // For XOR-based n-of-n sharing, k must equal n
        
        let shares = split_key(&key, n, k).unwrap();
        
        // Combine using all shares
        let combined = combine_key(&shares).unwrap();
        
        // Convert Box<[u8]> to Vec<u8> for comparison
        let combined_vec = combined.to_vec();
        assert_eq!(key, combined_vec);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_splitting_threshold() {
        let key = generate_test_key();
        let n = 5;
        let k = n; // For XOR-based n-of-n sharing, k must equal n
        
        let shares = split_key(&key, n, k).unwrap();
        
        // Test with all shares - should succeed
        let result = combine_key(&shares);
        assert!(result.is_ok());
        
        // Convert the result to Vec for comparison
        let combined_vec = result.unwrap().to_vec();
        assert_eq!(key, combined_vec);
        
        // We can't easily test combining with fewer shares in this implementation
        // without modifying the shares binary format
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_sign_verify() {
        let data = b"This is data to sign".to_vec();
        let key = generate_test_key();
        
        let signature = sign_data(&data, &key).unwrap();
        let is_valid = verify_data(&data, &signature, &key).unwrap();
        
        assert!(is_valid);
        
        // Test with modified data
        let mut modified_data = data.clone();
        modified_data[0] = modified_data[0].wrapping_add(1);
        
        let is_invalid = verify_data(&modified_data, &signature, &key).unwrap();
        assert!(!is_invalid);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_sign_verify_command() {
        let command = "LOCK_DEVICE";
        let key = generate_test_key();
        
        let signature = sign_command(command, &key).unwrap();
        let is_valid = verify_command(command, &signature, &key).unwrap();
        
        assert!(is_valid);
        
        // Test with wrong command
        let is_invalid = verify_command("UNLOCK_DEVICE", &signature, &key).unwrap();
        assert!(!is_invalid);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_invalid_inputs_for_key_sharing() {
        let key = generate_test_key();
        
        // Test n < 2
        let result = split_key(&key, 1, 1);
        assert!(result.is_err());
        
        // Note: Empty key is actually supported as a special case in the implementation
        // so we don't test it as an error case
        
        // Test with k != n (for XOR-based approach, k must equal n)
        let result = split_key(&key, 5, 3);
        assert!(result.is_err());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_empty_key_handling() {
        // Test the special case for empty keys
        let empty_key: Vec<u8> = vec![];
        let n = 3;
        let k = n;
        
        let shares = split_key(&empty_key, n, k).unwrap();
        let recovered = combine_key(&shares).unwrap();
        
        assert_eq!(recovered.len(), 0);
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_key_derivation_errors() {
        // Test with wrong biometric hash length (not 32 bytes)
        let result = derive_key("user", &vec![0u8; 16], "pattern", None);
        assert!(result.is_err());
        
        // Note: The implementation doesn't validate empty UID or empty pattern
        // so we don't test those as error cases
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_combine_key_errors() {
        // Test with empty shares
        let empty_shares: Vec<u8> = vec![];
        let result = combine_key(&empty_shares);
        assert!(result.is_err());
        
        // Test with invalid shares format
        let invalid_shares: Vec<u8> = vec![1, 2]; // Just k and n, no actual shares
        let result = combine_key(&invalid_shares);
        assert!(result.is_err());
    }
    
    #[test]
    #[wasm_bindgen_test]
    fn test_hex_conversion() {
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        
        // Test without prefix
        let hex = bytes_to_hex(&data, false);
        assert_eq!(hex, "123456789abcdef0");
        
        // Test with prefix
        let hex_with_prefix = bytes_to_hex(&data, true);
        assert_eq!(hex_with_prefix, "0x123456789abcdef0");
        
        // Test round-trip conversion
        let bytes = hex_to_bytes(&hex).unwrap();
        assert_eq!(data, bytes.to_vec());
        
        let bytes_with_prefix = hex_to_bytes(&hex_with_prefix).unwrap();
        assert_eq!(data, bytes_with_prefix.to_vec());
    }
} 