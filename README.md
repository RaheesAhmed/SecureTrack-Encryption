# SecureTrack Crypto Library

A secure, WASM-ready cryptographic library for the SecureTrack anti-theft app. This library provides military-grade encryption, key derivation, and secure key sharing functions.

## Features

- WASM-compatible crypto primitives with wasm-bindgen exports
- AES-256-GCM authenticated encryption
- PBKDF2 with HMAC-SHA256 key derivation
- HMAC-SHA256 signing and verification
- Shamir's Secret Sharing for secure key backup
- Constant-time comparisons and secure memory wiping
- Comprehensive error handling and logging

## Usage Examples

### Using in Rust Projects

```rust
use securetrack_crypto::{
    derive_key, get_key_from_key_result,
    encrypt_data, decrypt_data,
    sign_command, verify_command,
    split_key, combine_key
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a biometric hash (normally from your app's biometric module)
    let biometric_hash = [0u8; 32];

    // Step 1: Derive an encryption key from user data
    let key_result = derive_key(
        "user123",             // User identifier
        biometric_hash.to_vec(), // Biometric hash
        "device:sensor:pattern", // Device-specific pattern
        None,                  // Use default security config
    )?;

    // Extract the key from the result
    let key = get_key_from_key_result(&key_result, None)?;

    // Step 2: Encrypt sensitive data
    let data = "My secure data that needs protection".as_bytes();
    let encrypted = encrypt_data(data, &key)?;

    // Step 3: Decrypt the data when needed
    let decrypted = decrypt_data(&encrypted, &key)?;
    assert_eq!(data, decrypted.as_ref());

    // Step 4: Sign and verify commands
    let command = "LOCK_DEVICE";
    let signature = sign_command(command, &key)?;
    let is_valid = verify_command(command, &signature, &key)?;
    assert!(is_valid);

    // Step 5: Split the key for secure backup (5 shares, need 3 to reconstruct)
    let shares = split_key(&key, 5, 3)?;

    // Later, reconstruct the key from the shares
    let recovered_key = combine_key(&shares)?;
    assert_eq!(key.as_ref(), recovered_key.as_ref());

    Ok(())
}
```

### Using from JavaScript/TypeScript via WASM

First, build and import the WASM module:

```typescript
import * as crypto from "securetrack_crypto";

async function secureDemo() {
  // Generate a 32-byte biometric hash
  const biometricHash = new Uint8Array(32);
  crypto.getRandomValues(biometricHash);

  // Derive an encryption key
  const keyResult = crypto.derive_key(
    "user123", // User ID
    biometricHash, // Biometric hash
    "device:sensor:pattern", // Device pattern
    null // Use default config
  );

  // Get the key
  const key = crypto.get_key_from_key_result(keyResult);

  // Encrypt a string
  const data = "Sensitive data to protect";
  const encrypted = crypto.encrypt_string(data, key);

  // Decrypt back to a string
  const decrypted = crypto.decrypt_to_string(encrypted, key);
  console.log("Decrypted:", decrypted); // Should match original data

  // Sign and verify a command
  const command = "LOCK_DEVICE";
  const signature = crypto.sign_command(command, key);
  const isValid = crypto.verify_command(command, signature, key);
  console.log("Signature valid:", isValid);

  // Split the key for secure backup (5 shares, need 3)
  const shares = crypto.split_key(key, 5, 3);

  // Later reconstruct the key from shares
  const recoveredKey = crypto.combine_key(shares);

  // Clean up sensitive data when done
  crypto.secure_zero(key);
}

secureDemo().catch(console.error);
```

## Building for WASM

To build the library for WebAssembly:

1. Install the required toolchain:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

2. Build the WASM package:

```bash
# From the project root
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir ./pkg ./target/wasm32-unknown-unknown/release/securetrack_crypto.wasm
```

3. Use the generated files in `./pkg` directory in your web project.

## Integration with SecureTrack

This library is designed to work with SecureTrack's Kotlin/Android application via the WasmEdge runtime. It provides all the cryptographic primitives needed for secure key management, data encryption, and anti-theft features.

### Kotlin-WASM Integration

```kotlin
// Example of using the WASM module from Kotlin
val wasmRuntime = WasmEdgeRuntime()
wasmRuntime.loadModule("securetrack_crypto.wasm")

// Derive a key
val biometricHash = getDeviceBiometricHash() // Your biometric function
val keyResult = wasmRuntime.callFunction(
    "derive_key",
    arrayOf(userId, biometricHash, devicePattern)
) as ByteArray

// Use the key for encryption
val key = wasmRuntime.callFunction(
    "get_key_from_key_result",
    arrayOf(keyResult)
) as ByteArray

val encryptedData = wasmRuntime.callFunction(
    "encrypt_data",
    arrayOf(sensitiveData, key)
) as ByteArray
```

## Security Considerations

- The library uses AES-256-GCM for authenticated encryption, which provides both confidentiality and integrity.
- PBKDF2 with HMAC-SHA256 uses 100,000 iterations by default for key derivation.
- The Shamir's Secret Sharing implementation uses the 'sharks' crate for secure key splitting and combining.
- All cryptographic operations use constant-time operations where possible to avoid timing attacks.
- Sensitive data in memory is securely zeroed after use.

## License

MIT License - See LICENSE file for details.
