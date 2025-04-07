# SecureTrack Crypto Library

A secure, WASM-ready cryptographic library for the SecureTrack anti-theft app. This library provides military-grade encryption, key derivation, and secure key sharing functions.

## Features

- WASM-compatible crypto primitives with wasm-bindgen exports
- AES-256-GCM authenticated encryption
- AES-256-SIV for misuse-resistant encryption
- Argon2id and PBKDF2 key derivation functions
- Hardware-bound key generation for multi-factor security
- Memory-protected secure containers with automatic wiping
- HMAC-SHA256 signing and verification
- XOR-based secret sharing for secure key backup
- Constant-time comparisons and secure memory wiping
- Comprehensive error handling with detailed diagnostics
- Entropy measurement for password strength assessment

## Usage Examples

### Using in Rust Projects

```rust
use securetrack_crypto::{
    derive_key, derive_key_argon2id, derive_key_hardware_bound,
    get_key_from_key_result, generate_random_key,
    encrypt_data, decrypt_data,
    sign_command, verify_command,
    split_key, combine_key,
    SecretBytes, measure_entropy
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a biometric hash (normally from your app's biometric module)
    let biometric_hash = [0u8; 32];

    // Step 1: Derive an encryption key (multiple options available)

    // Option 1: PBKDF2-based key derivation
    let key_result = derive_key(
        "user123",             // User identifier
        biometric_hash.to_vec(), // Biometric hash
        "device:sensor:pattern", // Device-specific pattern
        None,                  // Use default security config
    )?;
    let key = get_key_from_key_result(&key_result, None)?;

    // Option 2: Argon2id (stronger, more modern algorithm)
    let argon_key_result = derive_key_argon2id(
        "strong_password",    // Password or passphrase
        None,                 // Use random salt
        None                  // Use default configuration
    )?;
    let argon_key = get_key_from_key_result(&argon_key_result, None)?;

    // Option 3: Hardware-bound key derivation
    let hw_key_result = derive_key_hardware_bound(
        "password",            // Password
        &biometric_hash,       // Biometric factor
        "hardware:id:123",     // Device hardware identifiers
        None                   // Use default configuration
    )?;
    let hw_key = get_key_from_key_result(&hw_key_result, None)?;

    // Step 2: Encrypt sensitive data
    let data = "My secure data that needs protection".as_bytes();
    let encrypted = encrypt_data(data, &key)?;

    // Step 3: Decrypt the data when needed
    let decrypted = decrypt_data(&encrypted, &key)?;
    assert_eq!(data, decrypted.as_ref());

    // Step 4: Use secure memory containers
    let secure_key = SecretBytes::new(&key);
    // Key is automatically wiped when secure_key goes out of scope

    // Step 5: Measure password entropy
    let password = "p@ssw0rd123";
    let entropy = measure_entropy(password.as_bytes());
    println!("Password entropy: {} bits", entropy);

    // Step 6: Sign and verify commands
    let command = "LOCK_DEVICE";
    let signature = sign_command(command, &key)?;
    let is_valid = verify_command(command, &signature, &key)?;
    assert!(is_valid);

    // Step 7: Split the key for secure backup (needs all shares to reconstruct)
    let shares = split_key(&key, 3, 3)?;

    // Later, reconstruct the key from the shares
    let recovered_key = combine_key(&shares)?;
    assert_eq!(key.as_ref(), recovered_key.as_ref());

    // Step 8: Securely wipe sensitive data when done
    let mut sensitive_data = key.to_vec();
    secure_zero(&mut sensitive_data);

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

  // Option 1: Derive an encryption key with PBKDF2
  const keyResult = crypto.derive_key(
    "user123", // User ID
    biometricHash, // Biometric hash
    "device:sensor:pattern", // Device pattern
    null // Use default config
  );

  // Option 2: Use Argon2id for stronger key derivation
  const argonKeyResult = crypto.derive_key_argon2id(
    "secure_passphrase", // Password
    null, // Use random salt
    null // Use default config
  );

  // Option 3: Hardware-bound key derivation
  const hwKeyResult = crypto.derive_key_hardware_bound(
    "password",
    biometricHash,
    "hwid:12345abc",
    null
  );

  // Get the key
  const key = crypto.get_key_from_key_result(keyResult);

  // Encrypt a string
  const data = "Sensitive data to protect";
  const encrypted = crypto.encrypt_string(data, key);

  // Decrypt back to a string
  const decrypted = crypto.decrypt_to_string(encrypted, key);
  console.log("Decrypted:", decrypted); // Should match original data

  // Measure password entropy
  const passwordStrength = crypto.measure_entropy(
    new TextEncoder().encode("MyPassw0rd!")
  );
  console.log(`Password strength: ${passwordStrength.toFixed(2)} bits`);

  // Sign and verify a command
  const command = "LOCK_DEVICE";
  const signature = crypto.sign_command(command, key);
  const isValid = crypto.verify_command(command, signature, key);
  console.log("Signature valid:", isValid);

  // Split the key for secure backup (5 shares, need all 5)
  const shares = crypto.split_key(key, 5, 5);

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

// Derive a key with Argon2id (stronger algorithm)
val password = getUserPassword()
val keyResult = wasmRuntime.callFunction(
    "derive_key_argon2id",
    arrayOf(password, null, null)
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

// Clean up when done
wasmRuntime.callFunction(
    "secure_zero",
    arrayOf(key)
)
```

## Security Considerations

- The library uses AES-256-GCM for authenticated encryption, which provides both confidentiality and integrity.
- AES-256-SIV provides misuse-resistant encryption that maintains confidentiality even with nonce reuse.
- Argon2id (winner of the Password Hashing Competition) provides superior protection against brute-force attacks compared to PBKDF2.
- PBKDF2 with HMAC-SHA256 uses 100,000 iterations by default for legacy key derivation.
- The XOR-based secret sharing implementation enables secure key backup and recovery when all shares are available.
- Memory-protected containers (`SecretBytes`) automatically wipe sensitive data when no longer needed.
- All cryptographic operations use constant-time algorithms where possible to avoid timing attacks.
- Detailed error handling with unique error codes aids in security diagnostics without leaking sensitive information.
- Hardware-binding enables multi-factor security combining knowledge factors (passwords) with hardware identifiers and biometrics.

## License

MIT License - See LICENSE file for details.
