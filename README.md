# SecureTrack Crypto Library

A secure, cross-platform cryptographic library for the SecureTrack anti-theft app. This library provides military-grade encryption, key derivation, and secure key sharing functions with support for WebAssembly, Android, and other platforms.

![Version](https://img.shields.io/badge/version-1.2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Core Features

- **Strong Encryption** - AES-256-GCM authenticated encryption and AES-256-SIV for misuse resistance
- **Advanced Key Derivation** - Argon2id and PBKDF2 with hardware binding and biometric integration
- **Cross-Platform Support** - Native binaries and WebAssembly (WASM) for browser compatibility
- **Military-Grade Security** - Constant-time operations, secure memory management, and more
- **Complete Integration Support** - Guides for Web, Android/Kotlin, and other platforms

## Platform Support

| Platform | Support | Distribution Format                   |
| -------- | ------- | ------------------------------------- |
| Web      | ✅      | WebAssembly + JavaScript              |
| Android  | ✅      | WASM via WasmEdge or Native Libraries |
| iOS      | ✅      | WASM or Native Libraries              |
| Windows  | ✅      | Native DLL                            |
| macOS    | ✅      | Native dylib                          |
| Linux    | ✅      | Native shared object                  |

## Installation

### Web Applications

```bash
# Via NPM
npm install securetrack-crypto
# or yarn
yarn add securetrack-crypto
```

For manual installation, copy the WASM files from the `dist/wasm` directory to your web project.

### Android Applications

Follow the [Kotlin/Android Integration Guide](KOTLIN_INTEGRATION.md) for detailed instructions on integrating with Android applications.

### Native Applications

Include the appropriate binary for your platform from the `dist` directory.

## Usage Examples

### Key Derivation

```rust
// In Rust
use securetrack_crypto::{
    derive_key_argon2id,
    get_key_from_key_result,
};

// Derive a key with Argon2id (stronger algorithm)
let key_result = derive_key_argon2id(
    "strong_password",    // Password or passphrase
    None,                 // Use random salt
    None                  // Use default configuration
)?;
let key = get_key_from_key_result(&key_result, None)?;
```

```javascript
// In JavaScript (Web)
import * as crypto from "securetrack-crypto";

// Initialize the module
await crypto.default();

// Derive a key with Argon2id
const keyResult = crypto.derive_key_argon2id(
  "secure_passphrase", // Password
  null, // Use random salt
  null // Use default config
);

// Get the actual key from the result
const key = crypto.get_key_from_key_result(keyResult);
```

```kotlin
// In Kotlin (Android)
val cryptoManager = CryptoManager(wasmRuntime)

// Derive a key with Argon2id
val keyResult = cryptoManager.deriveKeyArgon2id(
    "secure_password",
    null,  // Use random salt
    null   // Use default config
)

// Get the actual key
val key = cryptoManager.getKeyFromKeyResult(keyResult)
```

### Encryption and Decryption

```rust
// In Rust
use securetrack_crypto::{encrypt_data, decrypt_data};

// Encrypt sensitive data
let data = "My secure data that needs protection".as_bytes();
let encrypted = encrypt_data(data, &key)?;

// Decrypt the data when needed
let decrypted = decrypt_data(&encrypted, &key)?;
assert_eq!(data, decrypted.as_ref());
```

```javascript
// In JavaScript
// Encrypt data
const dataBytes = new TextEncoder().encode("Secret information");
const encrypted = crypto.encrypt_data(dataBytes, key);

// Decrypt data
const decrypted = crypto.decrypt_data(encrypted, key);
const plaintext = new TextDecoder().decode(decrypted);
```

```kotlin
// In Kotlin
// Encrypt data
val dataBytes = "Secret information".encodeToByteArray()
val encrypted = cryptoManager.encryptData(dataBytes, key)

// Decrypt data
val decrypted = cryptoManager.decryptData(encrypted, key)
val plaintext = decrypted.decodeToString()
```

### Hardware-Bound Key Derivation

```rust
// In Rust - Derive key with hardware binding
let hw_key_result = derive_key_hardware_bound(
    "password",            // Password
    &biometric_hash,       // Biometric factor
    "hardware:id:123",     // Device hardware identifiers
    None                   // Use default configuration
)?;
let hw_key = get_key_from_key_result(&hw_key_result, None)?;
```

```kotlin
// In Kotlin - Hardware binding with biometrics
val key = cryptoManager.deriveHardwareBoundKey(
    password,
    biometricHash,
    hardwareId
)
```

### Password Strength Measurement

```javascript
// In JavaScript
const password = "p@ssw0rd123";
const entropy = crypto.measure_entropy(new TextEncoder().encode(password));
console.log(`Password strength: ${entropy.toFixed(2)} bits`);

// Classify password strength
function checkPasswordStrength(password) {
  const passwordBytes = new TextEncoder().encode(password);
  const entropy = crypto.measure_entropy(passwordBytes);

  if (entropy < 40) {
    return "Weak";
  } else if (entropy < 60) {
    return "Moderate";
  } else if (entropy < 80) {
    return "Strong";
  } else {
    return "Very Strong";
  }
}
```

## Security Considerations

- The library uses AES-256-GCM for authenticated encryption, providing both confidentiality and integrity
- AES-256-SIV provides misuse-resistant encryption that maintains confidentiality even with nonce reuse
- Argon2id provides superior protection against brute-force attacks compared to PBKDF2
- Memory-protected containers automatically wipe sensitive data when no longer needed
- All cryptographic operations use constant-time algorithms where possible to avoid timing attacks
- Hardware-binding enables multi-factor security by combining passwords with hardware identifiers and biometrics

## Documentation

- [Main Documentation](docs.md)
- [Web Integration Guide](WEB_INTEGRATION.md)
- [Android/Kotlin Integration Guide](KOTLIN_INTEGRATION.md)
- [Security Audit Checklist](SECURITY_AUDIT.md)
- [Release Checklist](RELEASE_CHECKLIST.md)
- [Changelog](CHANGELOG.md)

## Building From Source

### Prerequisites

- Rust 1.53.0 or later
- Cargo and rustup
- For WASM: wasm-bindgen-cli

### Building

```bash
# Build native library
cargo build --release

# Build for WebAssembly
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir ./pkg ./target/wasm32-unknown-unknown/release/securetrack_crypto.wasm

# Build for all platforms (Unix/macOS)
./scripts/build-all.sh
```

## Benchmarking

The library includes benchmarks for key cryptographic operations:

```bash
# Run benchmarks
cargo bench
```

## Contributing

We welcome contributions to improve the SecureTrack Crypto Library! Please review our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
