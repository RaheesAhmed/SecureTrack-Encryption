# SecureTrack Crypto Library - Kotlin/Android Integration Guide

This guide provides step-by-step instructions for integrating the SecureTrack crypto library into Android applications using Kotlin.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setup](#setup)
3. [Integration Methods](#integration-methods)
4. [Basic Usage Examples](#basic-usage-examples)
5. [Advanced Features](#advanced-features)
6. [Security Best Practices](#security-best-practices)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

- Android Studio Arctic Fox (2021.3.1) or later
- Kotlin 1.6.0+
- Minimum Android API level 21
- JDK 11
- Gradle 7.0+

## Setup

### Method 1: Using WasmEdge (Recommended)

WasmEdge provides superior performance for running WebAssembly modules on Android.

1. **Add the WasmEdge dependencies to your build.gradle**

```gradle
dependencies {
    implementation 'org.wasmedge:wasmedge-java:0.13.0'
    implementation 'org.wasmedge:wasmedge-jni:0.13.0'
}
```

2. **Copy the SecureTrack crypto WASM module**

Copy the `securetrack_crypto.wasm` file to your app's `src/main/assets/wasm/` directory.

3. **Initialize WasmEdge in your application**

```kotlin
class SecureTrackApplication : Application() {
    lateinit var wasmRuntime: WasmEdgeRuntime

    override fun onCreate() {
        super.onCreate()
        // Initialize WasmEdge
        WasmEdgeLoader.initializeRuntime(this)
        wasmRuntime = WasmEdgeRuntime()
        wasmRuntime.loadModule(
            assets.open("wasm/securetrack_crypto.wasm").readBytes()
        )
    }
}
```

### Method 2: Using Kotlin Native (Advanced)

For advanced use cases requiring deeper integration:

1. Set up Rust build environment with Android targets
2. Configure Cargo to build native libraries for Android ABIs
3. Use JNI to bridge between Kotlin and native code

## Integration Methods

### WasmEdge Integration (Recommended)

#### Create a CryptoManager class to wrap the WASM operations

```kotlin
class CryptoManager(private val wasmRuntime: WasmEdgeRuntime) {

    /**
     * Derives a key using Argon2id (recommended)
     */
    fun deriveKeyArgon2id(
        password: String,
        salt: ByteArray? = null,
        configOverrides: Map<String, Any>? = null
    ): ByteArray {
        val params = mutableMapOf<String, Any>()
        params["password"] = password
        salt?.let { params["salt"] = it }
        configOverrides?.let { params["config"] = it }

        return wasmRuntime.callFunction(
            "derive_key_argon2id",
            params
        ) as ByteArray
    }

    /**
     * Extracts the key from a key derivation result
     */
    fun getKeyFromKeyResult(keyResult: ByteArray): ByteArray {
        return wasmRuntime.callFunction(
            "get_key_from_key_result",
            mapOf("key_result" to keyResult)
        ) as ByteArray
    }

    /**
     * Encrypts data using AES-256-GCM
     */
    fun encryptData(data: ByteArray, key: ByteArray): ByteArray {
        return wasmRuntime.callFunction(
            "encrypt_data",
            mapOf("data" to data, "key" to key)
        ) as ByteArray
    }

    /**
     * Decrypts data using AES-256-GCM
     */
    fun decryptData(ciphertext: ByteArray, key: ByteArray): ByteArray {
        return wasmRuntime.callFunction(
            "decrypt_data",
            mapOf("ciphertext" to ciphertext, "key" to key)
        ) as ByteArray
    }

    /**
     * Signs a command using HMAC-SHA256
     */
    fun signCommand(command: String, key: ByteArray): ByteArray {
        return wasmRuntime.callFunction(
            "sign_command",
            mapOf("command" to command, "key" to key)
        ) as ByteArray
    }

    /**
     * Verifies a command signature
     */
    fun verifyCommand(command: String, signature: ByteArray, key: ByteArray): Boolean {
        return wasmRuntime.callFunction(
            "verify_command",
            mapOf(
                "command" to command,
                "signature" to signature,
                "key" to key
            )
        ) as Boolean
    }

    /**
     * Generates a cryptographically secure random key
     */
    fun generateRandomKey(length: Int = 32): ByteArray {
        return wasmRuntime.callFunction(
            "generate_random_key",
            mapOf("length" to length)
        ) as ByteArray
    }

    /**
     * Measures password entropy
     */
    fun measurePasswordStrength(password: String): Double {
        val passwordBytes = password.encodeToByteArray()
        return wasmRuntime.callFunction(
            "measure_entropy",
            mapOf("data" to passwordBytes)
        ) as Double
    }

    /**
     * Hardware-bound key derivation
     */
    fun deriveHardwareBoundKey(
        password: String,
        biometricHash: ByteArray,
        hardwareId: String
    ): ByteArray {
        val keyResult = wasmRuntime.callFunction(
            "derive_key_hardware_bound",
            mapOf(
                "password" to password,
                "biometric_hash" to biometricHash,
                "hardware_id" to hardwareId,
                "config" to null
            )
        ) as ByteArray

        return getKeyFromKeyResult(keyResult)
    }

    /**
     * Securely wipes sensitive data
     */
    fun secureWipe(data: ByteArray) {
        wasmRuntime.callFunction(
            "secure_zero",
            mapOf("data" to data)
        )
    }
}
```

## Basic Usage Examples

### Initializing the Crypto Manager

```kotlin
// In your Application class or main Activity
val cryptoManager = CryptoManager(
    (application as SecureTrackApplication).wasmRuntime
)
```

### Secure Password Storage

```kotlin
class SecurePasswordManager(private val cryptoManager: CryptoManager) {
    private val keystore = KeystoreWrapper()

    // Store a password securely
    suspend fun securePassword(userId: String, password: String): Boolean {
        try {
            // Get hardware identifiers
            val hardwareId = getSecureHardwareId()

            // Get biometric hash (if available)
            val biometricHash = getBiometricHash() ?: ByteArray(32)

            // Derive a hardware-bound key
            val key = cryptoManager.deriveHardwareBoundKey(
                password,
                biometricHash,
                hardwareId
            )

            // Store the key in the Android Keystore
            keystore.storeKey(userId, key)

            // Clean up
            cryptoManager.secureWipe(key)

            return true
        } catch (e: Exception) {
            Log.e("SecurePasswordManager", "Failed to secure password", e)
            return false
        }
    }

    // Verify a password
    suspend fun verifyPassword(userId: String, password: String): Boolean {
        try {
            // Get hardware identifiers
            val hardwareId = getSecureHardwareId()

            // Get biometric hash (if available)
            val biometricHash = getBiometricHash() ?: ByteArray(32)

            // Derive a hardware-bound key
            val derivedKey = cryptoManager.deriveHardwareBoundKey(
                password,
                biometricHash,
                hardwareId
            )

            // Retrieve the stored key
            val storedKey = keystore.getKey(userId)

            // Compare the keys (constant-time)
            val result = derivedKey.contentEquals(storedKey)

            // Clean up
            cryptoManager.secureWipe(derivedKey)
            cryptoManager.secureWipe(storedKey)

            return result
        } catch (e: Exception) {
            Log.e("SecurePasswordManager", "Failed to verify password", e)
            return false
        }
    }
}
```

### Secure Data Storage

```kotlin
class SecureDataManager(private val cryptoManager: CryptoManager) {
    private val keystore = KeystoreWrapper()

    // Encrypt and store data
    suspend fun secureData(userId: String, data: ByteArray): Boolean {
        try {
            // Get the user's key from the keystore
            val key = keystore.getKey(userId)

            // Encrypt the data
            val encryptedData = cryptoManager.encryptData(data, key)

            // Store the encrypted data
            storeEncryptedData(userId, encryptedData)

            // Clean up
            cryptoManager.secureWipe(key)

            return true
        } catch (e: Exception) {
            Log.e("SecureDataManager", "Failed to secure data", e)
            return false
        }
    }

    // Retrieve and decrypt data
    suspend fun retrieveData(userId: String): ByteArray? {
        try {
            // Get the user's key from the keystore
            val key = keystore.getKey(userId)

            // Retrieve the encrypted data
            val encryptedData = getEncryptedData(userId)

            // Decrypt the data
            val decryptedData = cryptoManager.decryptData(encryptedData, key)

            // Clean up
            cryptoManager.secureWipe(key)

            return decryptedData
        } catch (e: Exception) {
            Log.e("SecureDataManager", "Failed to retrieve data", e)
            return null
        }
    }
}
```

## Advanced Features

### Biometric Integration

```kotlin
class BiometricManager(private val context: Context, private val cryptoManager: CryptoManager) {
    private val biometricPrompt: BiometricPrompt

    init {
        val executor = ContextCompat.getMainExecutor(context)
        biometricPrompt = BiometricPrompt(
            context as FragmentActivity,
            executor,
            BiometricCallback()
        )
    }

    fun authenticateAndExecute(onSuccess: (ByteArray) -> Unit) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to access secure features")
            .setNegativeButtonText("Cancel")
            .build()

        // Store the callback for later use
        this.onSuccessCallback = onSuccess

        biometricPrompt.authenticate(promptInfo)
    }

    private var onSuccessCallback: ((ByteArray) -> Unit)? = null

    inner class BiometricCallback : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)

            // Generate a biometric hash from the authentication result
            val cryptoObject = result.cryptoObject
            val signature = cryptoObject?.signature

            val biometricHash = createBiometricHash(signature)

            // Call the success callback with the biometric hash
            onSuccessCallback?.invoke(biometricHash)
        }

        private fun createBiometricHash(signature: Signature?): ByteArray {
            // This is a simplified example
            // In a real implementation, you would use the signature to create a
            // deterministic but secure biometric hash
            return signature?.let {
                val data = "biometric_seed".toByteArray()
                it.update(data)
                it.sign()
            } ?: ByteArray(32)
        }
    }
}
```

### Key Backup

```kotlin
class KeyBackupManager(private val cryptoManager: CryptoManager) {

    /**
     * Splits a key into multiple shares for secure backup
     */
    fun createKeyBackup(key: ByteArray, totalShares: Int): List<ByteArray> {
        return wasmRuntime.callFunction(
            "split_key",
            mapOf(
                "key" to key,
                "total_shares" to totalShares,
                "threshold" to totalShares  // n-of-n threshold
            )
        ) as List<ByteArray>
    }

    /**
     * Reconstructs a key from shares
     */
    fun restoreKeyFromBackup(shares: List<ByteArray>): ByteArray {
        return wasmRuntime.callFunction(
            "combine_key",
            mapOf("shares" to shares)
        ) as ByteArray
    }
}
```

## Security Best Practices

1. **Always Clean Up Sensitive Data**

   - Use `cryptoManager.secureWipe()` on any sensitive ByteArrays when done
   - Avoid storing sensitive data in Strings (they can't be securely wiped)

2. **Biometric Protection**

   - Always combine biometrics with hardware binding for maximum security
   - Use the Android KeyStore to protect cryptographic keys

3. **Offline Resilience**

   - Cache necessary cryptographic materials securely for offline operation
   - Implement proper key rotation policies

4. **Error Handling**

   - Never expose cryptographic exceptions directly to the user
   - Implement proper logging that doesn't reveal sensitive data

5. **UI Integration**

   - Display security status clearly in the UI
   - Use proper visual indicators for secure states

6. **Testing**
   - Test on multiple Android versions and device types
   - Implement instrumentation tests for cryptographic operations

## Troubleshooting

### Common Issues

1. **"Module not found" errors**

   - Ensure the WASM file is correctly placed in the assets directory
   - Check your WasmEdge initialization code

2. **Performance issues**

   - Key derivation operations (especially Argon2id) can be slow on older devices
   - Consider running these operations in a background thread or coroutine

3. **Memory issues**

   - Large cryptographic operations can consume significant memory
   - Ensure proper cleanup with `secureWipe()`

4. **Compatibility issues**
   - Test on a range of API levels
   - Consider providing fallback mechanisms for older devices

### Debugging Tips

1. Use the debug logging feature of the crypto library
2. Implement proper error handling with descriptive messages
3. Test on real devices, not just emulators

---

## Support

For further assistance, refer to the main SecureTrack documentation or contact the SecureTrack team.
