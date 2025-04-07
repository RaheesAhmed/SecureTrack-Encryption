# SecureTrack Crypto Library - Web Integration Guide

This guide provides step-by-step instructions for integrating the SecureTrack crypto library into web applications using WebAssembly.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setup](#setup)
3. [Basic Usage Examples](#basic-usage-examples)
4. [Advanced Features](#advanced-features)
5. [Security Best Practices](#security-best-practices)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

- Modern web environment (ES6+ compatible)
- Node.js 14+ for development/build tools
- Webpack, Rollup, or another bundler with WASM support

## Setup

### Installing from NPM

For React, Next.js, Vue, or other NPM-based projects:

```bash
npm install securetrack-crypto
# or
yarn add securetrack-crypto
```

### Manual Installation

If you prefer to manually integrate the library:

1. Copy the `securetrack_crypto_bg.wasm` and `securetrack_crypto.js` files to your project's assets directory.
2. Import the module in your JavaScript/TypeScript code.

### Loading the WASM Module

```javascript
// Using ES modules (recommended)
import * as secureTrackCrypto from "securetrack-crypto";

// Or with dynamic import
const initCrypto = async () => {
  const secureTrackCrypto = await import("securetrack-crypto");
  await secureTrackCrypto.default(); // Initialize the module
  return secureTrackCrypto;
};

// Or with manual loading
const initCrypto = async () => {
  const module = await import("/path/to/securetrack_crypto.js");
  await module.default();
  return module;
};
```

## Basic Usage Examples

### Key Derivation

```javascript
// Initialize the crypto module
const crypto = await initCrypto();

// Derive a key using Argon2id (recommended)
const deriveKey = async (password) => {
  try {
    // Generate a random salt (or use a stored one for key regeneration)
    const salt = null; // null means generate a random salt

    // Derive the key
    const keyResult = crypto.derive_key_argon2id(password, salt, null);

    // Extract the key and salt from the result
    const key = crypto.get_key_from_key_result(keyResult);
    const extractedSalt = crypto.get_salt_from_key_result(keyResult);

    // Store the salt securely for later use in password verification
    // Never store the actual key!
    localStorage.setItem("user_salt", arrayBufferToBase64(extractedSalt));

    return key;
  } catch (error) {
    console.error("Key derivation failed:", error);
    throw error;
  }
};

// Helper function to convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  return btoa(String.fromCharCode.apply(null, bytes));
}

// Helper function to convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
```

### Encryption and Decryption

```javascript
// Encrypt data
const encryptData = async (data, key) => {
  try {
    // Convert string data to Uint8Array if needed
    const dataBytes =
      typeof data === "string" ? new TextEncoder().encode(data) : data;

    // Encrypt the data
    const encrypted = crypto.encrypt_data(dataBytes, key);

    // Return the encrypted data as Base64 for easy storage
    return arrayBufferToBase64(encrypted);
  } catch (error) {
    console.error("Encryption failed:", error);
    throw error;
  }
};

// Decrypt data
const decryptData = async (encryptedBase64, key) => {
  try {
    // Convert Base64 encrypted data back to ArrayBuffer
    const encryptedData = base64ToArrayBuffer(encryptedBase64);

    // Decrypt the data
    const decrypted = crypto.decrypt_data(encryptedData, key);

    // Convert the decrypted data to a string if needed
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Decryption failed:", error);
    throw error;
  }
};
```

### Secure Command Signing

```javascript
// Sign a command
const signCommand = async (command, key) => {
  try {
    const signature = crypto.sign_command(command, key);
    return arrayBufferToBase64(signature);
  } catch (error) {
    console.error("Command signing failed:", error);
    throw error;
  }
};

// Verify a command signature
const verifyCommand = async (command, signatureBase64, key) => {
  try {
    const signature = base64ToArrayBuffer(signatureBase64);
    return crypto.verify_command(command, signature, key);
  } catch (error) {
    console.error("Signature verification failed:", error);
    return false;
  }
};
```

## Advanced Features

### Password Strength Estimation

```javascript
const checkPasswordStrength = (password) => {
  // Measure password entropy in bits
  const passwordBytes = new TextEncoder().encode(password);
  const entropy = crypto.measure_entropy(passwordBytes);

  // Classify password strength
  if (entropy < 40) {
    return { strength: "weak", entropy, message: "Password is too weak" };
  } else if (entropy < 60) {
    return {
      strength: "moderate",
      entropy,
      message: "Password is moderately strong",
    };
  } else if (entropy < 80) {
    return { strength: "strong", entropy, message: "Password is strong" };
  } else {
    return {
      strength: "very-strong",
      entropy,
      message: "Password is very strong",
    };
  }
};
```

### Secure Key Backup

```javascript
// Split a key into multiple shares
const backupKey = (key, totalShares) => {
  try {
    // Split the key into 'totalShares' pieces (all required to reconstruct)
    const shares = crypto.split_key(key, totalShares, totalShares);

    // Convert shares to Base64 for storage/display
    return shares.map((share) => arrayBufferToBase64(share));
  } catch (error) {
    console.error("Key splitting failed:", error);
    throw error;
  }
};

// Reconstruct a key from shares
const restoreKey = (shareBase64Array) => {
  try {
    // Convert Base64 shares back to ArrayBuffers
    const shares = shareBase64Array.map((share) => base64ToArrayBuffer(share));

    // Reconstruct the original key
    return crypto.combine_key(shares);
  } catch (error) {
    console.error("Key reconstruction failed:", error);
    throw error;
  }
};
```

### React Component Example: Secure Storage

```jsx
import React, { useState, useEffect } from "react";
import * as secureTrackCrypto from "securetrack-crypto";

const SecureStorage = () => {
  const [isInitialized, setIsInitialized] = useState(false);
  const [masterKey, setMasterKey] = useState(null);
  const [data, setData] = useState("");
  const [encryptedData, setEncryptedData] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState({
    type: "info",
    message: "Enter your password",
  });

  // Initialize the crypto module
  useEffect(() => {
    const initCrypto = async () => {
      try {
        await secureTrackCrypto.default();
        setIsInitialized(true);
        setStatus({
          type: "success",
          message: "Crypto module loaded successfully",
        });
      } catch (error) {
        setStatus({ type: "error", message: "Failed to load crypto module" });
        console.error(error);
      }
    };

    initCrypto();
  }, []);

  // Derive a key from the password
  const handleDeriveKey = async () => {
    if (!isInitialized) return;

    try {
      setStatus({ type: "info", message: "Deriving key..." });

      // Check password strength
      const passwordBytes = new TextEncoder().encode(password);
      const entropy = secureTrackCrypto.measure_entropy(passwordBytes);

      if (entropy < 50) {
        setStatus({
          type: "warning",
          message: "Password is too weak. Please use a stronger password.",
        });
        return;
      }

      // Derive the key
      const keyResult = secureTrackCrypto.derive_key_argon2id(
        password,
        null,
        null
      );
      const key = secureTrackCrypto.get_key_from_key_result(keyResult);

      setMasterKey(key);
      setStatus({ type: "success", message: "Key derived successfully" });
    } catch (error) {
      setStatus({ type: "error", message: "Failed to derive key" });
      console.error(error);
    }
  };

  // Encrypt the data
  const handleEncrypt = async () => {
    if (!isInitialized || !masterKey) return;

    try {
      setStatus({ type: "info", message: "Encrypting data..." });

      const dataBytes = new TextEncoder().encode(data);
      const encrypted = secureTrackCrypto.encrypt_data(dataBytes, masterKey);

      // Convert to Base64 for display
      const encryptedBase64 = btoa(
        String.fromCharCode.apply(null, new Uint8Array(encrypted))
      );

      setEncryptedData(encryptedBase64);
      setStatus({ type: "success", message: "Data encrypted successfully" });
    } catch (error) {
      setStatus({ type: "error", message: "Encryption failed" });
      console.error(error);
    }
  };

  // Decrypt the data
  const handleDecrypt = async () => {
    if (!isInitialized || !masterKey || !encryptedData) return;

    try {
      setStatus({ type: "info", message: "Decrypting data..." });

      // Convert from Base64
      const binary = atob(encryptedData);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }

      const decrypted = secureTrackCrypto.decrypt_data(bytes, masterKey);
      const decryptedText = new TextDecoder().decode(decrypted);

      setData(decryptedText);
      setStatus({ type: "success", message: "Data decrypted successfully" });
    } catch (error) {
      setStatus({ type: "error", message: "Decryption failed" });
      console.error(error);
    }
  };

  return (
    <div className="secure-storage p-4 bg-gray-900 text-white rounded-lg shadow-lg max-w-md mx-auto">
      <h2 className="text-2xl font-bold mb-4 text-cyan-400">
        SecureTrack Secure Storage
      </h2>

      <div
        className={`status-message p-2 rounded mb-4 ${
          status.type === "error"
            ? "bg-red-900"
            : status.type === "success"
            ? "bg-green-900"
            : status.type === "warning"
            ? "bg-yellow-900"
            : "bg-blue-900"
        }`}
      >
        {status.message}
      </div>

      <div className="mb-4">
        <label className="block text-sm font-medium mb-1">
          Master Password
        </label>
        <div className="flex gap-2">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="flex-1 px-3 py-2 bg-gray-800 rounded border border-gray-700 text-white"
            placeholder="Enter secure password"
          />
          <button
            onClick={handleDeriveKey}
            disabled={!isInitialized || !password}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded disabled:bg-gray-700"
          >
            Derive Key
          </button>
        </div>
      </div>

      <div className="mb-4">
        <label className="block text-sm font-medium mb-1">Secret Data</label>
        <textarea
          value={data}
          onChange={(e) => setData(e.target.value)}
          className="w-full px-3 py-2 bg-gray-800 rounded border border-gray-700 text-white"
          rows={4}
          placeholder="Enter data to encrypt"
        ></textarea>
      </div>

      <div className="flex gap-2 mb-4">
        <button
          onClick={handleEncrypt}
          disabled={!isInitialized || !masterKey || !data}
          className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded disabled:bg-gray-700"
        >
          Encrypt
        </button>
        <button
          onClick={handleDecrypt}
          disabled={!isInitialized || !masterKey || !encryptedData}
          className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded disabled:bg-gray-700"
        >
          Decrypt
        </button>
      </div>

      {encryptedData && (
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">
            Encrypted Data
          </label>
          <div className="w-full px-3 py-2 bg-gray-800 rounded border border-gray-700 text-white overflow-x-auto">
            <code className="text-xs break-all">{encryptedData}</code>
          </div>
        </div>
      )}

      <div className="text-xs text-gray-400 mt-4">
        <p>Security Status: {masterKey ? "🔒 Secure" : "🔓 Not Secured"}</p>
        {masterKey && (
          <p>Key is stored in memory. Refresh the page to clear it.</p>
        )}
      </div>
    </div>
  );
};

export default SecureStorage;
```

## Security Best Practices

1. **Key Management**

   - Never store encryption keys directly in LocalStorage, SessionStorage, or cookies
   - Use the Web Crypto API's secure key storage where possible
   - Consider hardware security (WebAuthn) for additional protection

2. **Password Handling**

   - Always use strong password requirements (check with `measure_entropy`)
   - Never log passwords or cryptographic keys
   - Use password managers and autofill where possible

3. **Data Protection**

   - Clear sensitive data from memory when no longer needed
   - Minimize the time that decrypted data is held in memory
   - Use proper Content Security Policy headers

4. **Secure Communication**

   - Only run over HTTPS connections
   - Consider using Subresource Integrity (SRI) for loading the WASM module
   - Implement proper CORS policies

5. **User Experience**
   - Provide clear visual security indicators
   - Implement proper loading states during cryptographic operations
   - Handle errors gracefully without exposing sensitive details

## Troubleshooting

### Common Issues

1. **"Cannot read properties of undefined" errors**

   - Ensure you've properly initialized the WASM module before calling functions
   - Check that you're awaiting the module initialization properly

2. **"Out of memory" errors**

   - The WASM module has limited memory; avoid very large inputs
   - Break large operations into smaller chunks

3. **"Invalid key length" or similar errors**

   - Double-check that you're passing the correct types to function calls
   - Ensure Binary data is properly converted to/from strings

4. **Performance issues**
   - Key derivation (especially Argon2id) can be slow in the browser
   - Use Web Workers for intensive cryptographic operations
   - Consider caching derived keys (securely) to avoid recalculation

### Debugging Tips

1. Set up proper error handling with try/catch around all crypto operations
2. Use browser developer tools to inspect WebAssembly memory and performance
3. Implement logging that captures error codes but not sensitive data

---

## Support

For further assistance, refer to the main SecureTrack documentation or contact the SecureTrack team.
