#!/bin/bash
# SecureTrack Crypto Library Build Script
# Builds the library for all target platforms

set -e

# Output banner
echo "====================================="
echo "SecureTrack Crypto Library Builder"
echo "====================================="
echo "Building version: $(grep version ../Cargo.toml | head -1 | cut -d'"' -f2)"
echo

# Create output directory
mkdir -p ../dist

# Function to build for a specific target
build_target() {
    local target=$1
    local output_name=$2
    local additional_flags=$3
    
    echo "Building for $target..."
    
    # Build the target
    rustup target add $target 2>/dev/null || true
    
    cargo build --target $target --release $additional_flags
    
    # Copy the output to the dist directory
    local ext=""
    if [[ $target == *windows* ]]; then
        ext=".dll"
    elif [[ $target == *apple* || $target == *linux* || $target == *android* ]]; then
        ext=".so"
    fi
    
    cp ../target/$target/release/libsecuretrack_crypto$ext ../dist/$output_name
    
    echo "✓ Built $output_name"
    echo
}

# Function to build WASM
build_wasm() {
    echo "Building WebAssembly module..."
    
    # Ensure wasm32 target is installed
    rustup target add wasm32-unknown-unknown 2>/dev/null || true
    
    # Build the WASM module
    cargo build --target wasm32-unknown-unknown --release
    
    # Process with wasm-bindgen if available
    if command -v wasm-bindgen &> /dev/null; then
        echo "Generating JavaScript bindings with wasm-bindgen..."
        wasm-bindgen --target web --out-dir ../dist/wasm ../target/wasm32-unknown-unknown/release/securetrack_crypto.wasm
        
        # Optional: Optimize with wasm-opt if available
        if command -v wasm-opt &> /dev/null; then
            echo "Optimizing WASM with wasm-opt..."
            wasm-opt -Oz -o ../dist/wasm/securetrack_crypto_opt.wasm ../dist/wasm/securetrack_crypto_bg.wasm
            cp ../dist/wasm/securetrack_crypto_opt.wasm ../dist/wasm/securetrack_crypto_bg.wasm
        fi
    else
        # If wasm-bindgen is not available, just copy the raw wasm file
        mkdir -p ../dist/wasm
        cp ../target/wasm32-unknown-unknown/release/securetrack_crypto.wasm ../dist/wasm/
        echo "⚠️ wasm-bindgen not found. Copying raw WASM file."
    fi
    
    echo "✓ Built WebAssembly module"
    echo
}

# Function to build for Android
build_android() {
    echo "Building for Android..."
    
    # Ensure required targets are installed
    rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android 2>/dev/null || true
    
    # Check for Android NDK
    if [ -z "$ANDROID_NDK_HOME" ]; then
        echo "⚠️ ANDROID_NDK_HOME not set. Android builds may fail."
    fi
    
    # Create Android output directory
    mkdir -p ../dist/android
    
    # Build for each Android architecture
    cargo ndk --target aarch64-linux-android --output ../dist/android --release
    cargo ndk --target armv7-linux-androideabi --output ../dist/android --release
    cargo ndk --target i686-linux-android --output ../dist/android --release
    cargo ndk --target x86_64-linux-android --output ../dist/android --release
    
    echo "✓ Built Android libraries"
    echo
}

# Function to build for iOS
build_ios() {
    echo "Building for iOS..."
    
    # Check if we're on macOS
    if [[ "$(uname)" != "Darwin" ]]; then
        echo "⚠️ iOS builds are only supported on macOS. Skipping."
        return
    fi
    
    # Ensure required targets are installed
    rustup target add aarch64-apple-ios x86_64-apple-ios 2>/dev/null || true
    
    # Create iOS output directory
    mkdir -p ../dist/ios
    
    # Build for iOS device
    cargo build --target aarch64-apple-ios --release
    cp ../target/aarch64-apple-ios/release/libsecuretrack_crypto.a ../dist/ios/
    
    # Build for iOS simulator
    cargo build --target x86_64-apple-ios --release
    cp ../target/x86_64-apple-ios/release/libsecuretrack_crypto.a ../dist/ios/libsecuretrack_crypto_simulator.a
    
    # Create a universal binary if lipo is available
    if command -v lipo &> /dev/null; then
        lipo -create ../dist/ios/libsecuretrack_crypto.a ../dist/ios/libsecuretrack_crypto_simulator.a -output ../dist/ios/libsecuretrack_crypto_universal.a
        echo "Created universal iOS library"
    fi
    
    echo "✓ Built iOS libraries"
    echo
}

# Function to package everything
create_package() {
    echo "Creating release package..."
    
    # Copy documentation
    cp ../README.md ../dist/
    cp ../KOTLIN_INTEGRATION.md ../dist/
    cp ../WEB_INTEGRATION.md ../dist/
    cp ../LICENSE ../dist/
    cp ../CHANGELOG.md ../dist/
    
    # Create version info
    VERSION=$(grep version ../Cargo.toml | head -1 | cut -d'"' -f2)
    echo "SecureTrack Crypto Library v$VERSION" > ../dist/VERSION
    date >> ../dist/VERSION
    
    # Create a zip archive
    (cd ../dist && zip -r securetrack_crypto_v${VERSION}.zip *)
    
    echo "✓ Created package: securetrack_crypto_v${VERSION}.zip"
    echo
}

# Function to run tests
run_tests() {
    echo "Running tests..."
    cargo test --release
    echo "✓ All tests passed"
    echo
}

# Main build process
run_tests
build_wasm
build_target "x86_64-unknown-linux-gnu" "libsecuretrack_crypto_linux_x64.so"
build_target "x86_64-pc-windows-gnu" "securetrack_crypto_windows_x64.dll" "--features windows"
build_target "x86_64-apple-darwin" "libsecuretrack_crypto_macos_x64.dylib" 

# Build for mobile platforms
build_android
build_ios

# Create the final package
create_package

echo "====================================="
echo "Build completed successfully!"
echo "Output is available in the dist directory"
echo "=====================================" 