// SecureTrack Crypto Benchmarking Tool
// Measures performance of critical cryptographic operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use securetrack_crypto::{
    derive_key, derive_key_argon2id, get_key_from_key_result,
    encrypt_data, decrypt_data, sign_command, verify_command,
    generate_random_key,
};

fn benchmark_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Derivation");
    
    // PBKDF2 benchmarking
    group.bench_function("PBKDF2 (default)", |b| {
        b.iter(|| {
            let key_result = derive_key(
                black_box("user123"),
                black_box(vec![0u8; 32]), // Mock biometric hash
                black_box("device:test:1"),
                None,
            ).unwrap();
            let _key = get_key_from_key_result(&key_result, None).unwrap();
        })
    });
    
    // Argon2id benchmarking
    group.bench_function("Argon2id (default)", |b| {
        b.iter(|| {
            let key_result = derive_key_argon2id(
                black_box("secure_password"),
                None,
                None,
            ).unwrap();
            let _key = get_key_from_key_result(&key_result, None).unwrap();
        })
    });
    
    group.finish();
}

fn benchmark_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encryption");
    
    let key = generate_random_key(32).unwrap();
    let data_1kb = vec![0u8; 1024];
    let data_1mb = vec![0u8; 1024 * 1024];
    
    // 1KB data encryption
    group.bench_function("Encrypt 1KB", |b| {
        b.iter(|| {
            let _encrypted = encrypt_data(black_box(&data_1kb), black_box(&key)).unwrap();
        })
    });
    
    // 1MB data encryption
    group.bench_function("Encrypt 1MB", |b| {
        b.iter(|| {
            let _encrypted = encrypt_data(black_box(&data_1mb), black_box(&key)).unwrap();
        })
    });
    
    // Pre-encrypt for decryption benchmarks
    let encrypted_1kb = encrypt_data(&data_1kb, &key).unwrap();
    let encrypted_1mb = encrypt_data(&data_1mb, &key).unwrap();
    
    // 1KB data decryption
    group.bench_function("Decrypt 1KB", |b| {
        b.iter(|| {
            let _decrypted = decrypt_data(black_box(&encrypted_1kb), black_box(&key)).unwrap();
        })
    });
    
    // 1MB data decryption
    group.bench_function("Decrypt 1MB", |b| {
        b.iter(|| {
            let _decrypted = decrypt_data(black_box(&encrypted_1mb), black_box(&key)).unwrap();
        })
    });
    
    group.finish();
}

fn benchmark_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signing");
    
    let key = generate_random_key(32).unwrap();
    let command = "LOCK_DEVICE";
    let data_1kb = vec![0u8; 1024];
    
    // Command signing
    group.bench_function("Sign Command", |b| {
        b.iter(|| {
            let _signature = sign_command(black_box(command), black_box(&key)).unwrap();
        })
    });
    
    // Data signing
    group.bench_function("Sign 1KB Data", |b| {
        b.iter(|| {
            let _signature = sign_command(black_box(&data_1kb), black_box(&key)).unwrap();
        })
    });
    
    // Pre-sign for verification benchmarks
    let signature = sign_command(command, &key).unwrap();
    
    // Command verification
    group.bench_function("Verify Command", |b| {
        b.iter(|| {
            let _is_valid = verify_command(
                black_box(command), 
                black_box(&signature), 
                black_box(&key)
            ).unwrap();
        })
    });
    
    group.finish();
}

fn benchmark_wasm_overhead(c: &mut Criterion) {
    // This benchmark would typically be run in a WASM environment
    // For demonstration purposes, we're showing the structure
    let mut group = c.benchmark_group("WASM Overhead");
    
    let key = generate_random_key(32).unwrap();
    let data = "Hello, SecureTrack!".as_bytes();
    
    group.bench_function("Encrypt/Decrypt Round Trip", |b| {
        b.iter(|| {
            let encrypted = encrypt_data(black_box(data), black_box(&key)).unwrap();
            let _decrypted = decrypt_data(black_box(&encrypted), black_box(&key)).unwrap();
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_key_derivation,
    benchmark_encryption,
    benchmark_signing,
    benchmark_wasm_overhead,
);
criterion_main!(benches); 