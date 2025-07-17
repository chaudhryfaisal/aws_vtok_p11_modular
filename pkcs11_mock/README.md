# pkcs11_mock

A complete PKCS#11 provider with mock cryptographic backend for testing and development.

## Overview

`pkcs11_mock` provides a standalone PKCS#11 provider that uses mock implementations for all cryptographic operations. It's designed for testing, development, and CI/CD environments where real cryptography is not needed but PKCS#11 compatibility is required.

## Features

- **Complete PKCS#11 C API compatibility** - Drop-in replacement for real PKCS#11 providers
- **Deterministic behavior** - Reproducible results for testing
- **Configurable error injection** - Test error handling paths
- **Performance simulation** - Simulate realistic operation delays
- **Thread-safe operations** - Safe for concurrent use
- **Comprehensive test utilities** - Built-in test data generators and scenarios

## Use Cases

- Unit and integration testing
- CI/CD pipelines where real crypto isn't needed
- Development environments
- Performance testing and benchmarking
- Error condition testing
- PKCS#11 application development and debugging

## Quick Start

### As a Library

```rust
use pkcs11_mock::provider::MockProvider;
use vtok_backend::traits::CryptoBackend;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a deterministic mock provider
    let provider = MockProvider::deterministic()?;
    let backend = provider.backend();
    
    // Generate a key pair
    let keypair = backend.generate_keypair(
        vtok_backend::types::KeyAlgorithm::Rsa2048, 
        None
    ).await?;
    
    // Create a signing context
    let sign_ctx = backend.create_sign_context(
        vtok_backend::types::Mechanism::RsaPkcs1 { 
            digest: Some(vtok_backend::types::DigestAlgorithm::Sha256) 
        },
        keypair.private_key(),
        None
    ).await?;
    
    // Sign some data
    let data = b"Hello, World!";
    let signature = sign_ctx.sign_oneshot(data)?;
    
    println!("Signature: {:?}", signature);
    Ok(())
}
```

### As a PKCS#11 Provider

The crate can be compiled as a shared library and used directly by PKCS#11 applications:

```bash
# Build as shared library
cargo build --release

# Use with PKCS#11 applications
export PKCS11_MODULE=./target/release/libpkcs11_mock.so
```

### Command Line Utility

```bash
# Get provider information
cargo run --bin info -- --provider-info

# List supported mechanisms
cargo run --bin info -- --mechanisms

# Generate test vectors
cargo run --bin info -- --generate-test-vectors --test-vectors-file vectors.json

# Run performance test
cargo run --bin info -- --performance-test
```

## Configuration

### Basic Configuration

```rust
use pkcs11_mock::data::MockConfig;
use pkcs11_mock::provider::MockProvider;

// Create deterministic configuration
let config = MockConfig::deterministic();
let provider = MockProvider::with_config(config)?;
```

### Error Injection

```rust
use pkcs11_mock::provider::MockProvider;

// Enable error injection for specific operations
let provider = MockProvider::with_error_injection(vec![
    "generate_keypair".to_string(),
    "sign_oneshot".to_string(),
])?;
```

### Performance Simulation

```rust
use std::collections::HashMap;
use std::time::Duration;
use pkcs11_mock::provider::MockProvider;

// Add delays to operations
let mut delays = HashMap::new();
delays.insert("generate_keypair".to_string(), Duration::from_millis(100));
delays.insert("sign_oneshot".to_string(), Duration::from_millis(10));

let provider = MockProvider::with_performance_simulation(delays)?;
```

### Configuration Files

```rust
use pkcs11_mock::provider::MockProvider;

// Load from JSON configuration file
let provider = MockProvider::from_config_file("config.json")?;

// Save configuration
provider.save_config_to_file("saved_config.json")?;
```

## Test Scenarios

The crate provides predefined test scenarios for common use cases:

```rust
use pkcs11_mock::utils::TestScenarios;
use pkcs11_mock::provider::MockProvider;

// Basic deterministic testing
let config = TestScenarios::basic_deterministic();
let provider = MockProvider::with_config(config)?;

// Error injection testing
let config = TestScenarios::error_injection();
let provider = MockProvider::with_config(config)?;

// Performance testing
let config = TestScenarios::performance_testing();
let provider = MockProvider::with_config(config)?;

// CI/CD optimized
let config = TestScenarios::ci_cd();
let provider = MockProvider::with_config(config)?;
```

## Test Data Generation

Generate comprehensive test vectors for cryptographic operations:

```rust
use pkcs11_mock::utils::{MockDataFactory, TestVectorCollection};

// Create deterministic test data
let factory = MockDataFactory::deterministic();

// Generate RSA test data
let rsa_data = factory.rsa_test_data(2048);
println!("RSA private key: {:?}", rsa_data.private_key);
println!("RSA signature: {:?}", rsa_data.signature);

// Generate comprehensive test vectors
let vectors = TestVectorCollection::comprehensive();
vectors.save_to_file("test_vectors.json")?;
```

## Supported Operations

### Key Operations
- RSA key pair generation (2048, 3072, 4096 bits)
- ECDSA key pair generation (P-256, P-384)
- AES symmetric key generation (256 bits)
- Key import/export
- Key derivation (mock)

### Cryptographic Operations
- Digital signatures (RSA-PKCS#1, RSA-PSS, ECDSA)
- Signature verification
- Encryption/Decryption (mock implementations)
- Digest operations (SHA-256, SHA-384, SHA-512)

### PKCS#11 Functions
- Session management
- Object management
- Token operations
- Mechanism queries
- All standard PKCS#11 C API functions

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run with logging
RUST_LOG=debug cargo test
```

## Examples

See the `examples/` directory for complete usage examples:

- `basic_usage.rs` - Basic provider usage
- `error_injection.rs` - Error injection testing
- `performance_test.rs` - Performance simulation
- `test_vectors.rs` - Test data generation

## Architecture

The mock provider is built on the `vtok_backend` abstraction layer and implements all required traits:

- `CryptoBackend` - Main backend interface
- `Key`, `KeyPair`, `Certificate` - Key management
- `DigestContext`, `SignContext`, `VerifyContext` - Crypto operations
- `EncryptContext`, `DecryptContext` - Encryption operations

## Configuration Reference

### MockConfig Structure

```json
{
  "deterministic": true,
  "error_injection": {
    "enabled": false,
    "operations": [],
    "probability": 0.1,
    "error_types": ["MockError"]
  },
  "performance_simulation": {
    "enabled": false,
    "operation_delays": {},
    "cpu_simulation": null,
    "memory_simulation": null
  },
  "test_data": {
    "keys": { /* predefined key data */ },
    "certificates": { /* predefined cert data */ },
    "signatures": { /* predefined signature data */ }
  }
}
```

### Error Injection Operations

- `generate_keypair` - Key pair generation
- `generate_key` - Symmetric key generation
- `sign_oneshot` - One-shot signing
- `verify_oneshot` - One-shot verification
- `encrypt_oneshot` - One-shot encryption
- `decrypt_oneshot` - One-shot decryption
- `digest_finalize` - Digest finalization

## License

Licensed under the Apache License, Version 2.0.

## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.