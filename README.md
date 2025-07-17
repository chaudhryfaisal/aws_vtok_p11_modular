# vtok_p11 Modular PKCS#11 Architecture

A modular, extensible PKCS#11 provider implementation that supports pluggable cryptographic backends. This project transforms the original monolithic vtok_p11 implementation into a layered architecture with clear separation of concerns.

## 🏗️ Architecture Overview

The modular architecture consists of five main components:

```
┌─────────────────┬─────────────────┐
│  pkcs11_aws_lc  │  pkcs11_mock    │  ← Complete PKCS#11 Providers
├─────────────────┴─────────────────┤
│           vtok_p11                │  ← Core PKCS#11 Implementation
├───────────────────────────────────┤
│         vtok_backend              │  ← Backend Abstraction Layer
├───────────────────────────────────┤
│         vtok_common               │  ← Shared Utilities
└───────────────────────────────────┘
```

### Components

- **`vtok_backend`**: Core abstraction layer defining traits for cryptographic operations
- **`vtok_common`**: Shared utilities and common functionality
- **`vtok_p11`**: PKCS#11 implementation core (crypto-backend agnostic)
- **`pkcs11_aws_lc`**: Complete PKCS#11 provider using AWS-LC cryptographic backend
- **`pkcs11_mock`**: Complete PKCS#11 provider with mock backend for testing

## 🚀 Quick Start

### Using AWS-LC Provider

```rust
use pkcs11_aws_lc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the AWS-LC PKCS#11 provider
    pkcs11_aws_lc::initialize()?;
    
    // Use standard PKCS#11 C API
    unsafe {
        let mut rv = pkcs11::C_Initialize(std::ptr::null_mut());
        assert_eq!(rv, pkcs11::CKR_OK);
        
        // Your PKCS#11 operations here...
        
        rv = pkcs11::C_Finalize(std::ptr::null_mut());
        assert_eq!(rv, pkcs11::CKR_OK);
    }
    
    Ok(())
}
```

### Using Mock Provider

```rust
use pkcs11_mock;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the mock PKCS#11 provider
    pkcs11_mock::initialize()?;
    
    // Configure mock behavior
    pkcs11_mock::configure()
        .with_deterministic_keys(true)
        .with_error_injection(false)
        .apply()?;
    
    // Use standard PKCS#11 C API for testing
    unsafe {
        let mut rv = pkcs11::C_Initialize(std::ptr::null_mut());
        assert_eq!(rv, pkcs11::CKR_OK);
        
        // Your test operations here...
        
        rv = pkcs11::C_Finalize(std::ptr::null_mut());
        assert_eq!(rv, pkcs11::CKR_OK);
    }
    
    Ok(())
}
```

## 🔧 Building

### Prerequisites

- Rust 1.70 or later
- CMake (for AWS-LC)
- C compiler (GCC, Clang, or MSVC)

### Build All Components

```bash
# Build the entire workspace
cargo build --workspace

# Build specific providers
cargo build -p pkcs11_aws_lc
cargo build -p pkcs11_mock

# Build optimized release versions
cargo build --workspace --release
```

### Build Profiles

The workspace includes several optimized build profiles:

```bash
# Standard release build
cargo build --release

# Size-optimized build
cargo build --profile release-small

# Development build with debug info
cargo build --profile dev

# Benchmarking build
cargo build --profile bench
```

## 📦 Crate Details

### vtok_backend

The foundational abstraction layer that defines traits for cryptographic operations.

**Key Features:**
- Trait-based design for pluggable backends
- Comprehensive error handling
- Async operation support
- Type-safe key and mechanism definitions

**Core Traits:**
- `CryptoBackend`: Main backend interface
- `Key`, `KeyPair`, `Certificate`: Key management
- `SignContext`, `VerifyContext`: Digital signatures
- `EncryptContext`, `DecryptContext`: Encryption operations
- `DigestContext`: Hashing operations

### vtok_p11

The core PKCS#11 implementation that provides the standard PKCS#11 C API.

**Key Features:**
- Complete PKCS#11 v2.40 compatibility
- Backend-agnostic design
- Session and token management
- Object database with persistence
- Thread-safe concurrent operations

### pkcs11_aws_lc

Production-ready PKCS#11 provider using AWS-LC as the cryptographic backend.

**Supported Algorithms:**
- **RSA**: 1024, 2048, 3072, 4096, 8192-bit keys
- **ECDSA**: P-224, P-256, P-384, P-521, secp256k1 curves
- **AES**: 128, 192, 256-bit keys (ECB, CBC, CTR, GCM modes)
- **Hash**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-3
- **HMAC**: With all supported hash algorithms

**Features:**
- Hardware acceleration support
- FIPS 140-2 compliance (when using FIPS-validated AWS-LC)
- High-performance cryptographic operations
- Memory-safe implementation

### pkcs11_mock

Comprehensive mock PKCS#11 provider for testing and development.

**Key Features:**
- Deterministic key generation for reproducible tests
- Configurable error injection
- Performance simulation
- Complete PKCS#11 API coverage
- No actual cryptographic security (for testing only)

**Use Cases:**
- Unit and integration testing
- CI/CD pipelines
- Development environments
- PKCS#11 application testing

## 🧪 Testing

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test -p vtok_backend
cargo test -p pkcs11_aws_lc
cargo test -p pkcs11_mock

# Run integration tests
cargo test --test integration_tests

# Run with mock backend for faster testing
cargo test --features mock-backend
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: Cross-crate functionality testing
- **PKCS#11 Compliance Tests**: Standard compliance verification
- **Performance Tests**: Benchmarking and performance validation

## 📚 Documentation

### Architecture Documentation

- **[Architecture Overview](docs/architecture.md)**: Complete architectural design and principles
- **[Migration Guide](docs/migration_guide.md)**: Guide for migrating from monolithic to modular architecture
- **[Backend Implementation Guide](docs/backend_implementation.md)**: How to implement new cryptographic backends
- **[API Reference](docs/api_reference.md)**: Comprehensive API documentation

### Examples

```bash
# View provider information
cargo run --bin info -p pkcs11_aws_lc
cargo run --bin info -p pkcs11_mock

# Run example applications
cargo run --example key_generation -p pkcs11_aws_lc
cargo run --example signing -p pkcs11_aws_lc
```

## 🔐 Security Considerations

### Production Use

For production environments, use `pkcs11_aws_lc`:

```toml
[dependencies]
pkcs11_aws_lc = { version = "0.1.0", features = ["static-linking"] }
```

### Testing and Development

For testing and development, use `pkcs11_mock`:

```toml
[dev-dependencies]
pkcs11_mock = { version = "0.1.0", features = ["deterministic"] }
```

### Security Features

- **Memory Safety**: All implementations use memory-safe Rust
- **Key Protection**: Sensitive key material is properly protected
- **Thread Safety**: Concurrent access is safely handled
- **Error Handling**: Comprehensive error handling prevents information leakage

## 🚀 Performance

### Benchmarks

```bash
# Run performance benchmarks
cargo bench --workspace

# Compare backend performance
cargo bench --bench backend_comparison

# Profile specific operations
cargo bench --bench signing_performance
```

### Optimization Features

- **Zero-copy operations** where possible
- **Efficient memory management** with minimal allocations
- **Hardware acceleration** support (when available)
- **Optimized build profiles** for different use cases

## 🔌 Extending the Architecture

### Implementing a New Backend

1. Create a new crate (e.g., `pkcs11_openssl`)
2. Implement the `vtok_backend` traits
3. Depend on `vtok_p11` for PKCS#11 functionality
4. Export the PKCS#11 C API

Example structure:

```rust
// src/lib.rs
use vtok_backend::traits::CryptoBackend;
use vtok_p11::VtokP11;

pub struct OpenSslBackend {
    // OpenSSL-specific implementation
}

impl CryptoBackend for OpenSslBackend {
    // Implement required methods
}

pub fn initialize() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(OpenSslBackend::new()?);
    VtokP11::initialize_with_backend(backend)?;
    Ok(())
}

// Export PKCS#11 C API
vtok_p11::export_pkcs11_api!();
```

### Supported Crypto Libraries

The architecture is designed to support any cryptographic library:

- **AWS-LC** (implemented)
- **Mock** (implemented)
- **OpenSSL** (planned)
- **BoringSSL** (planned)
- **WolfCrypt** (planned)
- **Hardware Security Modules** (planned)

## 📋 Project Status

### Completed Features

- ✅ Modular architecture design
- ✅ Backend abstraction layer (`vtok_backend`)
- ✅ Core PKCS#11 implementation (`vtok_p11`)
- ✅ AWS-LC backend provider (`pkcs11_aws_lc`)
- ✅ Mock backend provider (`pkcs11_mock`)
- ✅ Comprehensive documentation
- ✅ Integration tests
- ✅ Workspace configuration

### Current Capabilities

- **Complete PKCS#11 v2.40 API** implementation
- **Multiple cryptographic backends** (AWS-LC, Mock)
- **Thread-safe concurrent operations**
- **Comprehensive error handling**
- **Memory-safe implementation**
- **Extensive testing framework**

### Future Enhancements

- Additional cryptographic backends (OpenSSL, BoringSSL, WolfCrypt)
- Hardware Security Module (HSM) support
- PKCS#11 URI support
- Enhanced configuration management
- Performance optimizations
- Additional cryptographic algorithms

## 🤝 Contributing

### Development Setup

```bash
# Clone the repository
git clone https://github.com/aws/aws-vtok-p11-modular.git
cd aws-vtok-p11-modular

# Install dependencies
cargo build --workspace

# Run tests
cargo test --workspace

# Check formatting and linting
cargo fmt --check
cargo clippy --workspace
```

### Contribution Guidelines

1. **Follow Rust best practices** and coding standards
2. **Add comprehensive tests** for new functionality
3. **Update documentation** for API changes
4. **Ensure thread safety** for all implementations
5. **Handle errors appropriately** with proper error types

## 📄 License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **AWS Nitro Enclaves Team** for the original vtok_p11 implementation
- **AWS-LC Team** for the cryptographic library
- **Rust Community** for excellent cryptographic crates and tools

## 📞 Support

- **Documentation**: See [docs/](docs/) directory
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Discussions**: Join discussions for questions and ideas

---

**Note**: This modular architecture provides a solid foundation for PKCS#11 implementations while maintaining flexibility for different cryptographic backends and use cases. The design prioritizes security, performance, and maintainability.