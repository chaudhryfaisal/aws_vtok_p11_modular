# Backend Implementation Guide

## Overview

This guide provides comprehensive instructions for implementing new cryptographic backends for the vtok_p11 modular architecture. The backend system is designed to be extensible, allowing developers to integrate different cryptographic libraries while maintaining PKCS#11 compatibility.

## Backend Architecture

### Core Components

A complete backend implementation consists of:

1. **Backend Implementation**: Main struct implementing [`CryptoBackend`](../vtok_backend/src/traits/crypto.rs)
2. **Key Types**: Implementations of [`Key`](../vtok_backend/src/traits/key.rs), [`KeyPair`](../vtok_backend/src/traits/key.rs), and [`Certificate`](../vtok_backend/src/traits/key.rs) traits
3. **Operation Contexts**: Implementations for signing, verification, encryption, decryption, and digest operations
4. **Provider Library**: Complete PKCS#11 provider that integrates with vtok_p11

### Trait Hierarchy

```
CryptoBackend (main entry point)
├── Key Management
│   ├── Key (individual keys)
│   ├── KeyPair (asymmetric key pairs)
│   └── Certificate (X.509 certificates)
└── Operation Contexts
    ├── SignContext (digital signatures)
    ├── VerifyContext (signature verification)
    ├── EncryptContext (encryption operations)
    ├── DecryptContext (decryption operations)
    └── DigestContext (hashing operations)
```

## Step-by-Step Implementation

### Step 1: Project Setup

Create a new crate for your backend provider:

```bash
cargo new --lib pkcs11_your_backend
cd pkcs11_your_backend
```

Update `Cargo.toml`:

```toml
[package]
name = "pkcs11_your_backend"
version = "0.1.0"
edition = "2021"
description = "PKCS#11 provider with YourCrypto backend"
license = "Apache-2.0"

[lib]
name = "pkcs11_your_backend"
crate-type = ["cdylib", "rlib"]

[dependencies]
# Core vtok dependencies
vtok_p11 = { path = "../vtok_p11" }
vtok_backend = { path = "../vtok_backend" }
vtok_common = { path = "../vtok_common" }

# Your cryptographic library
your_crypto_lib = "1.0"

# Standard dependencies
libc = "0.2"
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["rt", "rt-multi-thread"] }
log = "0.4"
thiserror = "1.0"

[dev-dependencies]
tokio-test = "0.4"
tempfile = "3.0"
```

### Step 2: Define Error Types

Create `src/error.rs`:

```rust
use thiserror::Error;
use vtok_backend::types::BackendError;

#[derive(Error, Debug)]
pub enum YourBackendError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(#[from] your_crypto_lib::Error),
    
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    
    #[error("Unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(vtok_backend::types::KeyAlgorithm),
    
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    
    #[error("Operation not supported: {0}")]
    UnsupportedOperation(String),
}

impl From<YourBackendError> for BackendError {
    fn from(err: YourBackendError) -> Self {
        match err {
            YourBackendError::CryptoError(e) => BackendError::CryptoOperation(e.to_string()),
            YourBackendError::InvalidKey(e) => BackendError::InvalidKey(e),
            YourBackendError::UnsupportedAlgorithm(alg) => BackendError::UnsupportedAlgorithm(format!("{:?}", alg)),
            YourBackendError::KeyGeneration(e) => BackendError::KeyGeneration(e),
            YourBackendError::InvalidParameters(e) => BackendError::InvalidParameters(e),
            YourBackendError::UnsupportedOperation(e) => BackendError::UnsupportedOperation(e),
        }
    }
}
```

### Step 3: Implement Key Types

Create `src/key.rs`:

```rust
use std::collections::HashMap;
use vtok_backend::traits::{Key, KeyPair, Certificate};
use vtok_backend::types::{BackendResult, KeyAlgorithm, KeyType};
use vtok_backend::types::key::KeyUsage;
use your_crypto_lib::{PrivateKey, PublicKey, SymmetricKey};

#[derive(Debug, Clone)]
pub struct YourKey {
    inner: KeyInner,
    algorithm: KeyAlgorithm,
    key_type: KeyType,
    usage: KeyUsage,
    extractable: bool,
    sensitive: bool,
    label: Option<String>,
    key_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum KeyInner {
    Private(PrivateKey),
    Public(PublicKey),
    Symmetric(SymmetricKey),
}

impl Key for YourKey {
    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_type(&self) -> KeyType {
        self.key_type
    }

    fn key_size(&self) -> usize {
        match &self.inner {
            KeyInner::Private(key) => key.size_bits(),
            KeyInner::Public(key) => key.size_bits(),
            KeyInner::Symmetric(key) => key.size_bits(),
        }
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.key_id.as_deref()
    }

    fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    fn usage(&self) -> KeyUsage {
        self.usage
    }

    fn is_extractable(&self) -> bool {
        self.extractable
    }

    fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    fn export_key(&self) -> BackendResult<Vec<u8>> {
        if !self.extractable {
            return Err(BackendError::KeyNotExtractable);
        }
        if self.sensitive {
            return Err(BackendError::KeySensitive);
        }

        match &self.inner {
            KeyInner::Private(key) => Ok(key.to_der()?),
            KeyInner::Public(key) => Ok(key.to_der()?),
            KeyInner::Symmetric(key) => Ok(key.to_bytes()),
        }
    }

    fn export_public_key(&self) -> BackendResult<Vec<u8>> {
        match &self.inner {
            KeyInner::Public(key) => Ok(key.to_der()?),
            KeyInner::Private(key) => Ok(key.public_key().to_der()?),
            KeyInner::Symmetric(_) => Err(BackendError::InvalidKeyType),
        }
    }

    fn attributes(&self) -> HashMap<String, Vec<u8>> {
        let mut attrs = HashMap::new();
        
        if let Some(label) = &self.label {
            attrs.insert("CKA_LABEL".to_string(), label.as_bytes().to_vec());
        }
        
        if let Some(id) = &self.key_id {
            attrs.insert("CKA_ID".to_string(), id.clone());
        }
        
        attrs.insert("CKA_KEY_TYPE".to_string(), self.algorithm.to_pkcs11_key_type().to_le_bytes().to_vec());
        attrs.insert("CKA_CLASS".to_string(), self.key_type.to_pkcs11_class().to_le_bytes().to_vec());
        
        attrs
    }

    fn set_attribute(&mut self, name: &str, value: Vec<u8>) -> BackendResult<()> {
        match name {
            "CKA_LABEL" => {
                self.label = Some(String::from_utf8_lossy(&value).to_string());
                Ok(())
            }
            "CKA_ID" => {
                self.key_id = Some(value);
                Ok(())
            }
            _ => Err(BackendError::ReadOnlyAttribute(name.to_string())),
        }
    }

    fn fingerprint(&self) -> BackendResult<Vec<u8>> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        
        match &self.inner {
            KeyInner::Public(key) => hasher.update(key.to_der()?),
            KeyInner::Private(key) => hasher.update(key.public_key().to_der()?),
            KeyInner::Symmetric(key) => hasher.update(key.to_bytes()),
        }
        
        Ok(hasher.finalize().to_vec())
    }
}

#[derive(Debug)]
pub struct YourKeyPair {
    private_key: YourKey,
    public_key: YourKey,
}

impl KeyPair for YourKeyPair {
    type Key = YourKey;

    fn private_key(&self) -> &Self::Key {
        &self.private_key
    }

    fn public_key(&self) -> &Self::Key {
        &self.public_key
    }
}
```

### Step 4: Implement Operation Contexts

Create `src/contexts/sign.rs`:

```rust
use vtok_backend::traits::SignContext;
use vtok_backend::types::{BackendResult, Mechanism, ContextState, KeyAlgorithm};
use your_crypto_lib::Signer;
use crate::key::YourKey;

#[derive(Debug)]
pub struct YourSignContext {
    signer: Signer,
    mechanism: Mechanism,
    state: ContextState,
    bytes_processed: u64,
    key_algorithm: KeyAlgorithm,
    key_size: usize,
}

impl YourSignContext {
    pub fn new(mechanism: Mechanism, key: &YourKey) -> BackendResult<Self> {
        let signer = match &mechanism {
            Mechanism::RsaPkcs1 { digest } => {
                Signer::new_rsa_pkcs1(key.inner_private_key()?, digest.clone())?
            }
            Mechanism::Ecdsa { digest } => {
                Signer::new_ecdsa(key.inner_private_key()?, digest.clone())?
            }
            _ => return Err(BackendError::UnsupportedMechanism(format!("{:?}", mechanism))),
        };

        Ok(Self {
            signer,
            mechanism,
            state: ContextState::Active,
            bytes_processed: 0,
            key_algorithm: key.algorithm(),
            key_size: key.key_size(),
        })
    }
}

#[async_trait::async_trait]
impl SignContext for YourSignContext {
    fn mechanism(&self) -> &Mechanism {
        &self.mechanism
    }

    fn signature_size(&self) -> usize {
        self.signer.signature_size()
    }

    fn state(&self) -> ContextState {
        self.state
    }

    async fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        if self.state != ContextState::Active {
            return Err(BackendError::InvalidState);
        }

        self.signer.update(data)?;
        self.bytes_processed += data.len() as u64;
        Ok(())
    }

    async fn finalize(mut self) -> BackendResult<Vec<u8>> {
        if self.state != ContextState::Active {
            return Err(BackendError::ContextFinalized);
        }

        self.state = ContextState::Finalized;
        let signature = self.signer.finalize()?;
        Ok(signature)
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.key_algorithm
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}
```

### Step 5: Implement the Main Backend

Create `src/backend.rs`:

```rust
use std::sync::Arc;
use vtok_backend::traits::{CryptoBackend, Key, KeyPair, Certificate};
use vtok_backend::types::{
    BackendResult, KeyAlgorithm, KeyType, Mechanism, DigestAlgorithm,
    ContextConfig, BackendInfo, MechanismParams,
};
use crate::key::{YourKey, YourKeyPair};
use crate::contexts::{YourSignContext, YourVerifyContext, YourDigestContext};
use your_crypto_lib::CryptoProvider;

pub struct YourBackend {
    provider: Arc<CryptoProvider>,
    info: BackendInfo,
}

impl YourBackend {
    pub fn new() -> BackendResult<Self> {
        let provider = Arc::new(CryptoProvider::new()?);
        let info = BackendInfo {
            name: "YourCrypto Backend".to_string(),
            version: "1.0.0".to_string(),
            description: "PKCS#11 backend using YourCrypto library".to_string(),
            vendor: "Your Company".to_string(),
        };

        Ok(Self { provider, info })
    }
}

#[async_trait::async_trait]
impl CryptoBackend for YourBackend {
    type Key = YourKey;
    type KeyPair = YourKeyPair;
    type Certificate = YourCertificate;
    type DigestContext = YourDigestContext;
    type SignContext = YourSignContext;
    type VerifyContext = YourVerifyContext;
    type EncryptContext = YourEncryptContext;
    type DecryptContext = YourDecryptContext;

    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn supports_mechanism(&self, mechanism: &Mechanism) -> bool {
        match mechanism {
            Mechanism::RsaPkcs1 { .. } => true,
            Mechanism::Ecdsa { .. } => true,
            Mechanism::Sha256 => true,
            Mechanism::Sha384 => true,
            Mechanism::Sha512 => true,
            _ => false,
        }
    }

    fn supported_mechanisms(&self) -> Vec<Mechanism> {
        vec![
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) },
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha384) },
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha512) },
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) },
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha384) },
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha512) },
            Mechanism::Sha256,
            Mechanism::Sha384,
            Mechanism::Sha512,
        ]
    }

    fn supported_key_algorithms(&self) -> Vec<KeyAlgorithm> {
        vec![
            KeyAlgorithm::Rsa2048,
            KeyAlgorithm::Rsa3072,
            KeyAlgorithm::Rsa4096,
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdsaP384,
            KeyAlgorithm::EcdsaP521,
        ]
    }

    async fn generate_keypair(
        &self,
        algorithm: KeyAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair> {
        let keypair = match algorithm {
            KeyAlgorithm::Rsa2048 => self.provider.generate_rsa_keypair(2048)?,
            KeyAlgorithm::Rsa3072 => self.provider.generate_rsa_keypair(3072)?,
            KeyAlgorithm::Rsa4096 => self.provider.generate_rsa_keypair(4096)?,
            KeyAlgorithm::EcdsaP256 => self.provider.generate_ec_keypair("P-256")?,
            KeyAlgorithm::EcdsaP384 => self.provider.generate_ec_keypair("P-384")?,
            KeyAlgorithm::EcdsaP521 => self.provider.generate_ec_keypair("P-521")?,
            _ => return Err(BackendError::UnsupportedAlgorithm(format!("{:?}", algorithm))),
        };

        Ok(YourKeyPair::from_crypto_keypair(keypair, algorithm))
    }

    async fn create_sign_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::SignContext> {
        YourSignContext::new(mechanism, key)
    }

    async fn generate_random(&self, length: usize) -> BackendResult<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        self.provider.fill_random(&mut bytes)?;
        Ok(bytes)
    }

    // Implement other required methods...
}
```

### Step 6: Create the Provider Library

Create `src/lib.rs`:

```rust
//! YourCrypto PKCS#11 Provider
//! 
//! This crate provides a complete PKCS#11 implementation using YourCrypto
//! as the cryptographic backend.

mod backend;
mod key;
mod contexts;
mod error;

pub use backend::YourBackend;
pub use key::{YourKey, YourKeyPair};

use vtok_p11::VtokP11;
use std::sync::Arc;

/// Initialize the PKCS#11 provider with YourCrypto backend
pub fn initialize() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(YourBackend::new()?);
    VtokP11::initialize_with_backend(backend)?;
    Ok(())
}

/// Get provider information
pub fn provider_info() -> vtok_backend::types::BackendInfo {
    YourBackend::new().unwrap().info().clone()
}

// Export PKCS#11 C API functions
vtok_p11::export_pkcs11_api!();
```

### Step 7: Testing Your Backend

Create comprehensive tests in `tests/integration_tests.rs`:

```rust
use pkcs11_your_backend::{initialize, YourBackend};
use vtok_backend::traits::{CryptoBackend, SignContext};
use vtok_backend::types::{KeyAlgorithm, Mechanism, DigestAlgorithm};

#[tokio::test]
async fn test_key_generation() {
    let backend = YourBackend::new().unwrap();
    
    let keypair = backend.generate_keypair(KeyAlgorithm::Rsa2048, None).await.unwrap();
    assert_eq!(keypair.key_size(), 2048);
    assert_eq!(keypair.algorithm(), KeyAlgorithm::Rsa2048);
}

#[tokio::test]
async fn test_signing() {
    let backend = YourBackend::new().unwrap();
    
    let keypair = backend.generate_keypair(KeyAlgorithm::Rsa2048, None).await.unwrap();
    let mechanism = Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) };
    
    let sign_ctx = backend.create_sign_context(mechanism, keypair.private_key(), None).await.unwrap();
    let signature = sign_ctx.sign(b"test data").await.unwrap();
    
    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 256); // RSA-2048 signature size
}

#[tokio::test]
async fn test_pkcs11_compatibility() {
    initialize().unwrap();
    
    // Test basic PKCS#11 operations
    unsafe {
        let mut rv = vtok_p11::pkcs11::CK_RV::CKR_OK;
        
        // Initialize
        rv = vtok_p11::pkcs11::C_Initialize(std::ptr::null_mut());
        assert_eq!(rv, vtok_p11::pkcs11::CK_RV::CKR_OK);
        
        // Get slot list
        let mut slot_count = 0;
        rv = vtok_p11::pkcs11::C_GetSlotList(0, std::ptr::null_mut(), &mut slot_count);
        assert_eq!(rv, vtok_p11::pkcs11::CK_RV::CKR_OK);
        assert!(slot_count > 0);
        
        // Finalize
        rv = vtok_p11::pkcs11::C_Finalize(std::ptr::null_mut());
        assert_eq!(rv, vtok_p11::pkcs11::CK_RV::CKR_OK);
    }
}
```

## Advanced Implementation Topics

### Performance Optimization

1. **Memory Management**:
   ```rust
   // Use Arc for shared immutable data
   pub struct OptimizedKey {
       inner: Arc<CryptoKey>,
       metadata: KeyMetadata,
   }
   
   // Implement Clone efficiently
   impl Clone for OptimizedKey {
       fn clone(&self) -> Self {
           Self {
               inner: Arc::clone(&self.inner),
               metadata: self.metadata.clone(),
           }
       }
   }
   ```

2. **Async Operations**:
   ```rust
   // Use async for I/O-bound operations
   async fn generate_keypair_async(&self, algorithm: KeyAlgorithm) -> BackendResult<KeyPair> {
       tokio::task::spawn_blocking(move || {
           // CPU-intensive key generation
           self.crypto_provider.generate_keypair(algorithm)
       }).await?
   }
   ```

3. **Caching**:
   ```rust
   use std::collections::HashMap;
   use std::sync::RwLock;
   
   pub struct CachingBackend {
       cache: RwLock<HashMap<String, Arc<dyn Key>>>,
       inner: Box<dyn CryptoBackend>,
   }
   ```

### Error Handling Best Practices

1. **Comprehensive Error Types**:
   ```rust
   #[derive(Error, Debug)]
   pub enum DetailedError {
       #[error("Key generation failed: algorithm {algorithm:?}, size {size}")]
       KeyGeneration { algorithm: KeyAlgorithm, size: usize },
       
       #[error("Signature verification failed: expected {expected_size} bytes, got {actual_size}")]
       SignatureVerification { expected_size: usize, actual_size: usize },
       
       #[error("Hardware error: {device}: {message}")]
       Hardware { device: String, message: String },
   }
   ```

2. **Error Context**:
   ```rust
   use anyhow::{Context, Result};
   
   fn import_key(&self, data: &[u8]) -> Result<Key> {
       let parsed = parse_key_data(data)
           .context("Failed to parse key data")?;
       
       let key = self.crypto_provider.import_key(parsed)
           .context("Crypto provider failed to import key")?;
       
       Ok(key)
   }
   ```

### Security Considerations

1. **Memory Protection**:
   ```rust
   use zeroize::{Zeroize, ZeroizeOnDrop};
   
   #[derive(ZeroizeOnDrop)]
   pub struct SensitiveKey {
       #[zeroize(skip)]
       metadata: KeyMetadata,
       key_material: Vec<u8>,
   }
   ```

2. **Constant-Time Operations**:
   ```rust
   use subtle::ConstantTimeEq;
   
   fn verify_signature(&self, signature: &[u8], expected: &[u8]) -> bool {
       signature.ct_eq(expected).into()
   }
   ```

3. **Hardware Integration**:
   ```rust
   pub trait HardwareBackend: CryptoBackend {
       fn is_hardware_key(&self, key: &Self::Key) -> bool;
       fn hardware_info(&self) -> HardwareInfo;
       fn secure_delete(&self, key: &Self::Key) -> BackendResult<()>;
   }
   ```

## Testing and Validation

### Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vtok_backend::traits::*;
    
    #[tokio::test]
    async fn test_all_supported_algorithms() {
        let backend = YourBackend::new().unwrap();
        
        for algorithm in backend.supported_key_algorithms() {
            let keypair = backend.generate_keypair(algorithm, None).await;
            assert!(keypair.is_ok(), "Failed to generate {:?}", algorithm);
        }
    }
    
    #[tokio::test]
    async fn test_mechanism_compatibility() {
        let backend = YourBackend::new().unwrap();
        
        for mechanism in backend.supported_mechanisms() {
            assert!(backend.supports_mechanism(&mechanism));
        }
    }
}
```

### Integration Testing

```rust
#[tokio::test]
async fn test_cross_backend_compatibility() {
    // Test that keys generated by one backend can be used by another
    let backend1 = YourBackend::new().unwrap();
    let backend2 = AnotherBackend::new().unwrap();
    
    let keypair = backend1.generate_keypair(KeyAlgorithm::Rsa2048, None).await.unwrap();
    let exported = keypair.export_keypair().unwrap();
    
    let imported = backend2.import_keypair(
        KeyAlgorithm::Rsa2048,
        &exported.0,
        Some(&exported.1),
        None
    ).await.unwrap();
    
    // Verify compatibility
    assert_eq!(keypair.fingerprint().unwrap(), imported.fingerprint().unwrap());
}
```

### PKCS#11 Compliance Testing

```rust
use pkcs11_test_suite::*;

#[test]
fn test_pkcs11_compliance() {
    initialize().unwrap();
    
    let test_suite = Pkcs11TestSuite::new();
    let results = test_suite.run_all_tests();
    
    assert!(results.passed > 0);
    assert_eq!(results.failed, 0);
}
```

## Deployment and Distribution

### Building the Provider

```bash
# Build for development
cargo build

# Build optimized release
cargo build --release

# Build with specific features
cargo build --features "hardware-support,async-io"
```

### Installation

```bash
# Install the shared library
sudo cp target/release/libpkcs11_your_backend.so /usr/lib/pkcs11/

# Update PKCS#11 module configuration
echo "library=/usr/lib/pkcs11/libpkcs11_your_backend.so" >> ~/.config/pkcs11/modules/your_backend.module
```

### Configuration

Create a configuration file for your backend:

```json
{
  "backend": "your_backend",
  "version": "1.0.0",
  "settings": {
    "hardware_acceleration": true,
    "key_cache_size": 1000,
    "async_operations": true
  },
  "algorithms": {
    "rsa": {
      "min_key_size": 2048,
      "max_key_size": 4096
    },
    "ecdsa": {
      "supported_curves": ["P-256", "P-384", "P-521"]
    }
  }
}
```

## Maintenance and Updates

### Version Management

1. **Semantic Versioning**: Follow semver for API compatibility
2. **Migration Guides**: Provide upgrade paths between versions
3. **Deprecation Policy**: Give users time to migrate from deprecated features

### Monitoring and Logging

```rust
use log::{info, warn, error, debug};
use metrics::{counter, histogram, gauge};

impl CryptoBackend for YourBackend {
    async fn generate_keypair(&self, algorithm: KeyAlgorithm, config: Option<ContextConfig>) -> BackendResult<Self::KeyPair> {
        let start = std::time::Instant::now();
        
        info!("Generating keypair: algorithm={:?}", algorithm);
        counter!("keypair_generation_requests").increment(1);
        
        let result = self.inner_generate_keypair(algorithm, config).await;
        
        let duration = start.elapsed();
        histogram!("keypair_generation_duration").record(duration.as_millis() as f64);
        
        match &result {
            Ok(_) => {
                info!("Keypair generation successful: algorithm={:?}, duration={:?}", algorithm, duration);
                counter!("keypair_generation_success").increment(1);
            }
            Err(e) => {
                error!("Keypair generation failed: algorithm={:?}, error={}", algorithm, e);
                counter!("keypair_generation_errors").increment(1);
            }
        }
        
        result
    }
}
```

This comprehensive guide provides the foundation for implementing robust, secure, and performant cryptographic backends for the vtok_p11 modular architecture. Follow these patterns and best practices to create backends that integrate seamlessly with the existing ecosystem while providing the specific cryptographic capabilities your use case requires.