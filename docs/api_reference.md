# vtok_backend API Reference

## Overview

This document provides a comprehensive reference for the `vtok_backend` crate, which defines the core abstraction layer for the modular vtok_p11 architecture. The API is designed to be extensible, type-safe, and performant while providing a clean interface for implementing cryptographic backends.

## Table of Contents

1. [Core Traits](#core-traits)
2. [Type Definitions](#type-definitions)
3. [Error Handling](#error-handling)
4. [Usage Examples](#usage-examples)
5. [Implementation Guidelines](#implementation-guidelines)

## Core Traits

### CryptoBackend

The main trait that all cryptographic backends must implement.

```rust
pub trait CryptoBackend: Send + Sync + 'static {
    type Key: Key;
    type KeyPair: KeyPair<Key = Self::Key>;
    type Certificate: Certificate<Key = Self::Key>;
    type DigestContext: DigestContext;
    type SignContext: SignContext;
    type VerifyContext: VerifyContext;
    type EncryptContext: EncryptContext;
    type DecryptContext: DecryptContext;

    // Core methods
    fn info(&self) -> &BackendInfo;
    fn supports_mechanism(&self, mechanism: &Mechanism) -> bool;
    fn supported_mechanisms(&self) -> Vec<Mechanism>;
    fn supported_key_algorithms(&self) -> Vec<KeyAlgorithm>;

    // Lifecycle methods
    async fn initialize(&self) -> BackendResult<()>;
    async fn finalize(&self) -> BackendResult<()>;

    // Key management
    async fn generate_keypair(
        &self,
        algorithm: KeyAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair>;

    async fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key>;

    async fn import_key(
        &self,
        key_type: KeyType,
        algorithm: KeyAlgorithm,
        key_data: &[u8],
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key>;

    async fn import_keypair(
        &self,
        algorithm: KeyAlgorithm,
        private_key_data: &[u8],
        public_key_data: Option<&[u8]>,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair>;

    async fn import_certificate(
        &self,
        cert_data: &[u8],
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Certificate>;

    // Context creation
    async fn create_digest_context(
        &self,
        algorithm: DigestAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::DigestContext>;

    async fn create_sign_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::SignContext>;

    async fn create_verify_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::VerifyContext>;

    async fn create_encrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::EncryptContext>;

    async fn create_decrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::DecryptContext>;

    // Utility methods
    async fn generate_random(&self, length: usize) -> BackendResult<Vec<u8>>;
    
    async fn derive_key(
        &self,
        mechanism: Mechanism,
        base_key: &Self::Key,
        params: &MechanismParams,
        target_algorithm: KeyAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key>;

    async fn key_agreement(
        &self,
        mechanism: Mechanism,
        private_key: &Self::Key,
        public_key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Vec<u8>>;

    // Key size limits
    fn max_key_size(&self, algorithm: KeyAlgorithm) -> Option<usize>;
    fn min_key_size(&self, algorithm: KeyAlgorithm) -> usize;
}
```

#### Key Methods

- **`info()`**: Returns backend information including name, version, and description
- **`supports_mechanism()`**: Check if a specific mechanism is supported
- **`supported_mechanisms()`**: Get list of all supported mechanisms
- **`supported_key_algorithms()`**: Get list of all supported key algorithms

#### Lifecycle Methods

- **`initialize()`**: One-time backend initialization (optional)
- **`finalize()`**: Backend cleanup when no longer needed

#### Key Management

- **`generate_keypair()`**: Generate a new asymmetric key pair
- **`generate_key()`**: Generate a new symmetric key
- **`import_key()`**: Import a key from raw bytes
- **`import_keypair()`**: Import an asymmetric key pair
- **`import_certificate()`**: Import an X.509 certificate

#### Context Creation

- **`create_digest_context()`**: Create a context for hashing operations
- **`create_sign_context()`**: Create a context for signing operations
- **`create_verify_context()`**: Create a context for verification operations
- **`create_encrypt_context()`**: Create a context for encryption operations
- **`create_decrypt_context()`**: Create a context for decryption operations

### Key

Trait representing a cryptographic key.

```rust
pub trait Key: Send + Sync + std::fmt::Debug {
    // Basic properties
    fn algorithm(&self) -> KeyAlgorithm;
    fn key_type(&self) -> KeyType;
    fn key_size(&self) -> usize;
    fn key_id(&self) -> Option<&[u8]>;
    fn label(&self) -> Option<&str>;
    fn usage(&self) -> KeyUsage;

    // Capability checks
    fn can_sign(&self) -> bool;
    fn can_verify(&self) -> bool;
    fn can_encrypt(&self) -> bool;
    fn can_decrypt(&self) -> bool;
    fn can_derive(&self) -> bool;
    fn can_wrap(&self) -> bool;
    fn can_unwrap(&self) -> bool;

    // Security properties
    fn is_extractable(&self) -> bool;
    fn is_sensitive(&self) -> bool;
    fn is_hardware(&self) -> bool;
    fn is_token(&self) -> bool;

    // Key export
    fn export_key(&self) -> BackendResult<Vec<u8>>;
    fn export_public_key(&self) -> BackendResult<Vec<u8>>;
    fn export_standard_format(&self) -> BackendResult<Vec<u8>>;

    // Attributes
    fn attributes(&self) -> HashMap<String, Vec<u8>>;
    fn set_attribute(&mut self, name: &str, value: Vec<u8>) -> BackendResult<()>;
    fn get_attribute(&self, name: &str) -> Option<Vec<u8>>;
    fn has_attribute(&self, name: &str) -> bool;

    // Utilities
    fn fingerprint(&self) -> BackendResult<Vec<u8>>;
    fn clone_key(&self) -> BackendResult<Box<dyn Key>>;
}
```

#### Key Properties

- **`algorithm()`**: Get the key algorithm (RSA, ECDSA, AES, etc.)
- **`key_type()`**: Get the key type (Public, Private, Secret)
- **`key_size()`**: Get the key size in bits
- **`key_id()`**: Get the key identifier (if any)
- **`label()`**: Get the key label (if any)
- **`usage()`**: Get the key usage flags

#### Capability Checks

- **`can_sign()`**: Check if key can be used for signing
- **`can_verify()`**: Check if key can be used for verification
- **`can_encrypt()`**: Check if key can be used for encryption
- **`can_decrypt()`**: Check if key can be used for decryption
- **`can_derive()`**: Check if key can be used for key derivation
- **`can_wrap()`**: Check if key can be used for key wrapping
- **`can_unwrap()`**: Check if key can be used for key unwrapping

### KeyPair

Trait representing an asymmetric key pair.

```rust
pub trait KeyPair: Send + Sync + std::fmt::Debug {
    type Key: Key;

    fn private_key(&self) -> &Self::Key;
    fn public_key(&self) -> &Self::Key;
    fn algorithm(&self) -> KeyAlgorithm;
    fn key_size(&self) -> usize;
    fn key_id(&self) -> Option<&[u8]>;
    fn label(&self) -> Option<&str>;

    // Export methods
    fn export_public_key_info(&self) -> BackendResult<Vec<u8>>;
    fn export_private_key_info(&self) -> BackendResult<Vec<u8>>;
    fn export_keypair(&self) -> BackendResult<(Vec<u8>, Vec<u8>)>;

    // Utilities
    fn fingerprint(&self) -> BackendResult<Vec<u8>>;
    fn is_private_extractable(&self) -> bool;
    fn is_private_sensitive(&self) -> bool;
    fn is_hardware(&self) -> bool;
}
```

### SignContext

Trait for digital signature operations.

```rust
pub trait SignContext: Send + Sync + std::fmt::Debug {
    // Context properties
    fn mechanism(&self) -> &Mechanism;
    fn signature_size(&self) -> usize;
    fn state(&self) -> ContextState;

    // Core operations
    async fn update(&mut self, data: &[u8]) -> BackendResult<()>;
    async fn finalize(self) -> BackendResult<Vec<u8>>;
    async fn sign(mut self, data: &[u8]) -> BackendResult<Vec<u8>>;

    // Progress tracking
    fn bytes_processed(&self) -> u64;
    fn progress(&self) -> OperationProgress;

    // Capabilities
    fn supports_incremental(&self) -> bool;
    fn supports_single_part(&self) -> bool;
    fn key_algorithm(&self) -> KeyAlgorithm;
    fn key_size(&self) -> usize;

    // Advanced operations
    async fn reset(&mut self) -> BackendResult<()>;
    fn supports_reset(&self) -> bool;
    async fn update_chunks<'a, I>(&mut self, chunks: I) -> BackendResult<()>;

    // Mechanism information
    fn mechanism_params(&self) -> HashMap<String, Vec<u8>>;
    fn set_mechanism_params(&mut self, params: HashMap<String, Vec<u8>>) -> BackendResult<()>;
    fn max_data_size(&self) -> Option<usize>;
    fn is_valid_data_size(&self, data_size: usize) -> bool;
    fn digest_algorithm(&self) -> Option<DigestAlgorithm>;
    fn is_recoverable(&self) -> bool;
    fn signature_format(&self) -> SignatureFormat;
}
```

### VerifyContext

Trait for signature verification operations.

```rust
pub trait VerifyContext: Send + Sync + std::fmt::Debug {
    // Context properties
    fn mechanism(&self) -> &Mechanism;
    fn signature_size(&self) -> usize;
    fn state(&self) -> ContextState;

    // Core operations
    async fn update(&mut self, data: &[u8]) -> BackendResult<()>;
    async fn finalize(self, signature: &[u8]) -> BackendResult<bool>;
    async fn verify(mut self, data: &[u8], signature: &[u8]) -> BackendResult<bool>;

    // Progress tracking
    fn bytes_processed(&self) -> u64;
    fn progress(&self) -> OperationProgress;

    // Capabilities
    fn supports_incremental(&self) -> bool;
    fn supports_single_part(&self) -> bool;
    fn key_algorithm(&self) -> KeyAlgorithm;
    fn key_size(&self) -> usize;

    // Advanced operations
    async fn reset(&mut self) -> BackendResult<()>;
    fn supports_reset(&self) -> bool;
    async fn update_chunks<'a, I>(&mut self, chunks: I) -> BackendResult<()>;
    async fn verify_recover(self, signature: &[u8]) -> BackendResult<Vec<u8>>;

    // Mechanism information
    fn mechanism_params(&self) -> HashMap<String, Vec<u8>>;
    fn set_mechanism_params(&mut self, params: HashMap<String, Vec<u8>>) -> BackendResult<()>;
    fn max_data_size(&self) -> Option<usize>;
    fn is_valid_data_size(&self, data_size: usize) -> bool;
    fn digest_algorithm(&self) -> Option<DigestAlgorithm>;
    fn is_recoverable(&self) -> bool;
    fn signature_format(&self) -> SignatureFormat;
}
```

## Type Definitions

### KeyAlgorithm

Enumeration of supported key algorithms.

```rust
pub enum KeyAlgorithm {
    // RSA algorithms
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Rsa8192,
    
    // ECDSA algorithms
    EcdsaP224,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EcdsaSecp256k1,
    
    // Symmetric algorithms
    Aes128,
    Aes192,
    Aes256,
    ChaCha20,
    
    // EdDSA and key agreement
    Ed25519,
    X25519,
}
```

#### Methods

- **`key_size_bits()`**: Get key size in bits
- **`key_size_bytes()`**: Get key size in bytes
- **`is_rsa()`**: Check if this is an RSA algorithm
- **`is_ecdsa()`**: Check if this is an ECDSA algorithm
- **`is_symmetric()`**: Check if this is a symmetric algorithm
- **`is_asymmetric()`**: Check if this is an asymmetric algorithm
- **`is_eddsa()`**: Check if this is an EdDSA algorithm
- **`is_key_agreement()`**: Check if this is a key agreement algorithm
- **`curve_name()`**: Get curve name for ECDSA algorithms
- **`name()`**: Get algorithm name as string

### Mechanism

Enumeration of cryptographic mechanisms.

```rust
pub enum Mechanism {
    // Digest mechanisms
    Digest(DigestAlgorithm),
    
    // RSA mechanisms
    RsaPkcs1 { digest: Option<DigestAlgorithm> },
    RsaPkcs1Pss { digest: DigestAlgorithm, mgf: DigestAlgorithm, salt_len: usize },
    RsaOaep { hash: DigestAlgorithm, mgf: DigestAlgorithm, label: Option<Vec<u8>> },
    RsaX509,
    
    // ECDSA mechanisms
    Ecdsa { digest: Option<DigestAlgorithm> },
    EdDsa,
    
    // Symmetric mechanisms
    Aes { mode: AesMode, key_size: usize },
    ChaCha20,
    ChaCha20Poly1305,
    
    // MAC mechanisms
    Hmac { hash: DigestAlgorithm },
    
    // Key derivation
    Kdf { algorithm: KdfAlgorithm },
    
    // Key agreement
    Ecdh,
    X25519,
}
```

#### Methods

- **`name()`**: Get mechanism name as string
- **`is_sign_mechanism()`**: Check if this is a signing mechanism
- **`is_encrypt_mechanism()`**: Check if this is an encryption mechanism
- **`is_digest_mechanism()`**: Check if this is a digest mechanism
- **`is_kdf_mechanism()`**: Check if this is a key derivation mechanism
- **`is_key_agreement_mechanism()`**: Check if this is a key agreement mechanism
- **`supports_key_algorithm()`**: Check if mechanism supports a key algorithm
- **`output_size()`**: Get expected output size (if applicable)

### DigestAlgorithm

Enumeration of hash algorithms.

```rust
pub enum DigestAlgorithm {
    // SHA family
    Sha1,           // Deprecated
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    
    // SHA-3 family
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    
    // BLAKE2 family
    Blake2b256,
    Blake2b512,
    Blake2s256,
    
    // Legacy
    Md5,            // Deprecated
}
```

#### Methods

- **`output_size()`**: Get hash output size in bytes
- **`name()`**: Get algorithm name as string
- **`is_secure()`**: Check if algorithm is considered secure

### KeyType

Enumeration of key types.

```rust
pub enum KeyType {
    Public,     // Public key
    Private,    // Private key
    Secret,     // Symmetric key
}
```

#### Methods

- **`is_public()`**: Check if this is a public key
- **`is_private()`**: Check if this is a private key
- **`is_secret()`**: Check if this is a symmetric key
- **`name()`**: Get key type name as string

### KeyUsage

Structure defining key usage flags.

```rust
pub struct KeyUsage {
    pub sign: bool,
    pub verify: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub derive: bool,
    pub wrap: bool,
    pub unwrap: bool,
}
```

#### Methods

- **`all()`**: Create KeyUsage with all operations allowed
- **`sign_verify()`**: Create KeyUsage for signing operations
- **`encrypt_decrypt()`**: Create KeyUsage for encryption operations
- **`derive_only()`**: Create KeyUsage for key derivation only
- **`has_any_usage()`**: Check if any usage is allowed

### ContextState

Enumeration of operation context states.

```rust
pub enum ContextState {
    Initialized,        // Context created but no operations performed
    SinglePartActive,   // Single-part operation active
    MultiPartActive,    // Multi-part operation active
    MultiPartReady,     // Multi-part operation ready for finalization
    Finalized,          // Context finalized
}
```

#### Methods

- **`can_update()`**: Check if context can accept new data
- **`can_finalize()`**: Check if context can be finalized
- **`is_finalized()`**: Check if context is finalized
- **`can_single_part()`**: Check if single-part operation can be performed

## Error Handling

### BackendError

Comprehensive error type for backend operations.

```rust
pub enum BackendError {
    // General errors
    General(String),
    UnsupportedAlgorithm(String),
    UnsupportedMechanism(String),
    UnsupportedOperation(String),
    
    // Key errors
    KeyGeneration(String),
    KeyDerivation(String),
    InvalidKeyData(String),
    InvalidKey(String),
    KeyNotExtractable,
    KeySensitive,
    
    // Certificate errors
    InvalidCertificate(String),
    
    // Operation errors
    DigestOperation(String),
    DigestUpdate(String),
    DigestFinalize(String),
    SignOperation(String),
    VerifyOperation(String),
    EncryptOperation(String),
    DecryptOperation(String),
    RandomGeneration(String),
    
    // Context errors
    ContextFinalized,
    OperationActive,
    InvalidState(String),
    InvalidParameters(String),
    
    // Data errors
    BufferTooSmall { required: usize, provided: usize },
    InvalidDataLength(String),
    ReadOnlyAttribute(String),
    
    // System errors
    InitializationFailed(String),
    NotInitialized,
    HardwareError(String),
    IoError(String),
    Timeout,
    OutOfMemory,
    Internal(String),
    
    // Testing
    MockError(String),
}
```

#### Convenience Methods

- **`general()`**: Create a general error
- **`unsupported_algorithm()`**: Create an unsupported algorithm error
- **`unsupported_mechanism()`**: Create an unsupported mechanism error
- **`key_generation()`**: Create a key generation error
- **`invalid_key()`**: Create an invalid key error
- **`digest_operation()`**: Create a digest operation error
- **`sign_operation()`**: Create a sign operation error
- **`verify_operation()`**: Create a verify operation error
- **`encrypt_operation()`**: Create an encrypt operation error
- **`decrypt_operation()`**: Create a decrypt operation error
- **`internal()`**: Create an internal error
- **`mock_error()`**: Create a mock error (for testing)

### BackendResult

Type alias for backend operation results.

```rust
pub type BackendResult<T> = Result<T, BackendError>;
```

## Usage Examples

### Basic Backend Implementation

```rust
use vtok_backend::traits::CryptoBackend;
use vtok_backend::types::*;

struct MyBackend {
    // Backend state
}

#[async_trait::async_trait]
impl CryptoBackend for MyBackend {
    type Key = MyKey;
    type KeyPair = MyKeyPair;
    type Certificate = MyCertificate;
    type DigestContext = MyDigestContext;
    type SignContext = MySignContext;
    type VerifyContext = MyVerifyContext;
    type EncryptContext = MyEncryptContext;
    type DecryptContext = MyDecryptContext;

    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn supports_mechanism(&self, mechanism: &Mechanism) -> bool {
        match mechanism {
            Mechanism::RsaPkcs1 { .. } => true,
            Mechanism::Ecdsa { .. } => true,
            Mechanism::Digest(_) => true,
            _ => false,
        }
    }

    async fn generate_keypair(
        &self,
        algorithm: KeyAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair> {
        match algorithm {
            KeyAlgorithm::Rsa2048 => {
                // Generate RSA-2048 key pair
                Ok(self.generate_rsa_keypair(2048)?)
            }
            KeyAlgorithm::EcdsaP256 => {
                // Generate ECDSA P-256 key pair
                Ok(self.generate_ecdsa_keypair("P-256")?)
            }
            _ => Err(BackendError::unsupported_algorithm(format!("{:?}", algorithm))),
        }
    }

    // Implement other required methods...
}
```

### Signing Operation

```rust
use vtok_backend::traits::{CryptoBackend, SignContext};
use vtok_backend::types::*;

async fn sign_data<B: CryptoBackend>(
    backend: &B,
    key: &B::Key,
    data: &[u8],
) -> BackendResult<Vec<u8>> {
    let mechanism = Mechanism::RsaPkcs1 {
        digest: Some(DigestAlgorithm::Sha256),
    };
    
    let sign_ctx = backend.create_sign_context(mechanism, key, None).await?;
    let signature = sign_ctx.sign(data).await?;
    
    Ok(signature)
}
```

### Multi-part Signing

```rust
async fn sign_large_data<B: CryptoBackend>(
    backend: &B,
    key: &B::Key,
    data_chunks: Vec<&[u8]>,
) -> BackendResult<Vec<u8>> {
    let mechanism = Mechanism::RsaPkcs1 {
        digest: Some(DigestAlgorithm::Sha256),
    };
    
    let mut sign_ctx = backend.create_sign_context(mechanism, key, None).await?;
    
    for chunk in data_chunks {
        sign_ctx.update(chunk).await?;
    }
    
    let signature = sign_ctx.finalize().await?;
    Ok(signature)
}
```

### Key Generation with Configuration

```rust
async fn generate_configured_keypair<B: CryptoBackend>(
    backend: &B,
) -> BackendResult<B::KeyPair> {
    let config = ContextConfig::new()
        .with_attribute("CKA_LABEL", b"My Key".to_vec())
        .with_attribute("CKA_ID", b"key-001".to_vec())
        .with_hardware(true);
    
    let keypair = backend.generate_keypair(
        KeyAlgorithm::EcdsaP256,
        Some(config),
    ).await?;
    
    Ok(keypair)
}
```

### Error Handling

```rust
async fn safe_operation<B: CryptoBackend>(
    backend: &B,
) -> Result<(), Box<dyn std::error::Error>> {
    match backend.generate_keypair(KeyAlgorithm::Rsa2048, None).await {
        Ok(keypair) => {
            println!("Generated keypair: {}", keypair.algorithm());
            Ok(())
        }
        Err(BackendError::UnsupportedAlgorithm(alg)) => {
            eprintln!("Algorithm not supported: {}", alg);
            Err(format!("Unsupported algorithm: {}", alg).into())
        }
        Err(BackendError::KeyGeneration(msg)) => {
            eprintln!("Key generation failed: {}", msg);
            Err(format!("Key generation failed: {}", msg).into())
        }
        Err(e) => {
            eprintln!("Unexpected error: {}", e);
            Err(e.into())
        }
    }
}
```

## Implementation Guidelines

### Thread Safety

All trait implementations must be thread-safe (`Send + Sync`):

```rust
// ✅ Good - thread-safe implementation
#[derive(Debug)]
pub struct ThreadSafeKey {
    inner: Arc<CryptoKey>,
    metadata: KeyMetadata,
}

unsafe impl Send for ThreadSafeKey {}
unsafe impl Sync for ThreadSafeKey {}

// ❌ Bad - not thread-safe
#[derive(Debug)]
pub struct UnsafeKey {
    inner: Rc<CryptoKey>,  // Rc is not Send/Sync
    metadata: KeyMetadata,
}
```

### Error Handling

Use appropriate error types and provide context:

```rust
// ✅ Good - specific error with context
fn parse_key_data(data: &[u8]) -> BackendResult<ParsedKey> {
    if data.len() < 32 {
        return Err(BackendError::InvalidKeyData(
            format!("Key data too short: {} bytes, minimum 32", data.len())
        ));
    }
    
    // Parse key...
    Ok(parsed_key)
}

// ❌ Bad - generic error without context
fn parse_key_data(data: &[u8]) -> BackendResult<ParsedKey> {
    if data.len() < 32 {
        return Err(BackendError::General("Invalid key".to_string()));
    }
    
    // Parse key...
    Ok(parsed_key)
}
```

### Memory Management

Handle sensitive data securely:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct SensitiveKey {
    #[zeroize(skip)]
    metadata: KeyMetadata,
    key_material: Vec<u8>,  // Will be zeroed on drop
}

impl Drop for SensitiveKey {
    fn drop(&mut self) {
        // Additional cleanup if needed
    }
}
```

### Performance Considerations

Use efficient data structures and minimize allocations:

```rust
// ✅ Good - reuse buffers
pub struct EfficientContext {
    buffer: Vec<u8>,
    hasher: Sha256,
}

impl EfficientContext {
    pub async fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        // Reuse internal buffer
        self.hasher.update(data);
        Ok(())
    }
}

// ❌ Bad - allocate on every call
pub struct InefficientContext {
    hasher: Sha256,
}

impl InefficientContext {
    pub async fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        let mut buffer = Vec::new();  // New allocation every time
        buffer.extend_from_slice(data);
        self.hasher.update(&buffer);
        Ok(())
    }
}
```

### Testing

Implement comprehensive tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_key_generation() {
        let backend = MyBackend::new().unwrap();
        
        for algorithm in backend.supported_key_algorithms() {
            let result = backend.generate_keypair(algorithm, None).await;
            assert!(result.is_ok(), "Failed to generate {:?}", algorithm);
            
            let keypair = result.unwrap();
            assert_eq!(keypair.algorithm(), algorithm);
            assert!(keypair.key_size() > 0);
        }
    }
    
    #[tokio::test]
    async fn test_signing_verification() {
        let backend = MyBackend::new().unwrap();
        let keypair = backend.generate_keypair(KeyAlgorithm::EcdsaP256, None).await.unwrap();
        
        let data = b"test message";
        let mechanism = Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) };
        
        // Sign
        let sign_ctx = backend.create_sign_context(mechanism.clone(), keypair.private_key(), None).await.unwrap();
        let signature = sign_ctx.sign(data).await.unwrap();
        
        // Verify
        let verify_ctx = backend.create_verify_context(mechanism, keypair.public_key(), None).await.unwrap();
        let is_valid = verify_ctx.verify(data, &signature).await.unwrap();
        
        assert!(is_valid);
    }
}
```

This API reference provides the foundation for implementing robust, secure, and performant cryptographic backends for the vtok_p11 modular architecture.