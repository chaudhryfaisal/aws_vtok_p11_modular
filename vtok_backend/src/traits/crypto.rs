//! Main CryptoBackend trait definition.
//!
//! This module defines the primary trait that all crypto backends must implement.
//! The CryptoBackend trait serves as the main entry point for all cryptographic
//! operations and provides factory methods for creating operation contexts.

use std::sync::Arc;
use crate::types::{
    BackendError, BackendResult, KeyAlgorithm, KeyType, Mechanism,
    DigestAlgorithm, MechanismParams, ContextConfig,
};
use crate::traits::{
    Key, KeyPair, Certificate, DigestContext, SignContext, VerifyContext,
    EncryptContext, DecryptContext,
};
use crate::BackendInfo;

/// Main trait that all crypto backends must implement.
///
/// This trait provides the primary interface for cryptographic operations
/// and serves as a factory for creating operation-specific contexts.
/// All methods are designed to be thread-safe and can be called concurrently.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple PKCS#11 sessions.
///
/// # Example
///
/// ```rust
/// use vtok_backend::traits::{CryptoBackend, KeyPair};
/// use vtok_backend::types::{KeyAlgorithm, Mechanism, DigestAlgorithm};
///
/// async fn example_usage<B: CryptoBackend>(backend: &B) -> Result<(), Box<dyn std::error::Error>> {
///     // Generate a key pair
///     let keypair = backend.generate_keypair(KeyAlgorithm::EcdsaP256, None).await?;
///
///     // Create a signing context
///     let sign_ctx = backend.create_sign_context(
///         Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) },
///         keypair.private_key(),
///         None
///     ).await?;
///
///     Ok(())
/// }
/// ```
pub trait CryptoBackend: Send + Sync + 'static {
    /// Key type used by this backend
    type Key: Key;
    /// KeyPair type used by this backend
    type KeyPair: KeyPair<Key = Self::Key>;
    /// Certificate type used by this backend
    type Certificate: Certificate<Key = Self::Key>;
    /// Digest context type used by this backend
    type DigestContext: DigestContext;
    /// Sign context type used by this backend
    type SignContext: SignContext;
    /// Verify context type used by this backend
    type VerifyContext: VerifyContext;
    /// Encrypt context type used by this backend
    type EncryptContext: EncryptContext;
    /// Decrypt context type used by this backend
    type DecryptContext: DecryptContext;

    /// Get backend information
    fn info(&self) -> &BackendInfo;

    /// Check if a mechanism is supported by this backend
    fn supports_mechanism(&self, mechanism: &Mechanism) -> bool;

    /// Get list of supported mechanisms
    fn supported_mechanisms(&self) -> Vec<Mechanism>;

    /// Get list of supported key algorithms
    fn supported_key_algorithms(&self) -> Vec<KeyAlgorithm>;

    /// Initialize the backend (if needed)
    ///
    /// This method is called once when the backend is first used.
    /// Implementations can use this for one-time setup operations.
    ///
    /// # Errors
    ///
    /// Returns `BackendError::InitializationFailed` if initialization fails.
    async fn initialize(&self) -> BackendResult<()> {
        Ok(())
    }

    /// Finalize the backend (cleanup)
    ///
    /// This method is called when the backend is no longer needed.
    /// Implementations should clean up any resources.
    async fn finalize(&self) -> BackendResult<()> {
        Ok(())
    }

    /// Generate a new key pair
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key algorithm to use for generation
    /// * `config` - Optional configuration for key generation
    ///
    /// # Returns
    ///
    /// A new key pair of the specified algorithm
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedAlgorithm` if the algorithm is not supported.
    /// Returns `BackendError::KeyGeneration` if key generation fails.
    async fn generate_keypair(
        &self,
        algorithm: KeyAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair>;

    /// Generate a symmetric key
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key algorithm to use for generation
    /// * `config` - Optional configuration for key generation
    ///
    /// # Returns
    ///
    /// A new symmetric key of the specified algorithm
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedAlgorithm` if the algorithm is not supported.
    /// Returns `BackendError::KeyGeneration` if key generation fails.
    async fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key>;

    /// Import a key from raw bytes
    ///
    /// # Arguments
    ///
    /// * `key_type` - The type of key being imported
    /// * `algorithm` - The key algorithm
    /// * `key_data` - The raw key material
    /// * `config` - Optional configuration for key import
    ///
    /// # Returns
    ///
    /// The imported key
    ///
    /// # Errors
    ///
    /// Returns `BackendError::InvalidKeyData` if the key data is invalid.
    /// Returns `BackendError::UnsupportedAlgorithm` if the algorithm is not supported.
    async fn import_key(
        &self,
        key_type: KeyType,
        algorithm: KeyAlgorithm,
        key_data: &[u8],
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key>;

    /// Import a key pair from raw bytes
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key algorithm
    /// * `private_key_data` - The private key material
    /// * `public_key_data` - Optional public key material (can be derived if None)
    /// * `config` - Optional configuration for key import
    ///
    /// # Returns
    ///
    /// The imported key pair
    ///
    /// # Errors
    ///
    /// Returns `BackendError::InvalidKeyData` if the key data is invalid.
    /// Returns `BackendError::UnsupportedAlgorithm` if the algorithm is not supported.
    async fn import_keypair(
        &self,
        algorithm: KeyAlgorithm,
        private_key_data: &[u8],
        public_key_data: Option<&[u8]>,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair>;

    /// Import a certificate
    ///
    /// # Arguments
    ///
    /// * `cert_data` - The certificate data (typically DER or PEM encoded)
    /// * `config` - Optional configuration for certificate import
    ///
    /// # Returns
    ///
    /// The imported certificate
    ///
    /// # Errors
    ///
    /// Returns `BackendError::InvalidCertificate` if the certificate data is invalid.
    async fn import_certificate(
        &self,
        cert_data: &[u8],
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Certificate>;

    /// Create a digest context for hashing operations
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The digest algorithm to use
    /// * `config` - Optional configuration for the digest context
    ///
    /// # Returns
    ///
    /// A new digest context
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedAlgorithm` if the algorithm is not supported.
    async fn create_digest_context(
        &self,
        algorithm: DigestAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::DigestContext>;

    /// Create a signing context
    ///
    /// # Arguments
    ///
    /// * `mechanism` - The signing mechanism to use
    /// * `key` - The private key to use for signing
    /// * `config` - Optional configuration for the signing context
    ///
    /// # Returns
    ///
    /// A new signing context
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedMechanism` if the mechanism is not supported.
    /// Returns `BackendError::InvalidKey` if the key is not suitable for signing.
    async fn create_sign_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::SignContext>;

    /// Create a verification context
    ///
    /// # Arguments
    ///
    /// * `mechanism` - The verification mechanism to use
    /// * `key` - The public key to use for verification
    /// * `config` - Optional configuration for the verification context
    ///
    /// # Returns
    ///
    /// A new verification context
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedMechanism` if the mechanism is not supported.
    /// Returns `BackendError::InvalidKey` if the key is not suitable for verification.
    async fn create_verify_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::VerifyContext>;

    /// Create an encryption context
    ///
    /// # Arguments
    ///
    /// * `mechanism` - The encryption mechanism to use
    /// * `key` - The key to use for encryption
    /// * `config` - Optional configuration for the encryption context
    ///
    /// # Returns
    ///
    /// A new encryption context
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedMechanism` if the mechanism is not supported.
    /// Returns `BackendError::InvalidKey` if the key is not suitable for encryption.
    async fn create_encrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::EncryptContext>;

    /// Create a decryption context
    ///
    /// # Arguments
    ///
    /// * `mechanism` - The decryption mechanism to use
    /// * `key` - The key to use for decryption
    /// * `config` - Optional configuration for the decryption context
    ///
    /// # Returns
    ///
    /// A new decryption context
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedMechanism` if the mechanism is not supported.
    /// Returns `BackendError::InvalidKey` if the key is not suitable for decryption.
    async fn create_decrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::DecryptContext>;

    /// Generate random bytes
    ///
    /// # Arguments
    ///
    /// * `length` - Number of random bytes to generate
    ///
    /// # Returns
    ///
    /// A vector containing the random bytes
    ///
    /// # Errors
    ///
    /// Returns `BackendError::RandomGeneration` if random generation fails.
    async fn generate_random(&self, length: usize) -> BackendResult<Vec<u8>>;

    /// Derive a key using a key derivation function
    ///
    /// # Arguments
    ///
    /// * `mechanism` - The key derivation mechanism
    /// * `base_key` - The base key for derivation
    /// * `params` - Derivation parameters
    /// * `target_algorithm` - The algorithm for the derived key
    /// * `config` - Optional configuration for key derivation
    ///
    /// # Returns
    ///
    /// The derived key
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedMechanism` if the mechanism is not supported.
    /// Returns `BackendError::KeyDerivation` if derivation fails.
    async fn derive_key(
        &self,
        mechanism: Mechanism,
        base_key: &Self::Key,
        params: &MechanismParams,
        target_algorithm: KeyAlgorithm,
        config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key>;

    /// Perform key agreement (e.g., ECDH)
    ///
    /// # Arguments
    ///
    /// * `mechanism` - The key agreement mechanism
    /// * `private_key` - Our private key
    /// * `public_key` - The other party's public key
    /// * `config` - Optional configuration for key agreement
    ///
    /// # Returns
    ///
    /// The shared secret
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedMechanism` if the mechanism is not supported.
    /// Returns `BackendError::InvalidKey` if the keys are not suitable for key agreement.
    async fn key_agreement(
        &self,
        mechanism: Mechanism,
        private_key: &Self::Key,
        public_key: &Self::Key,
        config: Option<ContextConfig>,
    ) -> BackendResult<Vec<u8>>;

    /// Get the maximum supported key size for an algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key algorithm
    ///
    /// # Returns
    ///
    /// Maximum key size in bits, or None if unlimited/unknown
    fn max_key_size(&self, algorithm: KeyAlgorithm) -> Option<usize> {
        // Default implementation based on common limits
        match algorithm {
            KeyAlgorithm::Rsa1024 => Some(1024),
            KeyAlgorithm::Rsa2048 => Some(2048),
            KeyAlgorithm::Rsa3072 => Some(3072),
            KeyAlgorithm::Rsa4096 => Some(4096),
            KeyAlgorithm::Rsa8192 => Some(8192),
            _ => None,
        }
    }

    /// Get the minimum supported key size for an algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key algorithm
    ///
    /// # Returns
    ///
    /// Minimum key size in bits
    fn min_key_size(&self, algorithm: KeyAlgorithm) -> usize {
        match algorithm {
            KeyAlgorithm::Rsa1024 => 1024,
            KeyAlgorithm::Rsa2048 => 2048,
            KeyAlgorithm::Rsa3072 => 3072,
            KeyAlgorithm::Rsa4096 => 4096,
            KeyAlgorithm::Rsa8192 => 8192,
            _ => algorithm.key_size_bits(),
        }
    }
}

/// Convenience type alias for boxed crypto backends
pub type BoxedCryptoBackend = Box<dyn CryptoBackend<
    Key = Arc<dyn Key>,
    KeyPair = Arc<dyn KeyPair<Key = Arc<dyn Key>>>,
    Certificate = Arc<dyn Certificate<Key = Arc<dyn Key>>>,
    DigestContext = Box<dyn DigestContext>,
    SignContext = Box<dyn SignContext>,
    VerifyContext = Box<dyn VerifyContext>,
    EncryptContext = Box<dyn EncryptContext>,
    DecryptContext = Box<dyn DecryptContext>,
>>;