//! Error types for the vtok_backend abstraction layer.
//!
//! This module defines the comprehensive error handling for backend operations.

use thiserror::Error;

/// Result type alias for backend operations
pub type BackendResult<T> = Result<T, BackendError>;

/// Comprehensive error type for backend operations
#[derive(Error, Debug, Clone)]
pub enum BackendError {
    /// General backend error with message
    #[error("Backend error: {0}")]
    General(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Unsupported mechanism
    #[error("Unsupported mechanism: {0}")]
    UnsupportedMechanism(String),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Invalid key data
    #[error("Invalid key data: {0}")]
    InvalidKeyData(String),

    /// Invalid key type for operation
    #[error("Invalid key type: {0}")]
    InvalidKey(String),

    /// Key is not extractable
    #[error("Key is not extractable")]
    KeyNotExtractable,

    /// Key is sensitive and cannot be revealed
    #[error("Key is sensitive")]
    KeySensitive,

    /// Invalid certificate data
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    /// Digest operation failed
    #[error("Digest operation failed: {0}")]
    DigestOperation(String),

    /// Digest update failed
    #[error("Digest update failed: {0}")]
    DigestUpdate(String),

    /// Digest finalization failed
    #[error("Digest finalization failed: {0}")]
    DigestFinalize(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SignOperation(String),

    /// Signature verification failed
    #[error("Verification failed: {0}")]
    VerifyOperation(String),

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    EncryptOperation(String),

    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptOperation(String),

    /// Random number generation failed
    #[error("Random generation failed: {0}")]
    RandomGeneration(String),

    /// Context has already been finalized
    #[error("Context already finalized")]
    ContextFinalized,

    /// Operation is already active
    #[error("Operation already active")]
    OperationActive,

    /// Invalid operation state
    #[error("Invalid operation state: {0}")]
    InvalidState(String),

    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Buffer too small
    #[error("Buffer too small: required {required}, provided {provided}")]
    BufferTooSmall { required: usize, provided: usize },

    /// Data length is invalid
    #[error("Invalid data length: {0}")]
    InvalidDataLength(String),

    /// Read-only attribute cannot be modified
    #[error("Read-only attribute: {0}")]
    ReadOnlyAttribute(String),

    /// Backend initialization failed
    #[error("Backend initialization failed: {0}")]
    InitializationFailed(String),

    /// Backend not initialized
    #[error("Backend not initialized")]
    NotInitialized,

    /// Hardware error
    #[error("Hardware error: {0}")]
    HardwareError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Memory allocation error
    #[error("Memory allocation failed")]
    OutOfMemory,

    /// Internal error (should not happen in normal operation)
    #[error("Internal error: {0}")]
    Internal(String),
}

impl BackendError {
    /// Create a new general error
    pub fn general(msg: impl Into<String>) -> Self {
        Self::General(msg.into())
    }

    /// Create a new unsupported algorithm error
    pub fn unsupported_algorithm(alg: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm(alg.into())
    }

    /// Create a new unsupported mechanism error
    pub fn unsupported_mechanism(mech: impl Into<String>) -> Self {
        Self::UnsupportedMechanism(mech.into())
    }

    /// Create a new key generation error
    pub fn key_generation(msg: impl Into<String>) -> Self {
        Self::KeyGeneration(msg.into())
    }

    /// Create a new invalid key error
    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    /// Create a new digest operation error
    pub fn digest_operation(msg: impl Into<String>) -> Self {
        Self::DigestOperation(msg.into())
    }

    /// Create a new sign operation error
    pub fn sign_operation(msg: impl Into<String>) -> Self {
        Self::SignOperation(msg.into())
    }

    /// Create a new verify operation error
    pub fn verify_operation(msg: impl Into<String>) -> Self {
        Self::VerifyOperation(msg.into())
    }

    /// Create a new encrypt operation error
    pub fn encrypt_operation(msg: impl Into<String>) -> Self {
        Self::EncryptOperation(msg.into())
    }

    /// Create a new decrypt operation error
    pub fn decrypt_operation(msg: impl Into<String>) -> Self {
        Self::DecryptOperation(msg.into())
    }

    /// Create a new internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Convert from std::io::Error
impl From<std::io::Error> for BackendError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}