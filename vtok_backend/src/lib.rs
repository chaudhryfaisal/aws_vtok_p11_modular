//! # vtok_backend
//!
//! Foundational abstraction layer for modular PKCS#11 crypto backends.
//!
//! This crate provides the core traits and types that define the interface
//! between the PKCS#11 layer and various cryptographic backends. It enables
//! a modular architecture where different crypto implementations can be
//! plugged in without changing the PKCS#11 interface.
//!
//! ## Architecture
//!
//! The backend abstraction is built around several key concepts:
//!
//! - **CryptoBackend**: The main trait that crypto implementations must implement
//! - **Context Traits**: Specialized traits for different crypto operations
//! - **Type Safety**: Strong typing to prevent misuse of crypto primitives
//! - **Thread Safety**: All traits are designed to be thread-safe
//!
//! ## Example
//!
//! ```rust
//! use vtok_backend::traits::CryptoBackend;
//! use vtok_backend::types::{KeyAlgorithm, Mechanism};
//!
//! // Backend implementations would implement CryptoBackend
//! fn use_backend<B: CryptoBackend>(backend: &B) {
//!     // Use the backend for crypto operations
//! }
//! ```

pub mod traits;
pub mod types;
pub mod utils;

// Re-export commonly used items
pub use traits::{
    CryptoBackend, Key, KeyPair, Certificate,
    DigestContext, SignContext, VerifyContext,
    EncryptContext, DecryptContext,
};

pub use types::{
    BackendError, BackendResult,
    KeyAlgorithm, KeyType, Mechanism,
    DigestAlgorithm, SignaturePadding,
};

/// Version information for the vtok_backend crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Backend capability flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// Supports hardware-backed key generation
    pub hardware_keys: bool,
    /// Supports secure key storage
    pub secure_storage: bool,
    /// Supports hardware random number generation
    pub hardware_rng: bool,
    /// Supports side-channel resistant operations
    pub side_channel_resistant: bool,
}

impl Default for BackendCapabilities {
    fn default() -> Self {
        Self {
            hardware_keys: false,
            secure_storage: false,
            hardware_rng: false,
            side_channel_resistant: false,
        }
    }
}

/// Backend information structure
#[derive(Debug, Clone)]
pub struct BackendInfo {
    /// Backend name
    pub name: String,
    /// Backend version
    pub version: String,
    /// Backend description
    pub description: String,
    /// Backend capabilities
    pub capabilities: BackendCapabilities,
}

impl BackendInfo {
    /// Create new backend info
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        capabilities: BackendCapabilities,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description: description.into(),
            capabilities,
        }
    }
}