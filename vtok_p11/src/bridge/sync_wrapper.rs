//! Synchronous wrapper for async vtok_backend operations.
//!
//! This module provides a synchronous interface to the async vtok_backend traits,
//! allowing PKCS#11 operations (which are inherently synchronous) to use async backends.

use std::sync::Arc;
use tokio::runtime::Runtime;
use vtok_backend::types::{
    BackendResult, KeyAlgorithm, KeyType, Mechanism, DigestAlgorithm,
    MechanismParams, ContextConfig
};
use vtok_backend::BackendInfo;
use crate::aws_lc_backend::AwsLcBackend;

/// Synchronous wrapper around a CryptoBackend
/// This wraps the AwsLcBackend and provides synchronous access to async operations
pub struct SyncCryptoBackend {
    backend: Arc<AwsLcBackend>,
    runtime: Arc<Runtime>,
}

impl SyncCryptoBackend {
    /// Create a new synchronous backend wrapping AwsLcBackend
    pub fn new() -> BackendResult<Self> {
        let backend = Arc::new(AwsLcBackend::new()?);
        let runtime = Arc::new(
            Runtime::new()
                .map_err(|e| vtok_backend::types::BackendError::InitializationFailed(
                    format!("Failed to create async runtime: {}", e)
                ))?
        );
        
        Ok(Self {
            backend,
            runtime,
        })
    }

    /// Create a new mock synchronous backend (for compatibility)
    pub fn new_mock() -> BackendResult<Self> {
        Self::new()
    }

    /// Get backend information
    pub fn info(&self) -> &BackendInfo {
        self.backend.info()
    }

    /// Check if a mechanism is supported by this backend
    pub fn supports_mechanism(&self, mechanism: &Mechanism) -> bool {
        self.backend.supports_mechanism(mechanism)
    }

    /// Get list of supported mechanisms
    pub fn supported_mechanisms(&self) -> Vec<Mechanism> {
        self.backend.supported_mechanisms()
    }

    /// Get list of supported key algorithms
    pub fn supported_key_algorithms(&self) -> Vec<KeyAlgorithm> {
        self.backend.supported_key_algorithms()
    }

    /// Initialize the backend (if needed)
    pub fn initialize(&self) -> BackendResult<()> {
        self.runtime.block_on(self.backend.initialize())
    }

    /// Finalize the backend (cleanup)
    pub fn finalize(&self) -> BackendResult<()> {
        self.runtime.block_on(self.backend.finalize())
    }

    /// Generate random bytes
    pub fn generate_random(&self, length: usize) -> BackendResult<Vec<u8>> {
        self.runtime.block_on(self.backend.generate_random(length))
    }

    /// Get the maximum supported key size for an algorithm
    pub fn max_key_size(&self, algorithm: KeyAlgorithm) -> Option<usize> {
        self.backend.max_key_size(algorithm)
    }

    /// Get the minimum supported key size for an algorithm
    pub fn min_key_size(&self, algorithm: KeyAlgorithm) -> usize {
        self.backend.min_key_size(algorithm)
    }
}

// Implement Send and Sync for the wrapper
unsafe impl Send for SyncCryptoBackend {}
unsafe impl Sync for SyncCryptoBackend {}