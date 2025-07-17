//! AWS-LC decrypt context implementation.

use vtok_backend::traits::{DecryptContext, Key};
use vtok_backend::types::{
    BackendResult, BackendError, Mechanism, ContextState, OperationProgress, KeyAlgorithm,
};
use super::key::AwsLcKey;
use super::context::ContextStateManager;

/// AWS-LC decrypt context
pub struct AwsLcDecryptContext {
    mechanism: Mechanism,
    key: AwsLcKey,
    state_manager: ContextStateManager,
}

impl AwsLcDecryptContext {
    /// Create a new decrypt context
    pub fn new(mechanism: Mechanism, key: AwsLcKey) -> BackendResult<Self> {
        Ok(Self {
            mechanism,
            key,
            state_manager: ContextStateManager::new(),
        })
    }
}

impl std::fmt::Debug for AwsLcDecryptContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsLcDecryptContext")
            .field("mechanism", &self.mechanism)
            .field("state", &self.state_manager.state())
            .finish()
    }
}

impl DecryptContext for AwsLcDecryptContext {
    fn mechanism(&self) -> &Mechanism {
        &self.mechanism
    }

    fn state(&self) -> ContextState {
        self.state_manager.state()
    }

    async fn update(&mut self, ciphertext: &[u8]) -> BackendResult<Vec<u8>> {
        if !self.state_manager.can_update() {
            return Err(BackendError::InvalidState(format!(
                "Cannot update decrypt context in state {:?}",
                self.state_manager.state()
            )));
        }

        self.state_manager.add_bytes_processed(ciphertext.len());
        self.state_manager.set_state(ContextState::MultiPartActive);
        
        // For now, return placeholder decrypted data
        // In a real implementation, this would use AWS-LC to decrypt
        Ok(vec![0u8; ciphertext.len().saturating_sub(16)])
    }

    async fn finalize(self) -> BackendResult<Vec<u8>> {
        if !self.state_manager.can_finalize() {
            return Err(BackendError::InvalidState(format!(
                "Cannot finalize decrypt context in state {:?}",
                self.state_manager.state()
            )));
        }

        // For now, return empty final data
        // In a real implementation, this would return any remaining decrypted data
        Ok(Vec::new())
    }

    fn bytes_processed(&self) -> u64 {
        self.state_manager.bytes_processed()
    }

    fn progress(&self) -> OperationProgress {
        self.state_manager.progress()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.key.algorithm()
    }

    fn key_size(&self) -> usize {
        self.key.key_size()
    }
}