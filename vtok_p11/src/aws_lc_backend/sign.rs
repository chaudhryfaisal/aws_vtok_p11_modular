//! AWS-LC sign context implementation.

use vtok_backend::traits::SignContext;
use vtok_backend::types::{
    BackendResult, BackendError, Mechanism, ContextState, OperationProgress, KeyAlgorithm,
};
use super::key::AwsLcKey;
use super::context::ContextStateManager;

/// AWS-LC sign context
pub struct AwsLcSignContext {
    mechanism: Mechanism,
    key: AwsLcKey,
    state_manager: ContextStateManager,
    accumulated_data: Vec<u8>,
}

impl AwsLcSignContext {
    /// Create a new sign context
    pub fn new(mechanism: Mechanism, key: AwsLcKey) -> BackendResult<Self> {
        Ok(Self {
            mechanism,
            key,
            state_manager: ContextStateManager::new(),
            accumulated_data: Vec::new(),
        })
    }
}

impl std::fmt::Debug for AwsLcSignContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsLcSignContext")
            .field("mechanism", &self.mechanism)
            .field("state", &self.state_manager.state())
            .finish()
    }
}

impl SignContext for AwsLcSignContext {
    fn mechanism(&self) -> &Mechanism {
        &self.mechanism
    }

    fn signature_size(&self) -> usize {
        match self.key.algorithm() {
            KeyAlgorithm::Rsa2048 => 256,
            KeyAlgorithm::Rsa3072 => 384,
            KeyAlgorithm::Rsa4096 => 512,
            KeyAlgorithm::EcdsaP256 => 64,
            KeyAlgorithm::EcdsaP384 => 96,
            _ => 256,
        }
    }

    fn state(&self) -> ContextState {
        self.state_manager.state()
    }

    async fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        if !self.state_manager.can_update() {
            return Err(BackendError::InvalidState(format!(
                "Cannot update sign context in state {:?}",
                self.state_manager.state()
            )));
        }

        self.accumulated_data.extend_from_slice(data);
        self.state_manager.add_bytes_processed(data.len());
        self.state_manager.set_state(ContextState::MultiPartActive);
        Ok(())
    }

    async fn finalize(self) -> BackendResult<Vec<u8>> {
        if !self.state_manager.can_finalize() {
            return Err(BackendError::InvalidState(format!(
                "Cannot finalize sign context in state {:?}",
                self.state_manager.state()
            )));
        }

        // For now, return a placeholder signature
        // In a real implementation, this would use AWS-LC to sign the accumulated data
        Ok(vec![0u8; self.signature_size()])
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