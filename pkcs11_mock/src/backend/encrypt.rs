//! Mock encrypt context implementation.

use vtok_backend::traits::{EncryptContext, Key};
use vtok_backend::types::{BackendResult, BackendError, Mechanism, ContextState, KeyAlgorithm};

use crate::data::MockConfig;
use super::context::MockContext;
use super::key::MockKey;

/// Mock encrypt context
#[derive(Debug, Clone)]
pub struct MockEncryptContext {
    mechanism: Mechanism,
    key: MockKey,
    context: MockContext,
    data_buffer: Vec<u8>,
}

impl MockEncryptContext {
    /// Create a new mock encrypt context
    pub fn new(mechanism: Mechanism, key: MockKey, config: &MockConfig) -> BackendResult<Self> {
        if !key.can_encrypt() {
            return Err(BackendError::InvalidKey("Key cannot be used for encryption".to_string()));
        }

        Ok(Self {
            mechanism,
            key,
            context: MockContext::new(config),
            data_buffer: Vec::new(),
        })
    }

    /// Perform mock encryption
    fn encrypt_mock_data(&self, data: &[u8]) -> Vec<u8> {
        if self.context.is_deterministic() {
            // Simple XOR-based "encryption" for deterministic testing
            let key_data = self.key.key_data();
            let mut encrypted = Vec::with_capacity(data.len());
            
            for (i, &byte) in data.iter().enumerate() {
                let key_byte = key_data[i % key_data.len()];
                encrypted.push(byte ^ key_byte);
            }
            
            encrypted
        } else {
            // For non-deterministic mode, just return modified data
            let mut encrypted = data.to_vec();
            for byte in &mut encrypted {
                *byte = byte.wrapping_add(1);
            }
            encrypted
        }
    }

    /// Calculate output size for encryption
    fn calculate_output_size(&self, input_size: usize) -> usize {
        match self.mechanism {
            Mechanism::RsaPkcs1 { .. } | Mechanism::RsaPkcs1Pss { .. } => {
                // RSA encryption output is always the key size
                match self.key.algorithm() {
                    KeyAlgorithm::Rsa2048 => 256,
                    KeyAlgorithm::Rsa3072 => 384,
                    KeyAlgorithm::Rsa4096 => 512,
                    _ => 256,
                }
            }
            _ => {
                // For symmetric encryption, output size equals input size (simplified)
                input_size
            }
        }
    }
}

impl EncryptContext for MockEncryptContext {
    fn mechanism(&self) -> &Mechanism {
        &self.mechanism
    }

    fn state(&self) -> ContextState {
        ContextState::MultiPartActive
    }

    async fn update(&mut self, data: &[u8]) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.context.should_inject_error("encrypt_update") {
            return Err(error);
        }

        // For streaming encryption, we buffer the data
        self.data_buffer.extend_from_slice(data);
        
        // Return empty vector for update operations (data is buffered)
        Ok(Vec::new())
    }

    async fn finalize(self) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.context.should_inject_error("encrypt_finalize") {
            return Err(error);
        }

        Ok(self.encrypt_mock_data(&self.data_buffer))
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.key.algorithm()
    }

    fn key_size(&self) -> usize {
        self.key.key_size()
    }

    fn output_size(&self, input_size: usize) -> usize {
        self.calculate_output_size(input_size)
    }

    async fn reset(&mut self) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("encrypt_reset") {
            return Err(error);
        }

        self.data_buffer.clear();
        Ok(())
    }

    fn supports_reset(&self) -> bool {
        true
    }
}