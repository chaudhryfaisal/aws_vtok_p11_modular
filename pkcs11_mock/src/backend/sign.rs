//! Mock sign context implementation.

use vtok_backend::traits::SignContext;
use vtok_backend::types::{BackendResult, BackendError, Mechanism};

use crate::data::MockConfig;
use super::context::MockContext;
use super::key::MockKey;

/// Mock sign context
#[derive(Debug, Clone)]
pub struct MockSignContext {
    mechanism: Mechanism,
    key: MockKey,
    context: MockContext,
    data_buffer: Vec<u8>,
}

impl MockSignContext {
    /// Create a new mock sign context
    pub fn new(mechanism: Mechanism, key: MockKey, config: &MockConfig) -> BackendResult<Self> {
        if !key.can_sign() {
            return Err(BackendError::InvalidKey("Key cannot be used for signing".to_string()));
        }

        Ok(Self {
            mechanism,
            key,
            context: MockContext::new(config),
            data_buffer: Vec::new(),
        })
    }

    /// Generate a mock signature
    fn generate_mock_signature(&self, data: &[u8]) -> Vec<u8> {
        let sig_size = match self.mechanism {
            Mechanism::RsaPkcs1 { .. } | Mechanism::RsaPkcs1Pss { .. } => {
                match self.key.algorithm() {
                    vtok_backend::types::KeyAlgorithm::Rsa2048 => 256,
                    vtok_backend::types::KeyAlgorithm::Rsa3072 => 384,
                    vtok_backend::types::KeyAlgorithm::Rsa4096 => 512,
                    _ => 256,
                }
            }
            Mechanism::Ecdsa { .. } => {
                match self.key.algorithm() {
                    vtok_backend::types::KeyAlgorithm::EcdsaP256 => 64,
                    vtok_backend::types::KeyAlgorithm::EcdsaP384 => 96,
                    _ => 64,
                }
            }
            _ => 64,
        };

        if self.context.config.deterministic {
            // Generate deterministic signature for testing
            let mut signature = Vec::with_capacity(sig_size);
            for i in 0..sig_size {
                let byte = ((data.len() + i + self.key.key_data().len()) % 256) as u8;
                signature.push(byte);
            }
            signature
        } else {
            // Generate random signature
            self.context.generate_deterministic_data(sig_size, 0x55)
        }
    }
}

impl SignContext for MockSignContext {
    fn mechanism(&self) -> &Mechanism {
        &self.mechanism
    }

    fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("sign_update") {
            return Err(error);
        }

        self.data_buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.context.should_inject_error("sign_finalize") {
            return Err(error);
        }

        Ok(self.generate_mock_signature(&self.data_buffer))
    }

    fn sign_oneshot(&self, data: &[u8]) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.context.should_inject_error("sign_oneshot") {
            return Err(error);
        }

        Ok(self.generate_mock_signature(data))
    }

    fn max_signature_size(&self) -> usize {
        match self.mechanism {
            Mechanism::RsaPkcs1 { .. } | Mechanism::RsaPkcs1Pss { .. } => {
                match self.key.algorithm() {
                    vtok_backend::types::KeyAlgorithm::Rsa2048 => 256,
                    vtok_backend::types::KeyAlgorithm::Rsa3072 => 384,
                    vtok_backend::types::KeyAlgorithm::Rsa4096 => 512,
                    _ => 256,
                }
            }
            Mechanism::Ecdsa { .. } => {
                match self.key.algorithm() {
                    vtok_backend::types::KeyAlgorithm::EcdsaP256 => 64,
                    vtok_backend::types::KeyAlgorithm::EcdsaP384 => 96,
                    _ => 64,
                }
            }
            _ => 64,
        }
    }

    fn reset(&mut self) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("sign_reset") {
            return Err(error);
        }

        self.data_buffer.clear();
        Ok(())
    }
}