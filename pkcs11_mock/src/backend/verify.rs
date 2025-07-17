//! Mock verify context implementation.

use vtok_backend::traits::VerifyContext;
use vtok_backend::types::{BackendResult, BackendError, Mechanism};

use crate::data::MockConfig;
use super::context::MockContext;
use super::key::MockKey;

/// Mock verify context
#[derive(Debug, Clone)]
pub struct MockVerifyContext {
    mechanism: Mechanism,
    key: MockKey,
    context: MockContext,
    data_buffer: Vec<u8>,
}

impl MockVerifyContext {
    /// Create a new mock verify context
    pub fn new(mechanism: Mechanism, key: MockKey, config: &MockConfig) -> BackendResult<Self> {
        if !key.can_verify() {
            return Err(BackendError::InvalidKey("Key cannot be used for verification".to_string()));
        }

        Ok(Self {
            mechanism,
            key,
            context: MockContext::new(config),
            data_buffer: Vec::new(),
        })
    }

    /// Perform mock signature verification
    fn verify_mock_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        if self.context.config.deterministic {
            // For deterministic mode, verify against expected signature pattern
            let expected_sig_size = match self.mechanism {
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

            // Check signature size
            if signature.len() != expected_sig_size {
                return false;
            }

            // Generate expected signature and compare
            let mut expected_signature = Vec::with_capacity(expected_sig_size);
            for i in 0..expected_sig_size {
                let byte = ((data.len() + i + self.key.key_data().len()) % 256) as u8;
                expected_signature.push(byte);
            }

            signature == expected_signature
        } else {
            // For non-deterministic mode, use simple heuristics
            // Check if signature size is reasonable
            let min_size = match self.mechanism {
                Mechanism::RsaPkcs1 { .. } | Mechanism::RsaPkcs1Pss { .. } => 128,
                Mechanism::Ecdsa { .. } => 32,
                _ => 32,
            };

            signature.len() >= min_size && !signature.iter().all(|&b| b == 0)
        }
    }
}

impl VerifyContext for MockVerifyContext {
    fn mechanism(&self) -> &Mechanism {
        &self.mechanism
    }

    fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("verify_update") {
            return Err(error);
        }

        self.data_buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self, signature: &[u8]) -> BackendResult<bool> {
        if let Some(error) = self.context.should_inject_error("verify_finalize") {
            return Err(error);
        }

        Ok(self.verify_mock_signature(&self.data_buffer, signature))
    }

    fn verify_oneshot(&self, data: &[u8], signature: &[u8]) -> BackendResult<bool> {
        if let Some(error) = self.context.should_inject_error("verify_oneshot") {
            return Err(error);
        }

        Ok(self.verify_mock_signature(data, signature))
    }

    fn reset(&mut self) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("verify_reset") {
            return Err(error);
        }

        self.data_buffer.clear();
        Ok(())
    }
}