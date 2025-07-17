//! Mock decrypt context implementation.

use vtok_backend::traits::{DecryptContext, Key};
use vtok_backend::types::{BackendResult, BackendError, Mechanism, ContextState, KeyAlgorithm};

use crate::data::MockConfig;
use super::context::MockContext;
use super::key::MockKey;

/// Mock decrypt context
#[derive(Debug, Clone)]
pub struct MockDecryptContext {
    mechanism: Mechanism,
    key: MockKey,
    context: MockContext,
    data_buffer: Vec<u8>,
}

impl MockDecryptContext {
    /// Create a new mock decrypt context
    pub fn new(mechanism: Mechanism, key: MockKey, config: &MockConfig) -> BackendResult<Self> {
        if !key.can_decrypt() {
            return Err(BackendError::InvalidKey("Key cannot be used for decryption".to_string()));
        }

        Ok(Self {
            mechanism,
            key,
            context: MockContext::new(config),
            data_buffer: Vec::new(),
        })
    }

    /// Perform mock decryption
    fn decrypt_mock_data(&self, data: &[u8]) -> Vec<u8> {
        if self.context.is_deterministic() {
            // Simple XOR-based "decryption" for deterministic testing
            // This reverses the encryption operation
            let key_data = self.key.key_data();
            let mut decrypted = Vec::with_capacity(data.len());
            
            for (i, &byte) in data.iter().enumerate() {
                let key_byte = key_data[i % key_data.len()];
                decrypted.push(byte ^ key_byte);
            }
            
            decrypted
        } else {
            // For non-deterministic mode, just return modified data
            // This reverses the encryption operation (subtract 1)
            let mut decrypted = data.to_vec();
            for byte in &mut decrypted {
                *byte = byte.wrapping_sub(1);
            }
            decrypted
        }
    }

    /// Calculate output size for decryption
    fn calculate_output_size(&self, input_size: usize) -> usize {
        match self.mechanism {
            Mechanism::RsaPkcs1 { .. } | Mechanism::RsaPkcs1Pss { .. } => {
                // RSA decryption output is typically smaller than input
                // For simplicity, we'll assume maximum possible output
                match self.key.algorithm() {
                    KeyAlgorithm::Rsa2048 => 245, // 256 - 11 (PKCS#1 padding)
                    KeyAlgorithm::Rsa3072 => 373, // 384 - 11
                    KeyAlgorithm::Rsa4096 => 501, // 512 - 11
                    _ => 245,
                }
            }
            _ => {
                // For symmetric decryption, output size equals input size (simplified)
                input_size
            }
        }
    }
}

impl DecryptContext for MockDecryptContext {
    fn mechanism(&self) -> &Mechanism {
        &self.mechanism
    }

    fn state(&self) -> ContextState {
        ContextState::MultiPartActive
    }

    async fn update(&mut self, ciphertext: &[u8]) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.context.should_inject_error("decrypt_update") {
            return Err(error);
        }

        // For streaming decryption, we buffer the data
        self.data_buffer.extend_from_slice(ciphertext);
        
        // Return empty vector for update operations (data is buffered)
        Ok(Vec::new())
    }

    async fn finalize(self) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.context.should_inject_error("decrypt_finalize") {
            return Err(error);
        }

        Ok(self.decrypt_mock_data(&self.data_buffer))
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.key.algorithm()
    }

    fn key_size(&self) -> usize {
        self.key.key_size()
    }

    fn output_size(&self, ciphertext_size: usize) -> usize {
        self.calculate_output_size(ciphertext_size)
    }

    async fn reset(&mut self) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("decrypt_reset") {
            return Err(error);
        }

        self.data_buffer.clear();
        Ok(())
    }

    fn supports_reset(&self) -> bool {
        true
    }
}