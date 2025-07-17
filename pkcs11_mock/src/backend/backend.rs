//! Mock crypto backend implementation.

use std::sync::Arc;
use vtok_backend::traits::CryptoBackend;
use vtok_backend::types::{
    BackendResult, BackendError, KeyAlgorithm, KeyType, Mechanism,
    DigestAlgorithm, MechanismParams, ContextConfig,
};
use vtok_backend::BackendInfo;

use super::key::{MockKey, MockKeyPair, MockCertificate};
use super::digest::MockDigestContext;
use super::sign::MockSignContext;
use super::verify::MockVerifyContext;
use super::encrypt::MockEncryptContext;
use super::decrypt::MockDecryptContext;

use crate::data::MockConfig;

/// Mock crypto backend
pub struct MockBackend {
    info: BackendInfo,
    config: MockConfig,
}

impl MockBackend {
    /// Create a new mock backend
    pub fn new() -> BackendResult<Self> {
        let info = BackendInfo::new(
            "Mock Backend",
            "1.0.0",
            "Mock cryptographic backend implementation for testing",
            vtok_backend::BackendCapabilities {
                hardware_keys: false,
                secure_storage: false,
                hardware_rng: false,
                side_channel_resistant: false,
            },
        );

        let config = MockConfig::default();

        Ok(Self { info, config })
    }

    /// Create a new mock backend with custom configuration
    pub fn with_config(config: MockConfig) -> BackendResult<Self> {
        let info = BackendInfo::new(
            "Mock Backend",
            "1.0.0",
            "Mock cryptographic backend implementation for testing",
            vtok_backend::BackendCapabilities {
                hardware_keys: false,
                secure_storage: false,
                hardware_rng: false,
                side_channel_resistant: false,
            },
        );

        Ok(Self { info, config })
    }

    /// Get the mock configuration
    pub fn config(&self) -> &MockConfig {
        &self.config
    }

    /// Update the mock configuration
    pub fn update_config(&mut self, config: MockConfig) {
        self.config = config;
    }

    /// Check if error injection is enabled for a specific operation
    fn should_inject_error(&self, operation: &str) -> Option<BackendError> {
        if let Some(ref error_config) = self.config.error_injection {
            if error_config.enabled && error_config.operations.contains(&operation.to_string()) {
                return Some(BackendError::MockError(format!("Injected error for {}", operation)));
            }
        }
        None
    }

    /// Simulate performance delay if configured
    async fn simulate_delay(&self, operation: &str) {
        if let Some(ref perf_config) = self.config.performance_simulation {
            if perf_config.enabled {
                if let Some(delay) = perf_config.operation_delays.get(operation) {
                    tokio::time::sleep(*delay).await;
                }
            }
        }
    }
}

impl CryptoBackend for MockBackend {
    type Key = MockKey;
    type KeyPair = MockKeyPair;
    type Certificate = MockCertificate;
    type DigestContext = MockDigestContext;
    type SignContext = MockSignContext;
    type VerifyContext = MockVerifyContext;
    type EncryptContext = MockEncryptContext;
    type DecryptContext = MockDecryptContext;

    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn supports_mechanism(&self, mechanism: &Mechanism) -> bool {
        match mechanism {
            Mechanism::Digest(_) => true,
            Mechanism::RsaPkcs1 { .. } => true,
            Mechanism::RsaPkcs1Pss { .. } => true,
            Mechanism::Ecdsa { .. } => true,
            _ => false,
        }
    }

    fn supported_mechanisms(&self) -> Vec<Mechanism> {
        vec![
            Mechanism::Digest(DigestAlgorithm::Sha256),
            Mechanism::Digest(DigestAlgorithm::Sha384),
            Mechanism::Digest(DigestAlgorithm::Sha512),
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) },
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha384) },
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha512) },
            Mechanism::RsaPkcs1Pss { 
                digest: DigestAlgorithm::Sha256, 
                mgf: DigestAlgorithm::Sha256, 
                salt_len: 32 
            },
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) },
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha384) },
        ]
    }

    fn supported_key_algorithms(&self) -> Vec<KeyAlgorithm> {
        vec![
            KeyAlgorithm::Rsa2048,
            KeyAlgorithm::Rsa3072,
            KeyAlgorithm::Rsa4096,
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdsaP384,
            KeyAlgorithm::Aes256,
        ]
    }

    async fn generate_keypair(
        &self,
        algorithm: KeyAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair> {
        if let Some(error) = self.should_inject_error("generate_keypair") {
            return Err(error);
        }

        self.simulate_delay("generate_keypair").await;

        match algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
                let private_key = MockKey::new_rsa_private(algorithm, &self.config)?;
                let public_key = MockKey::new_rsa_public(algorithm, &self.config)?;
                Ok(MockKeyPair::new(private_key, public_key))
            }
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => {
                let private_key = MockKey::new_ecdsa_private(algorithm, &self.config)?;
                let public_key = MockKey::new_ecdsa_public(algorithm, &self.config)?;
                Ok(MockKeyPair::new(private_key, public_key))
            }
            _ => Err(BackendError::UnsupportedAlgorithm(format!(
                "Key generation for {:?} not supported",
                algorithm
            ))),
        }
    }

    async fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key> {
        if let Some(error) = self.should_inject_error("generate_key") {
            return Err(error);
        }

        self.simulate_delay("generate_key").await;

        match algorithm {
            KeyAlgorithm::Aes256 => {
                MockKey::new_symmetric(algorithm, &self.config)
            }
            _ => Err(BackendError::UnsupportedAlgorithm(format!(
                "Symmetric key generation for {:?} not supported",
                algorithm
            ))),
        }
    }

    async fn import_key(
        &self,
        key_type: KeyType,
        algorithm: KeyAlgorithm,
        key_data: &[u8],
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key> {
        if let Some(error) = self.should_inject_error("import_key") {
            return Err(error);
        }

        self.simulate_delay("import_key").await;

        match (key_type, algorithm) {
            (KeyType::Secret, KeyAlgorithm::Aes256) => {
                if key_data.len() != 32 {
                    return Err(BackendError::InvalidKeyData("AES-256 key must be 32 bytes".to_string()));
                }
                MockKey::import_symmetric(algorithm, key_data, &self.config)
            }
            (KeyType::Private, _) => {
                MockKey::import_private(algorithm, key_data, &self.config)
            }
            (KeyType::Public, _) => {
                MockKey::import_public(algorithm, key_data, &self.config)
            }
            _ => Err(BackendError::UnsupportedAlgorithm(format!(
                "Key import for {:?} {:?} not supported",
                key_type, algorithm
            ))),
        }
    }

    async fn import_keypair(
        &self,
        algorithm: KeyAlgorithm,
        private_key_data: &[u8],
        public_key_data: Option<&[u8]>,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair> {
        if let Some(error) = self.should_inject_error("import_keypair") {
            return Err(error);
        }

        self.simulate_delay("import_keypair").await;

        let private_key = MockKey::import_private(algorithm, private_key_data, &self.config)?;
        
        let public_key = if let Some(pub_data) = public_key_data {
            MockKey::import_public(algorithm, pub_data, &self.config)?
        } else {
            // Derive public key from private key (mock implementation)
            MockKey::derive_public_from_private(&private_key)?
        };

        Ok(MockKeyPair::new(private_key, public_key))
    }

    async fn import_certificate(
        &self,
        cert_data: &[u8],
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::Certificate> {
        if let Some(error) = self.should_inject_error("import_certificate") {
            return Err(error);
        }

        self.simulate_delay("import_certificate").await;

        MockCertificate::import(cert_data, &self.config)
    }

    async fn create_digest_context(
        &self,
        algorithm: DigestAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::DigestContext> {
        if let Some(error) = self.should_inject_error("create_digest_context") {
            return Err(error);
        }

        MockDigestContext::new(algorithm, &self.config)
    }

    async fn create_sign_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::SignContext> {
        if let Some(error) = self.should_inject_error("create_sign_context") {
            return Err(error);
        }

        MockSignContext::new(mechanism, key.clone(), &self.config)
    }

    async fn create_verify_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::VerifyContext> {
        if let Some(error) = self.should_inject_error("create_verify_context") {
            return Err(error);
        }

        MockVerifyContext::new(mechanism, key.clone(), &self.config)
    }

    async fn create_encrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::EncryptContext> {
        if let Some(error) = self.should_inject_error("create_encrypt_context") {
            return Err(error);
        }

        MockEncryptContext::new(mechanism, key.clone(), &self.config)
    }

    async fn create_decrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::DecryptContext> {
        if let Some(error) = self.should_inject_error("create_decrypt_context") {
            return Err(error);
        }

        MockDecryptContext::new(mechanism, key.clone(), &self.config)
    }

    async fn generate_random(&self, length: usize) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.should_inject_error("generate_random") {
            return Err(error);
        }

        self.simulate_delay("generate_random").await;

        if self.config.deterministic {
            // Generate deterministic "random" data for testing
            let mut bytes = vec![0u8; length];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
            Ok(bytes)
        } else {
            use rand::RngCore;
            let mut bytes = vec![0u8; length];
            rand::thread_rng().fill_bytes(&mut bytes);
            Ok(bytes)
        }
    }

    async fn derive_key(
        &self,
        _mechanism: Mechanism,
        _base_key: &Self::Key,
        _params: &MechanismParams,
        _target_algorithm: KeyAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key> {
        if let Some(error) = self.should_inject_error("derive_key") {
            return Err(error);
        }

        Err(BackendError::UnsupportedOperation("Key derivation not implemented in mock".to_string()))
    }

    async fn key_agreement(
        &self,
        _mechanism: Mechanism,
        _private_key: &Self::Key,
        _public_key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.should_inject_error("key_agreement") {
            return Err(error);
        }

        Err(BackendError::UnsupportedOperation("Key agreement not implemented in mock".to_string()))
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create mock backend")
    }
}