//! Utility features and mock data generators.
//!
//! This module provides utilities for generating test data, configuring
//! mock behavior, and creating test scenarios for PKCS#11 applications.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Deserialize, Serialize};

use crate::data::{MockConfig, MockDataGenerator, ErrorInjectionConfig, PerformanceSimulationConfig};

/// Test scenario builder for creating common testing configurations
pub struct TestScenarioBuilder {
    config: MockConfig,
}

impl TestScenarioBuilder {
    /// Create a new test scenario builder
    pub fn new() -> Self {
        Self {
            config: MockConfig::default(),
        }
    }

    /// Enable deterministic mode
    pub fn deterministic(mut self, enabled: bool) -> Self {
        self.config.deterministic = enabled;
        self
    }

    /// Add error injection for specific operations
    pub fn with_error_injection(mut self, operations: Vec<String>, probability: f64) -> Self {
        self.config.error_injection = Some(ErrorInjectionConfig {
            enabled: true,
            operations,
            probability,
            error_types: vec!["MockError".to_string()],
        });
        self
    }

    /// Add performance delays for operations
    pub fn with_performance_delays(mut self, delays: HashMap<String, Duration>) -> Self {
        self.config.performance_simulation = Some(PerformanceSimulationConfig {
            enabled: true,
            operation_delays: delays,
            cpu_simulation: None,
            memory_simulation: None,
        });
        self
    }

    /// Build the configuration
    pub fn build(self) -> MockConfig {
        self.config
    }
}

impl Default for TestScenarioBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Predefined test scenarios for common use cases
pub struct TestScenarios;

impl TestScenarios {
    /// Basic deterministic scenario for unit tests
    pub fn basic_deterministic() -> MockConfig {
        TestScenarioBuilder::new()
            .deterministic(true)
            .build()
    }

    /// Error injection scenario for testing error handling
    pub fn error_injection() -> MockConfig {
        TestScenarioBuilder::new()
            .deterministic(true)
            .with_error_injection(
                vec![
                    "generate_keypair".to_string(),
                    "sign_oneshot".to_string(),
                    "verify_oneshot".to_string(),
                ],
                0.5, // 50% error rate
            )
            .build()
    }

    /// Performance testing scenario with delays
    pub fn performance_testing() -> MockConfig {
        let mut delays = HashMap::new();
        delays.insert("generate_keypair".to_string(), Duration::from_millis(100));
        delays.insert("sign_oneshot".to_string(), Duration::from_millis(10));
        delays.insert("verify_oneshot".to_string(), Duration::from_millis(5));
        delays.insert("digest_finalize".to_string(), Duration::from_millis(2));

        TestScenarioBuilder::new()
            .deterministic(true)
            .with_performance_delays(delays)
            .build()
    }

    /// Stress testing scenario with high error rates
    pub fn stress_testing() -> MockConfig {
        TestScenarioBuilder::new()
            .deterministic(false)
            .with_error_injection(
                vec![
                    "generate_keypair".to_string(),
                    "generate_key".to_string(),
                    "sign_oneshot".to_string(),
                    "verify_oneshot".to_string(),
                    "encrypt_oneshot".to_string(),
                    "decrypt_oneshot".to_string(),
                ],
                0.1, // 10% error rate
            )
            .build()
    }

    /// CI/CD scenario optimized for continuous integration
    pub fn ci_cd() -> MockConfig {
        TestScenarioBuilder::new()
            .deterministic(true)
            .build()
    }
}

/// Mock data factory for creating test vectors
pub struct MockDataFactory {
    generator: MockDataGenerator,
}

impl MockDataFactory {
    /// Create a new mock data factory
    pub fn new(config: MockConfig) -> Self {
        Self {
            generator: MockDataGenerator::new(config),
        }
    }

    /// Create a factory with deterministic behavior
    pub fn deterministic() -> Self {
        Self::new(MockConfig::deterministic())
    }

    /// Generate test data for RSA operations
    pub fn rsa_test_data(&self, key_size: usize) -> RsaTestData {
        let keypair = self.generator.generate_rsa_keypair(key_size);
        let message = b"Hello, RSA World!";
        let signature = self.generator.generate_signature("RSA-PKCS1-SHA256", message);

        RsaTestData {
            key_size,
            private_key: keypair.private_key,
            public_key: keypair.public_key,
            message: message.to_vec(),
            signature: signature.signature,
        }
    }

    /// Generate test data for ECDSA operations
    pub fn ecdsa_test_data(&self, curve: &str) -> EcdsaTestData {
        let keypair = self.generator.generate_ecdsa_keypair(curve);
        let message = b"Hello, ECDSA World!";
        let signature = self.generator.generate_signature("ECDSA-SHA256", message);

        EcdsaTestData {
            curve: curve.to_string(),
            private_key: keypair.private_key,
            public_key: keypair.public_key,
            message: message.to_vec(),
            signature: signature.signature,
        }
    }

    /// Generate test data for symmetric operations
    pub fn symmetric_test_data(&self, algorithm: &str) -> SymmetricTestData {
        let key = self.generator.generate_symmetric_key(algorithm);
        let plaintext = b"Hello, Symmetric World!";
        let ciphertext = self.mock_encrypt(plaintext, &key.key_data);

        SymmetricTestData {
            algorithm: algorithm.to_string(),
            key: key.key_data,
            plaintext: plaintext.to_vec(),
            ciphertext,
        }
    }

    /// Generate test certificate data
    pub fn certificate_test_data(&self, subject: &str) -> CertificateTestData {
        let cert = self.generator.generate_certificate(subject);
        
        CertificateTestData {
            subject: cert.subject,
            issuer: cert.issuer,
            serial_number: cert.serial_number,
            der_data: cert.der_data,
            public_key: cert.public_key,
        }
    }

    /// Mock encryption for test data generation
    fn mock_encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut encrypted = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            encrypted.push(byte ^ key_byte);
        }
        encrypted
    }
}

/// RSA test data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaTestData {
    pub key_size: usize,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

/// ECDSA test data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaTestData {
    pub curve: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Symmetric test data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymmetricTestData {
    pub algorithm: String,
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Certificate test data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateTestData {
    pub subject: String,
    pub issuer: String,
    pub serial_number: Vec<u8>,
    pub der_data: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Test vector collection for comprehensive testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorCollection {
    pub rsa_vectors: Vec<RsaTestData>,
    pub ecdsa_vectors: Vec<EcdsaTestData>,
    pub symmetric_vectors: Vec<SymmetricTestData>,
    pub certificate_vectors: Vec<CertificateTestData>,
}

impl TestVectorCollection {
    /// Create a comprehensive test vector collection
    pub fn comprehensive() -> Self {
        let factory = MockDataFactory::deterministic();
        
        let rsa_vectors = vec![
            factory.rsa_test_data(2048),
            factory.rsa_test_data(3072),
            factory.rsa_test_data(4096),
        ];

        let ecdsa_vectors = vec![
            factory.ecdsa_test_data("P-256"),
            factory.ecdsa_test_data("P-384"),
        ];

        let symmetric_vectors = vec![
            factory.symmetric_test_data("AES-128"),
            factory.symmetric_test_data("AES-192"),
            factory.symmetric_test_data("AES-256"),
        ];

        let certificate_vectors = vec![
            factory.certificate_test_data("CN=Test Certificate 1"),
            factory.certificate_test_data("CN=Test Certificate 2"),
            factory.certificate_test_data("CN=Test CA Certificate"),
        ];

        Self {
            rsa_vectors,
            ecdsa_vectors,
            symmetric_vectors,
            certificate_vectors,
        }
    }

    /// Save test vectors to JSON file
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load test vectors from JSON file
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let vectors: TestVectorCollection = serde_json::from_str(&content)?;
        Ok(vectors)
    }
}

/// Utility functions for common testing operations
pub mod testing {
    use super::*;

    /// Create a mock provider for testing
    pub fn create_test_provider() -> Result<crate::provider::MockProvider, crate::provider::ProviderError> {
        crate::provider::MockProvider::deterministic()
    }

    /// Create a mock provider with error injection
    pub fn create_error_injection_provider(operations: Vec<String>) -> Result<crate::provider::MockProvider, crate::provider::ProviderError> {
        crate::provider::MockProvider::with_error_injection(operations)
    }

    /// Create a mock provider with performance simulation
    pub fn create_performance_provider(delays: HashMap<String, Duration>) -> Result<crate::provider::MockProvider, crate::provider::ProviderError> {
        crate::provider::MockProvider::with_performance_simulation(delays)
    }

    /// Verify that two byte arrays are equal (for testing)
    pub fn assert_bytes_equal(expected: &[u8], actual: &[u8], message: &str) {
        assert_eq!(expected.len(), actual.len(), "{}: length mismatch", message);
        assert_eq!(expected, actual, "{}: content mismatch", message);
    }

    /// Generate deterministic test data
    pub fn generate_test_data(size: usize, seed: u8) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        for i in 0..size {
            data.push(((seed as usize + i) % 256) as u8);
        }
        data
    }

    /// Create a test configuration with specific settings
    pub fn create_test_config(deterministic: bool, error_injection: bool) -> MockConfig {
        let mut builder = TestScenarioBuilder::new().deterministic(deterministic);
        
        if error_injection {
            builder = builder.with_error_injection(
                vec!["test_operation".to_string()],
                1.0, // Always inject errors for testing
            );
        }
        
        builder.build()
    }
}