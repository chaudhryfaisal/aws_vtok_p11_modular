//! Mock data management and configuration.
//!
//! This module provides configuration structures and data management
//! for the mock backend, including error injection, performance simulation,
//! and deterministic behavior controls.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Mock backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockConfig {
    /// Enable deterministic behavior for reproducible tests
    pub deterministic: bool,
    
    /// Error injection configuration
    pub error_injection: Option<ErrorInjectionConfig>,
    
    /// Performance simulation configuration
    pub performance_simulation: Option<PerformanceSimulationConfig>,
    
    /// Predefined test data configuration
    pub test_data: TestDataConfig,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            deterministic: true,
            error_injection: None,
            performance_simulation: None,
            test_data: TestDataConfig::default(),
        }
    }
}

/// Error injection configuration for testing error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInjectionConfig {
    /// Enable error injection
    pub enabled: bool,
    
    /// Operations to inject errors for
    pub operations: Vec<String>,
    
    /// Error injection probability (0.0 to 1.0)
    pub probability: f64,
    
    /// Specific error types to inject
    pub error_types: Vec<String>,
}

impl Default for ErrorInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            operations: vec![],
            probability: 0.1,
            error_types: vec!["MockError".to_string()],
        }
    }
}

/// Performance simulation configuration for load testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSimulationConfig {
    /// Enable performance simulation
    pub enabled: bool,
    
    /// Operation delays (operation_name -> delay)
    pub operation_delays: HashMap<String, Duration>,
    
    /// CPU usage simulation
    pub cpu_simulation: Option<CpuSimulationConfig>,
    
    /// Memory usage simulation
    pub memory_simulation: Option<MemorySimulationConfig>,
}

impl Default for PerformanceSimulationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            operation_delays: HashMap::new(),
            cpu_simulation: None,
            memory_simulation: None,
        }
    }
}

/// CPU usage simulation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSimulationConfig {
    /// Enable CPU simulation
    pub enabled: bool,
    
    /// CPU usage percentage (0.0 to 100.0)
    pub usage_percentage: f64,
    
    /// Duration of CPU usage simulation
    pub duration: Duration,
}

/// Memory usage simulation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySimulationConfig {
    /// Enable memory simulation
    pub enabled: bool,
    
    /// Memory allocation size in bytes
    pub allocation_size: usize,
    
    /// Duration to hold memory allocation
    pub duration: Duration,
}

/// Test data configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestDataConfig {
    /// Predefined key data
    pub keys: KeyTestData,
    
    /// Predefined certificate data
    pub certificates: CertificateTestData,
    
    /// Predefined signature data
    pub signatures: SignatureTestData,
}

impl Default for TestDataConfig {
    fn default() -> Self {
        Self {
            keys: KeyTestData::default(),
            certificates: CertificateTestData::default(),
            signatures: SignatureTestData::default(),
        }
    }
}

/// Predefined key test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTestData {
    /// RSA key pairs for testing
    pub rsa_keys: HashMap<String, RsaKeyData>,
    
    /// ECDSA key pairs for testing
    pub ecdsa_keys: HashMap<String, EcdsaKeyData>,
    
    /// Symmetric keys for testing
    pub symmetric_keys: HashMap<String, SymmetricKeyData>,
}

impl Default for KeyTestData {
    fn default() -> Self {
        let mut rsa_keys = HashMap::new();
        let mut ecdsa_keys = HashMap::new();
        let mut symmetric_keys = HashMap::new();

        // Add default test RSA key
        rsa_keys.insert("test_rsa_2048".to_string(), RsaKeyData {
            size: 2048,
            public_exponent: vec![0x01, 0x00, 0x01], // 65537
            private_key: vec![0x42; 256], // Mock private key data
            public_key: vec![0x43; 256],  // Mock public key data
        });

        // Add default test ECDSA key
        ecdsa_keys.insert("test_ecdsa_p256".to_string(), EcdsaKeyData {
            curve: "P-256".to_string(),
            private_key: vec![0x44; 32], // Mock private key data
            public_key: vec![0x45; 64],  // Mock public key data
        });

        // Add default test symmetric key
        symmetric_keys.insert("test_aes_256".to_string(), SymmetricKeyData {
            algorithm: "AES-256".to_string(),
            key_data: vec![0x46; 32], // Mock AES-256 key
        });

        Self {
            rsa_keys,
            ecdsa_keys,
            symmetric_keys,
        }
    }
}

/// RSA key test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaKeyData {
    pub size: usize,
    pub public_exponent: Vec<u8>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// ECDSA key test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaKeyData {
    pub curve: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Symmetric key test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymmetricKeyData {
    pub algorithm: String,
    pub key_data: Vec<u8>,
}

/// Predefined certificate test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateTestData {
    /// X.509 certificates for testing
    pub x509_certificates: HashMap<String, X509CertData>,
}

impl Default for CertificateTestData {
    fn default() -> Self {
        let mut x509_certificates = HashMap::new();

        // Add default test certificate
        x509_certificates.insert("test_cert".to_string(), X509CertData {
            subject: "CN=Test Certificate".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: vec![0x01, 0x02, 0x03, 0x04],
            not_before: "2023-01-01T00:00:00Z".to_string(),
            not_after: "2024-01-01T00:00:00Z".to_string(),
            public_key: vec![0x47; 64], // Mock public key
            der_data: vec![0x48; 512],  // Mock DER data
        });

        Self {
            x509_certificates,
        }
    }
}

/// X.509 certificate test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CertData {
    pub subject: String,
    pub issuer: String,
    pub serial_number: Vec<u8>,
    pub not_before: String,
    pub not_after: String,
    pub public_key: Vec<u8>,
    pub der_data: Vec<u8>,
}

/// Predefined signature test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureTestData {
    /// Known good signatures for verification testing
    pub known_signatures: HashMap<String, SignatureData>,
}

impl Default for SignatureTestData {
    fn default() -> Self {
        let mut known_signatures = HashMap::new();

        // Add default test signature
        known_signatures.insert("test_signature".to_string(), SignatureData {
            algorithm: "RSA-PKCS1-SHA256".to_string(),
            data: b"Hello, World!".to_vec(),
            signature: vec![0x49; 256], // Mock signature
        });

        Self {
            known_signatures,
        }
    }
}

/// Signature test data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureData {
    pub algorithm: String,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl MockConfig {
    /// Create a configuration for deterministic testing
    pub fn deterministic() -> Self {
        Self {
            deterministic: true,
            error_injection: None,
            performance_simulation: None,
            test_data: TestDataConfig::default(),
        }
    }

    /// Create a configuration with error injection enabled
    pub fn with_error_injection(operations: Vec<String>) -> Self {
        Self {
            deterministic: true,
            error_injection: Some(ErrorInjectionConfig {
                enabled: true,
                operations,
                probability: 1.0, // Always inject errors for testing
                error_types: vec!["MockError".to_string()],
            }),
            performance_simulation: None,
            test_data: TestDataConfig::default(),
        }
    }

    /// Create a configuration with performance simulation
    pub fn with_performance_simulation(delays: HashMap<String, Duration>) -> Self {
        Self {
            deterministic: true,
            error_injection: None,
            performance_simulation: Some(PerformanceSimulationConfig {
                enabled: true,
                operation_delays: delays,
                cpu_simulation: None,
                memory_simulation: None,
            }),
            test_data: TestDataConfig::default(),
        }
    }

    /// Load configuration from JSON file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: MockConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to JSON file
    pub fn to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Mock data generator for creating test vectors
pub struct MockDataGenerator {
    config: MockConfig,
    seed: u64,
}

impl MockDataGenerator {
    /// Create a new mock data generator
    pub fn new(config: MockConfig) -> Self {
        Self {
            config,
            seed: 12345, // Default deterministic seed
        }
    }

    /// Create a new mock data generator with custom seed
    pub fn with_seed(config: MockConfig, seed: u64) -> Self {
        Self {
            config,
            seed,
        }
    }

    /// Generate deterministic random data
    pub fn generate_data(&self, length: usize) -> Vec<u8> {
        if self.config.deterministic {
            // Generate deterministic data based on seed
            let mut data = Vec::with_capacity(length);
            for i in 0..length {
                data.push(((self.seed + i as u64) % 256) as u8);
            }
            data
        } else {
            use rand::RngCore;
            let mut data = vec![0u8; length];
            rand::thread_rng().fill_bytes(&mut data);
            data
        }
    }

    /// Generate a mock RSA key pair
    pub fn generate_rsa_keypair(&self, size: usize) -> RsaKeyData {
        RsaKeyData {
            size,
            public_exponent: vec![0x01, 0x00, 0x01], // 65537
            private_key: self.generate_data(size / 8),
            public_key: self.generate_data(size / 8),
        }
    }

    /// Generate a mock ECDSA key pair
    pub fn generate_ecdsa_keypair(&self, curve: &str) -> EcdsaKeyData {
        let key_size = match curve {
            "P-256" => 32,
            "P-384" => 48,
            "P-521" => 66,
            _ => 32,
        };

        EcdsaKeyData {
            curve: curve.to_string(),
            private_key: self.generate_data(key_size),
            public_key: self.generate_data(key_size * 2), // Uncompressed point
        }
    }

    /// Generate a mock symmetric key
    pub fn generate_symmetric_key(&self, algorithm: &str) -> SymmetricKeyData {
        let key_size = match algorithm {
            "AES-128" => 16,
            "AES-192" => 24,
            "AES-256" => 32,
            _ => 32,
        };

        SymmetricKeyData {
            algorithm: algorithm.to_string(),
            key_data: self.generate_data(key_size),
        }
    }

    /// Generate a mock certificate
    pub fn generate_certificate(&self, subject: &str) -> X509CertData {
        X509CertData {
            subject: subject.to_string(),
            issuer: "CN=Mock CA".to_string(),
            serial_number: self.generate_data(8),
            not_before: "2023-01-01T00:00:00Z".to_string(),
            not_after: "2024-01-01T00:00:00Z".to_string(),
            public_key: self.generate_data(64),
            der_data: self.generate_data(512),
        }
    }

    /// Generate a mock signature
    pub fn generate_signature(&self, algorithm: &str, data: &[u8]) -> SignatureData {
        let sig_size = match algorithm {
            "RSA-PKCS1-SHA256" => 256,
            "ECDSA-SHA256" => 64,
            _ => 64,
        };

        SignatureData {
            algorithm: algorithm.to_string(),
            data: data.to_vec(),
            signature: self.generate_data(sig_size),
        }
    }
}