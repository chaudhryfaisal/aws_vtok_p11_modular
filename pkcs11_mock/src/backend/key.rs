//! Mock key implementations.

use std::collections::HashMap;
use std::sync::Arc;
use vtok_backend::traits::{Key, KeyPair, Certificate};
use vtok_backend::types::{BackendResult, BackendError, KeyAlgorithm, KeyType};
use vtok_backend::types::key::KeyUsage;
use sha2::{Sha256, Digest};

use crate::data::{MockConfig, RsaKeyData, EcdsaKeyData, SymmetricKeyData, X509CertData, MockDataGenerator};

/// Mock key implementation
#[derive(Debug, Clone)]
pub struct MockKey {
    algorithm: KeyAlgorithm,
    key_type: KeyType,
    key_data: Vec<u8>,
    key_id: Option<Vec<u8>>,
    label: Option<String>,
    usage: KeyUsage,
    extractable: bool,
    sensitive: bool,
    attributes: HashMap<String, Vec<u8>>,
}

impl MockKey {
    /// Create a new mock RSA private key
    pub fn new_rsa_private(algorithm: KeyAlgorithm, config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        let key_size = algorithm.key_size_bits();
        let key_data = generator.generate_data(key_size / 8);
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Private,
            key_data,
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Mock RSA Private Key {}", key_size)),
            usage: KeyUsage {
                sign: true,
                decrypt: true,
                derive: false,
                verify: false,
                encrypt: false,
                wrap: false,
                unwrap: false,
            },
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Create a new mock RSA public key
    pub fn new_rsa_public(algorithm: KeyAlgorithm, config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        let key_size = algorithm.key_size_bits();
        let key_data = generator.generate_data(key_size / 8);
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Public,
            key_data,
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Mock RSA Public Key {}", key_size)),
            usage: KeyUsage {
                sign: false,
                decrypt: false,
                derive: false,
                verify: true,
                encrypt: true,
                wrap: false,
                unwrap: false,
            },
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Create a new mock ECDSA private key
    pub fn new_ecdsa_private(algorithm: KeyAlgorithm, config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        let key_size = algorithm.key_size_bits();
        let key_data = generator.generate_data(key_size / 8);
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Private,
            key_data,
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Mock ECDSA Private Key {}", key_size)),
            usage: KeyUsage {
                sign: true,
                decrypt: false,
                derive: true,
                verify: false,
                encrypt: false,
                wrap: false,
                unwrap: false,
            },
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Create a new mock ECDSA public key
    pub fn new_ecdsa_public(algorithm: KeyAlgorithm, config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        let key_size = algorithm.key_size_bits();
        let key_data = generator.generate_data(key_size / 8 * 2); // Uncompressed point
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Public,
            key_data,
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Mock ECDSA Public Key {}", key_size)),
            usage: KeyUsage {
                sign: false,
                decrypt: false,
                derive: true,
                verify: true,
                encrypt: false,
                wrap: false,
                unwrap: false,
            },
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Create a new mock symmetric key
    pub fn new_symmetric(algorithm: KeyAlgorithm, config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        let key_size = algorithm.key_size_bits();
        let key_data = generator.generate_data(key_size / 8);
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Secret,
            key_data,
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Mock Symmetric Key {}", key_size)),
            usage: KeyUsage {
                sign: false,
                decrypt: true,
                derive: true,
                verify: false,
                encrypt: true,
                wrap: true,
                unwrap: true,
            },
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Import a symmetric key from raw data
    pub fn import_symmetric(algorithm: KeyAlgorithm, key_data: &[u8], config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Secret,
            key_data: key_data.to_vec(),
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Imported Symmetric Key")),
            usage: KeyUsage {
                sign: false,
                decrypt: true,
                derive: true,
                verify: false,
                encrypt: true,
                wrap: true,
                unwrap: true,
            },
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Import a private key from raw data
    pub fn import_private(algorithm: KeyAlgorithm, key_data: &[u8], config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        
        let usage = match algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => KeyUsage {
                sign: true,
                decrypt: true,
                derive: false,
                verify: false,
                encrypt: false,
                wrap: false,
                unwrap: false,
            },
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => KeyUsage {
                sign: true,
                decrypt: false,
                derive: true,
                verify: false,
                encrypt: false,
                wrap: false,
                unwrap: false,
            },
            _ => KeyUsage::default(),
        };
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Private,
            key_data: key_data.to_vec(),
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Imported Private Key")),
            usage,
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Import a public key from raw data
    pub fn import_public(algorithm: KeyAlgorithm, key_data: &[u8], config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        
        let usage = match algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => KeyUsage {
                sign: false,
                decrypt: false,
                derive: false,
                verify: true,
                encrypt: true,
                wrap: false,
                unwrap: false,
            },
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => KeyUsage {
                sign: false,
                decrypt: false,
                derive: true,
                verify: true,
                encrypt: false,
                wrap: false,
                unwrap: false,
            },
            _ => KeyUsage::default(),
        };
        
        Ok(Self {
            algorithm,
            key_type: KeyType::Public,
            key_data: key_data.to_vec(),
            key_id: Some(generator.generate_data(16)),
            label: Some(format!("Imported Public Key")),
            usage,
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Derive public key from private key (mock implementation)
    pub fn derive_public_from_private(private_key: &MockKey) -> BackendResult<Self> {
        if private_key.key_type != KeyType::Private {
            return Err(BackendError::InvalidKeyData("Not a private key".to_string()));
        }

        // Mock derivation - in reality this would involve actual cryptographic operations
        let mut public_key_data = private_key.key_data.clone();
        // Modify the data slightly to simulate public key derivation
        for byte in &mut public_key_data {
            *byte = byte.wrapping_add(1);
        }

        let usage = match private_key.algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => KeyUsage {
                sign: false,
                decrypt: false,
                derive: false,
                verify: true,
                encrypt: true,
                wrap: false,
                unwrap: false,
            },
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => KeyUsage {
                sign: false,
                decrypt: false,
                derive: true,
                verify: true,
                encrypt: false,
                wrap: false,
                unwrap: false,
            },
            _ => KeyUsage::default(),
        };

        Ok(Self {
            algorithm: private_key.algorithm,
            key_type: KeyType::Public,
            key_data: public_key_data,
            key_id: private_key.key_id.clone(),
            label: Some(format!("Derived Public Key")),
            usage,
            extractable: true,
            sensitive: false,
            attributes: HashMap::new(),
        })
    }

    /// Get the raw key data
    pub fn key_data(&self) -> &[u8] {
        &self.key_data
    }
}

impl Key for MockKey {
    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_type(&self) -> KeyType {
        self.key_type
    }

    fn key_size(&self) -> usize {
        self.algorithm.key_size_bits()
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.key_id.as_deref()
    }

    fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    fn usage(&self) -> KeyUsage {
        self.usage
    }

    fn is_extractable(&self) -> bool {
        self.extractable
    }

    fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    fn export_key(&self) -> BackendResult<Vec<u8>> {
        if !self.extractable {
            return Err(BackendError::KeyNotExtractable("Key is not extractable".to_string()));
        }
        if self.sensitive {
            return Err(BackendError::KeySensitive("Key is sensitive".to_string()));
        }
        Ok(self.key_data.clone())
    }

    fn export_public_key(&self) -> BackendResult<Vec<u8>> {
        match self.key_type {
            KeyType::Public => Ok(self.key_data.clone()),
            KeyType::Private => {
                // Mock public key derivation from private key
                let mut public_data = self.key_data.clone();
                for byte in &mut public_data {
                    *byte = byte.wrapping_add(1);
                }
                Ok(public_data)
            }
            KeyType::Secret => Err(BackendError::InvalidKeyType("Symmetric keys don't have public components".to_string())),
        }
    }

    fn attributes(&self) -> HashMap<String, Vec<u8>> {
        self.attributes.clone()
    }

    fn set_attribute(&mut self, name: &str, value: Vec<u8>) -> BackendResult<()> {
        // Check for read-only attributes
        match name {
            "CKA_CLASS" | "CKA_KEY_TYPE" | "CKA_MODULUS" | "CKA_PUBLIC_EXPONENT" => {
                return Err(BackendError::ReadOnlyAttribute(format!("Attribute {} is read-only", name)));
            }
            _ => {}
        }
        
        self.attributes.insert(name.to_string(), value);
        Ok(())
    }

    fn fingerprint(&self) -> BackendResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(&self.key_data);
        Ok(hasher.finalize().to_vec())
    }
}

/// Mock key pair implementation
#[derive(Debug, Clone)]
pub struct MockKeyPair {
    private_key: MockKey,
    public_key: MockKey,
}

impl MockKeyPair {
    /// Create a new mock key pair
    pub fn new(private_key: MockKey, public_key: MockKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl KeyPair for MockKeyPair {
    type Key = MockKey;

    fn private_key(&self) -> &Self::Key {
        &self.private_key
    }

    fn public_key(&self) -> &Self::Key {
        &self.public_key
    }
}

/// Mock certificate implementation
#[derive(Debug, Clone)]
pub struct MockCertificate {
    subject: String,
    issuer: String,
    serial_number: Vec<u8>,
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
    public_key: MockKey,
    der_data: Vec<u8>,
    extensions: HashMap<String, Vec<u8>>,
}

impl MockCertificate {
    /// Import a certificate from DER data
    pub fn import(cert_data: &[u8], config: &MockConfig) -> BackendResult<Self> {
        let generator = MockDataGenerator::new(config.clone());
        
        // Mock certificate parsing - in reality this would parse actual DER data
        let public_key = MockKey::new_rsa_public(KeyAlgorithm::Rsa2048, config)?;
        
        let not_before = std::time::SystemTime::now();
        let not_after = not_before + std::time::Duration::from_secs(365 * 24 * 3600); // 1 year
        
        Ok(Self {
            subject: "CN=Mock Certificate".to_string(),
            issuer: "CN=Mock CA".to_string(),
            serial_number: generator.generate_data(8),
            not_before,
            not_after,
            public_key,
            der_data: cert_data.to_vec(),
            extensions: HashMap::new(),
        })
    }
}

impl Certificate for MockCertificate {
    type Key = MockKey;

    fn subject(&self) -> BackendResult<String> {
        Ok(self.subject.clone())
    }

    fn issuer(&self) -> BackendResult<String> {
        Ok(self.issuer.clone())
    }

    fn serial_number(&self) -> BackendResult<Vec<u8>> {
        Ok(self.serial_number.clone())
    }

    fn validity(&self) -> BackendResult<(std::time::SystemTime, std::time::SystemTime)> {
        Ok((self.not_before, self.not_after))
    }

    fn public_key(&self) -> BackendResult<Self::Key> {
        Ok(self.public_key.clone())
    }

    fn fingerprint_sha1(&self) -> BackendResult<Vec<u8>> {
        use sha2::Sha1;
        let mut hasher = Sha1::new();
        hasher.update(&self.der_data);
        Ok(hasher.finalize().to_vec())
    }

    fn fingerprint_sha256(&self) -> BackendResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(&self.der_data);
        Ok(hasher.finalize().to_vec())
    }

    fn export_der(&self) -> BackendResult<Vec<u8>> {
        Ok(self.der_data.clone())
    }

    fn export_pem(&self) -> BackendResult<String> {
        // Mock PEM encoding
        let base64_data = base64::encode(&self.der_data);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64_data
        );
        Ok(pem)
    }

    fn verify_signature(&self, _issuer_key: &Self::Key) -> BackendResult<bool> {
        // Mock signature verification - always returns true for testing
        Ok(true)
    }

    fn extensions(&self) -> BackendResult<HashMap<String, Vec<u8>>> {
        Ok(self.extensions.clone())
    }

    fn has_key_usage(&self, _usage: KeyUsage) -> BackendResult<bool> {
        // Mock key usage check - always returns true for testing
        Ok(true)
    }

    fn version(&self) -> BackendResult<u32> {
        Ok(3) // X.509 v3
    }

    fn signature_algorithm(&self) -> BackendResult<String> {
        Ok("sha256WithRSAEncryption".to_string())
    }

    fn public_key_algorithm(&self) -> BackendResult<KeyAlgorithm> {
        Ok(self.public_key.algorithm())
    }
}

// Add base64 encoding for PEM export
mod base64 {
    pub fn encode(data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        
        for chunk in data.chunks(3) {
            let mut buf = [0u8; 3];
            for (i, &byte) in chunk.iter().enumerate() {
                buf[i] = byte;
            }
            
            let b = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
            
            result.push(CHARS[((b >> 18) & 63) as usize] as char);
            result.push(CHARS[((b >> 12) & 63) as usize] as char);
            result.push(if chunk.len() > 1 { CHARS[((b >> 6) & 63) as usize] as char } else { '=' });
            result.push(if chunk.len() > 2 { CHARS[(b & 63) as usize] as char } else { '=' });
            
            if result.len() % 76 == 0 {
                result.push('\n');
            }
        }
        
        result
    }
}