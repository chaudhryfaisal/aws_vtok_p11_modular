//! AWS-LC crypto backend implementation.

use std::sync::Arc;
use aws_lc_rs::{signature, digest, rand};
use aws_lc_rs::rsa::KeySize;
use vtok_backend::traits::{CryptoBackend, Key};
use vtok_backend::types::{
    BackendResult, BackendError, KeyAlgorithm, KeyType, Mechanism,
    DigestAlgorithm, MechanismParams, ContextConfig,
};
use vtok_backend::BackendInfo;

use super::key::{AwsLcKey, AwsLcKeyPair, AwsLcCertificate};
use super::digest::AwsLcDigestContext;
use super::sign::AwsLcSignContext;
use super::verify::AwsLcVerifyContext;
use super::encrypt::AwsLcEncryptContext;
use super::decrypt::AwsLcDecryptContext;

/// AWS-LC crypto backend
pub struct AwsLcBackend {
    info: BackendInfo,
}

impl AwsLcBackend {
    /// Create a new AWS-LC backend
    pub fn new() -> BackendResult<Self> {
        let info = BackendInfo::new(
            "AWS-LC Backend",
            "1.0.0",
            "AWS-LC cryptographic backend implementation",
            vtok_backend::BackendCapabilities {
                hardware_keys: false,
                secure_storage: false,
                hardware_rng: true,
                side_channel_resistant: true,
            },
        );

        Ok(Self { info })
    }

    /// Convert vtok_backend Mechanism to AWS-LC algorithm
    fn mechanism_to_signature_algorithm(mechanism: &Mechanism) -> BackendResult<&'static signature::RsaEncoding> {
        match mechanism {
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) } => {
                Ok(&signature::RSA_PKCS1_SHA256)
            }
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha384) } => {
                Ok(&signature::RSA_PKCS1_SHA384)
            }
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha512) } => {
                Ok(&signature::RSA_PKCS1_SHA512)
            }
            Mechanism::RsaPkcs1Pss { digest: DigestAlgorithm::Sha256, .. } => {
                Ok(&signature::RSA_PSS_SHA256)
            }
            Mechanism::RsaPkcs1Pss { digest: DigestAlgorithm::Sha384, .. } => {
                Ok(&signature::RSA_PSS_SHA384)
            }
            Mechanism::RsaPkcs1Pss { digest: DigestAlgorithm::Sha512, .. } => {
                Ok(&signature::RSA_PSS_SHA512)
            }
            _ => Err(BackendError::UnsupportedMechanism(format!(
                "Mechanism {:?} not supported",
                mechanism
            ))),
        }
    }

    /// Convert vtok_backend Mechanism to AWS-LC ECDSA algorithm
    fn mechanism_to_ecdsa_algorithm(mechanism: &Mechanism) -> BackendResult<&'static signature::EcdsaSigningAlgorithm> {
        match mechanism {
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) } => {
                Ok(&signature::ECDSA_P256_SHA256_ASN1_SIGNING)
            }
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha384) } => {
                Ok(&signature::ECDSA_P384_SHA384_ASN1_SIGNING)
            }
            _ => Err(BackendError::UnsupportedMechanism(format!(
                "ECDSA mechanism {:?} not supported",
                mechanism
            ))),
        }
    }
}

impl CryptoBackend for AwsLcBackend {
    type Key = AwsLcKey;
    type KeyPair = AwsLcKeyPair;
    type Certificate = AwsLcCertificate;
    type DigestContext = AwsLcDigestContext;
    type SignContext = AwsLcSignContext;
    type VerifyContext = AwsLcVerifyContext;
    type EncryptContext = AwsLcEncryptContext;
    type DecryptContext = AwsLcDecryptContext;

    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn supports_mechanism(&self, mechanism: &Mechanism) -> bool {
        match mechanism {
            Mechanism::Digest(_) => true,
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) } => true,
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha384) } => true,
            Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha512) } => true,
            Mechanism::RsaPkcs1Pss { digest: DigestAlgorithm::Sha256, .. } => true,
            Mechanism::RsaPkcs1Pss { digest: DigestAlgorithm::Sha384, .. } => true,
            Mechanism::RsaPkcs1Pss { digest: DigestAlgorithm::Sha512, .. } => true,
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) } => true,
            Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha384) } => true,
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
        let rng = rand::SystemRandom::new();

        match algorithm {
            KeyAlgorithm::Rsa2048 => {
                let key_pair = signature::RsaKeyPair::generate(KeySize::Rsa2048)
                    .map_err(|e| BackendError::KeyGeneration(format!("RSA key generation failed: {}", e)))?;
                
                let private_key = AwsLcKey::new_rsa_keypair(key_pair, algorithm, KeyType::Private)?;
                let public_key_bytes = private_key.export_public_key()?;
                // For now, create a simple public key representation
                // In a real implementation, you'd properly parse the public key bytes
                let public_key_components = signature::RsaPublicKeyComponents {
                    n: public_key_bytes,
                    e: vec![0x01, 0x00, 0x01], // Standard RSA exponent
                };
                let public_key = AwsLcKey::new_rsa_public_key(public_key_components, algorithm)?;
                
                Ok(AwsLcKeyPair::new(private_key, public_key))
            }
            KeyAlgorithm::EcdsaP256 => {
                let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .map_err(|e| BackendError::KeyGeneration(format!("ECDSA key generation failed: {}", e)))?;
                
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref())
                    .map_err(|e| BackendError::KeyGeneration(format!("ECDSA key pair creation failed: {}", e)))?;
                
                let private_key = AwsLcKey::new_ecdsa_keypair(key_pair, algorithm, KeyType::Private)?;
                let public_key_der = private_key.export_public_key()?;
                let public_key = AwsLcKey::new_ecdsa_public_key(public_key_der, algorithm)?;
                
                Ok(AwsLcKeyPair::new(private_key, public_key))
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
        match algorithm {
            KeyAlgorithm::Aes256 => {
                let mut key_bytes = vec![0u8; 32];
                rand::fill(&mut key_bytes)
                    .map_err(|e| BackendError::KeyGeneration(format!("AES key generation failed: {}", e)))?;
                
                AwsLcKey::new_symmetric_key(key_bytes, algorithm)
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
        match (key_type, algorithm) {
            (KeyType::Secret, KeyAlgorithm::Aes256) => {
                if key_data.len() != 32 {
                    return Err(BackendError::InvalidKeyData("AES-256 key must be 32 bytes".to_string()));
                }
                AwsLcKey::new_symmetric_key(key_data.to_vec(), algorithm)
            }
            _ => Err(BackendError::UnsupportedAlgorithm(format!(
                "Key import for {:?} {:?} not supported",
                key_type, algorithm
            ))),
        }
    }

    async fn import_keypair(
        &self,
        _algorithm: KeyAlgorithm,
        _private_key_data: &[u8],
        _public_key_data: Option<&[u8]>,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::KeyPair> {
        Err(BackendError::UnsupportedOperation("Key pair import not implemented".to_string()))
    }

    async fn import_certificate(
        &self,
        _cert_data: &[u8],
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::Certificate> {
        Err(BackendError::UnsupportedOperation("Certificate import not implemented".to_string()))
    }

    async fn create_digest_context(
        &self,
        algorithm: DigestAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::DigestContext> {
        AwsLcDigestContext::new(algorithm)
    }

    async fn create_sign_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::SignContext> {
        AwsLcSignContext::new(mechanism, key.clone())
    }

    async fn create_verify_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::VerifyContext> {
        AwsLcVerifyContext::new(mechanism, key.clone())
    }

    async fn create_encrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::EncryptContext> {
        AwsLcEncryptContext::new(mechanism, key.clone())
    }

    async fn create_decrypt_context(
        &self,
        mechanism: Mechanism,
        key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::DecryptContext> {
        AwsLcDecryptContext::new(mechanism, key.clone())
    }

    async fn generate_random(&self, length: usize) -> BackendResult<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        rand::fill(&mut bytes)
            .map_err(|e| BackendError::RandomGeneration(format!("Random generation failed: {}", e)))?;
        Ok(bytes)
    }

    async fn derive_key(
        &self,
        _mechanism: Mechanism,
        _base_key: &Self::Key,
        _params: &MechanismParams,
        _target_algorithm: KeyAlgorithm,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Self::Key> {
        Err(BackendError::UnsupportedOperation("Key derivation not implemented".to_string()))
    }

    async fn key_agreement(
        &self,
        _mechanism: Mechanism,
        _private_key: &Self::Key,
        _public_key: &Self::Key,
        _config: Option<ContextConfig>,
    ) -> BackendResult<Vec<u8>> {
        Err(BackendError::UnsupportedOperation("Key agreement not implemented".to_string()))
    }
}

impl Default for AwsLcBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create AWS-LC backend")
    }
}