//! Key management bridge for vtok_backend integration.
//!
//! This module provides key-related functionality that bridges between
//! PKCS#11 key objects and vtok_backend key traits.

use std::sync::Arc;
use std::collections::HashMap;
use vtok_backend::traits::{Key, KeyPair, Certificate};
use vtok_backend::types::{BackendResult, BackendError, KeyAlgorithm, KeyType};
use vtok_backend::types::key::KeyUsage;
use crate::backend::db::{Object, ObjectKind};
use crate::backend::Mechanism;
use crate::{Error, Result};

/// A bridge wrapper for keys that implements vtok_backend Key trait
#[derive(Debug)]
pub struct BridgeKey {
    pem_data: String,
    key_type: KeyType,
    algorithm: KeyAlgorithm,
    key_id: Option<Vec<u8>>,
    label: Option<String>,
    usage: KeyUsage,
}

impl BridgeKey {
    /// Create a new BridgeKey from PEM data
    pub fn from_pem(pem_data: String, key_type: KeyType, algorithm: KeyAlgorithm) -> Self {
        Self {
            pem_data,
            key_type,
            algorithm,
            key_id: None,
            label: None,
            usage: KeyUsage::all(), // Default to all usages allowed
        }
    }

    /// Create a BridgeKey from a PKCS#11 object
    pub fn from_p11_object(obj: &Object) -> Result<Self> {
        match obj.kind() {
            ObjectKind::RsaPrivateKey(pem) => Ok(Self::from_pem(
                pem.clone(),
                KeyType::Private,
                KeyAlgorithm::Rsa2048, // Default to 2048-bit RSA
            )),
            ObjectKind::RsaPublicKey(pem) => Ok(Self::from_pem(
                pem.clone(),
                KeyType::Public,
                KeyAlgorithm::Rsa2048, // Default to 2048-bit RSA
            )),
            ObjectKind::EcPrivateKey(pem) => Ok(Self::from_pem(
                pem.clone(),
                KeyType::Private,
                KeyAlgorithm::EcdsaP256, // Default to P-256 curve
            )),
            ObjectKind::EcPublicKey(pem) => Ok(Self::from_pem(
                pem.clone(),
                KeyType::Public,
                KeyAlgorithm::EcdsaP256, // Default to P-256 curve
            )),
            _ => Err(Error::KeyTypeInconsistent),
        }
    }

    /// Get the PEM data
    pub fn pem_data(&self) -> &str {
        &self.pem_data
    }
}

impl Key for BridgeKey {
    fn key_type(&self) -> KeyType {
        self.key_type
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }


    fn is_extractable(&self) -> bool {
        // For this implementation, assume keys are extractable
        // In a real implementation, this would check key attributes
        true
    }

    fn is_sensitive(&self) -> bool {
        // Private keys are considered sensitive
        matches!(self.key_type, KeyType::Private)
    }

    fn export_public_key(&self) -> BackendResult<Vec<u8>> {
        // Return the PEM data as bytes
        // In a real implementation, this would extract just the public key portion
        Ok(self.pem_data.as_bytes().to_vec())
    }

    fn key_size(&self) -> usize {
        // Return the key size based on algorithm
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

    fn export_key(&self) -> BackendResult<Vec<u8>> {
        if !self.is_extractable() {
            return Err(BackendError::KeyNotExtractable);
        }
        if self.is_sensitive() && matches!(self.key_type, KeyType::Private) {
            return Err(BackendError::KeySensitive);
        }
        // Return the PEM data as bytes
        Ok(self.pem_data.as_bytes().to_vec())
    }

    fn attributes(&self) -> HashMap<String, Vec<u8>> {
        let mut attrs = HashMap::new();
        
        // Add basic attributes
        attrs.insert("algorithm".to_string(), self.algorithm.name().as_bytes().to_vec());
        attrs.insert("key_type".to_string(), self.key_type.name().as_bytes().to_vec());
        attrs.insert("key_size".to_string(), self.key_size().to_string().as_bytes().to_vec());
        
        if let Some(ref key_id) = self.key_id {
            attrs.insert("key_id".to_string(), key_id.clone());
        }
        
        if let Some(ref label) = self.label {
            attrs.insert("label".to_string(), label.as_bytes().to_vec());
        }
        
        attrs
    }

    fn set_attribute(&mut self, name: &str, value: Vec<u8>) -> BackendResult<()> {
        match name {
            "key_id" => {
                self.key_id = Some(value);
                Ok(())
            }
            "label" => {
                self.label = Some(String::from_utf8(value).map_err(|_| {
                    BackendError::InvalidKeyData("Invalid UTF-8 in label".to_string())
                })?);
                Ok(())
            }
            _ => Err(BackendError::ReadOnlyAttribute(name.to_string()))
        }
    }

    fn fingerprint(&self) -> BackendResult<Vec<u8>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Create a simple fingerprint by hashing the PEM data
        let mut hasher = DefaultHasher::new();
        self.pem_data.hash(&mut hasher);
        let hash = hasher.finish();
        
        // Convert to bytes (this is a simplified implementation)
        Ok(hash.to_be_bytes().to_vec())
    }
}

/// Helper function to create a BridgeKey from a mechanism and PKCS#11 object
pub fn key_for_mechanism(mech: &Mechanism, obj: &Object, is_private: bool) -> Result<BridgeKey> {
    let key_type = if is_private {
        KeyType::Private
    } else {
        KeyType::Public
    };

    match mech {
        Mechanism::RsaX509 | Mechanism::RsaPkcs(..) | Mechanism::RsaPkcsPss(..) => {
            match obj.kind() {
                ObjectKind::RsaPrivateKey(pem) if is_private => {
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::Rsa2048))
                }
                ObjectKind::RsaPublicKey(pem) if !is_private => {
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::Rsa2048))
                }
                _ => Err(Error::KeyTypeInconsistent),
            }
        }
        Mechanism::Ecdsa(..) => {
            match obj.kind() {
                ObjectKind::EcPrivateKey(pem) if is_private => {
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::EcdsaP256))
                }
                ObjectKind::EcPublicKey(pem) if !is_private => {
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::EcdsaP256))
                }
                _ => Err(Error::KeyTypeInconsistent),
            }
        }
        _ => Err(Error::MechanismInvalid),
    }
}