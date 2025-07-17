//! Key management bridge for vtok_backend integration.
//!
//! This module provides key-related functionality that bridges between
//! PKCS#11 key objects and vtok_backend key traits.

use std::sync::Arc;
use vtok_backend::traits::{Key, KeyPair, Certificate};
use vtok_backend::types::{BackendResult, KeyAlgorithm, KeyType};
use crate::backend::db::{Object, ObjectKind};
use crate::backend::Mechanism;
use crate::{Error, Result};

/// A bridge wrapper for keys that implements vtok_backend Key trait
pub struct BridgeKey {
    pem_data: String,
    key_type: KeyType,
    algorithm: KeyAlgorithm,
}

impl BridgeKey {
    /// Create a new BridgeKey from PEM data
    pub fn from_pem(pem_data: String, key_type: KeyType, algorithm: KeyAlgorithm) -> Self {
        Self {
            pem_data,
            key_type,
            algorithm,
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

    fn key_size_bits(&self) -> BackendResult<usize> {
        // For now, return a default size based on algorithm
        // In a real implementation, this would parse the key to get actual size
        match self.algorithm {
            KeyAlgorithm::Rsa => Ok(2048), // Default RSA size
            KeyAlgorithm::Ec => Ok(256),   // Default EC size (P-256)
            _ => Ok(256),
        }
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
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::Rsa))
                }
                ObjectKind::RsaPublicKey(pem) if !is_private => {
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::Rsa))
                }
                _ => Err(Error::KeyTypeInconsistent),
            }
        }
        Mechanism::Ecdsa(..) => {
            match obj.kind() {
                ObjectKind::EcPrivateKey(pem) if is_private => {
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::Ec))
                }
                ObjectKind::EcPublicKey(pem) if !is_private => {
                    Ok(BridgeKey::from_pem(pem.clone(), key_type, KeyAlgorithm::Ec))
                }
                _ => Err(Error::KeyTypeInconsistent),
            }
        }
        _ => Err(Error::MechanismInvalid),
    }
}