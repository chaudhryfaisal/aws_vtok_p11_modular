//! Key management traits.
//!
//! This module defines traits for keys, key pairs, and certificates.
//! These traits provide a common interface for different key types
//! and enable type-safe key operations.

use crate::types::{BackendError, BackendResult, KeyAlgorithm, KeyType};
use crate::types::key::KeyUsage;
use std::collections::HashMap;

/// Trait representing a cryptographic key.
///
/// This trait provides a common interface for all types of cryptographic keys,
/// including symmetric keys, public keys, and private keys.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple PKCS#11 sessions.
pub trait Key: Send + Sync + std::fmt::Debug {
    /// Get the key algorithm
    fn algorithm(&self) -> KeyAlgorithm;

    /// Get the key type (public, private, or symmetric)
    fn key_type(&self) -> KeyType;

    /// Get the key size in bits
    fn key_size(&self) -> usize;

    /// Get the key ID (if any)
    fn key_id(&self) -> Option<&[u8]>;

    /// Get the key label (if any)
    fn label(&self) -> Option<&str>;

    /// Get the key usage flags
    fn usage(&self) -> KeyUsage;

    /// Check if the key can be used for signing
    fn can_sign(&self) -> bool {
        self.usage().sign
    }

    /// Check if the key can be used for verification
    fn can_verify(&self) -> bool {
        self.usage().verify
    }

    /// Check if the key can be used for encryption
    fn can_encrypt(&self) -> bool {
        self.usage().encrypt
    }

    /// Check if the key can be used for decryption
    fn can_decrypt(&self) -> bool {
        self.usage().decrypt
    }

    /// Check if the key can be used for key derivation
    fn can_derive(&self) -> bool {
        self.usage().derive
    }

    /// Check if the key can be used for key wrapping
    fn can_wrap(&self) -> bool {
        self.usage().wrap
    }

    /// Check if the key can be used for key unwrapping
    fn can_unwrap(&self) -> bool {
        self.usage().unwrap
    }

    /// Check if the key is extractable (can export key material)
    fn is_extractable(&self) -> bool;

    /// Check if the key is sensitive (key material cannot be revealed)
    fn is_sensitive(&self) -> bool;

    /// Check if the key is stored in hardware
    fn is_hardware(&self) -> bool {
        false
    }

    /// Check if the key is a token object (persistent)
    fn is_token(&self) -> bool {
        false
    }

    /// Export the key material (if extractable)
    ///
    /// # Returns
    ///
    /// The raw key material
    ///
    /// # Errors
    ///
    /// Returns `BackendError::KeyNotExtractable` if the key is not extractable.
    /// Returns `BackendError::KeySensitive` if the key is sensitive.
    fn export_key(&self) -> BackendResult<Vec<u8>>;

    /// Export the public key material (for asymmetric keys)
    ///
    /// # Returns
    ///
    /// The public key material
    ///
    /// # Errors
    ///
    /// Returns `BackendError::InvalidKeyType` if this is not an asymmetric key.
    fn export_public_key(&self) -> BackendResult<Vec<u8>>;

    /// Export the key in a standard format
    ///
    /// For public keys: SubjectPublicKeyInfo (SPKI) DER encoding
    /// For private keys: PKCS#8 DER encoding
    /// For symmetric keys: raw key material
    ///
    /// # Returns
    ///
    /// The key in standard format
    ///
    /// # Errors
    ///
    /// Returns `BackendError::KeyNotExtractable` if the key is not extractable.
    fn export_standard_format(&self) -> BackendResult<Vec<u8>> {
        match self.key_type() {
            KeyType::Public => self.export_public_key(),
            KeyType::Private | KeyType::Secret => self.export_key(),
        }
    }

    /// Get key attributes as a map
    fn attributes(&self) -> HashMap<String, Vec<u8>>;

    /// Set a key attribute
    ///
    /// # Arguments
    ///
    /// * `name` - The attribute name
    /// * `value` - The attribute value
    ///
    /// # Errors
    ///
    /// Returns `BackendError::ReadOnlyAttribute` if the attribute is read-only.
    fn set_attribute(&mut self, name: &str, value: Vec<u8>) -> BackendResult<()>;

    /// Get a specific attribute value
    ///
    /// # Arguments
    ///
    /// * `name` - The attribute name
    ///
    /// # Returns
    ///
    /// The attribute value if it exists
    fn get_attribute(&self, name: &str) -> Option<Vec<u8>> {
        self.attributes().get(name).cloned()
    }

    /// Check if the key has a specific attribute
    ///
    /// # Arguments
    ///
    /// * `name` - The attribute name
    ///
    /// # Returns
    ///
    /// True if the attribute exists
    fn has_attribute(&self, name: &str) -> bool {
        self.attributes().contains_key(name)
    }

    /// Get the key fingerprint (hash of key material)
    ///
    /// # Returns
    ///
    /// SHA-256 hash of the key material
    fn fingerprint(&self) -> BackendResult<Vec<u8>>;

    /// Clone the key (if supported)
    ///
    /// # Returns
    ///
    /// A cloned copy of the key
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if cloning is not supported.
    fn clone_key(&self) -> BackendResult<Box<dyn Key>> {
        Err(BackendError::UnsupportedOperation(
            "Key cloning not supported".to_string()
        ))
    }
}

/// Trait representing a cryptographic key pair.
///
/// This trait provides access to both the public and private keys
/// in an asymmetric key pair.
pub trait KeyPair: Send + Sync + std::fmt::Debug {
    /// The key type used by this key pair
    type Key: Key;

    /// Get the private key
    fn private_key(&self) -> &Self::Key;

    /// Get the public key
    fn public_key(&self) -> &Self::Key;

    /// Get the key algorithm
    fn algorithm(&self) -> KeyAlgorithm {
        self.private_key().algorithm()
    }

    /// Get the key size in bits
    fn key_size(&self) -> usize {
        self.private_key().key_size()
    }

    /// Get the key pair ID (if any)
    fn key_id(&self) -> Option<&[u8]> {
        self.private_key().key_id()
    }

    /// Get the key pair label (if any)
    fn label(&self) -> Option<&str> {
        self.private_key().label()
    }

    /// Export the public key in a standard format (e.g., SubjectPublicKeyInfo)
    fn export_public_key_info(&self) -> BackendResult<Vec<u8>> {
        self.public_key().export_standard_format()
    }

    /// Export the private key in a standard format (e.g., PKCS#8)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::KeyNotExtractable` if the private key is not extractable.
    fn export_private_key_info(&self) -> BackendResult<Vec<u8>> {
        self.private_key().export_standard_format()
    }

    /// Export both keys as a key pair structure
    ///
    /// # Returns
    ///
    /// A tuple of (private_key_data, public_key_data)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::KeyNotExtractable` if the private key is not extractable.
    fn export_keypair(&self) -> BackendResult<(Vec<u8>, Vec<u8>)> {
        let private_data = self.export_private_key_info()?;
        let public_data = self.export_public_key_info()?;
        Ok((private_data, public_data))
    }

    /// Get the key pair fingerprint
    ///
    /// # Returns
    ///
    /// SHA-256 hash of the public key material
    fn fingerprint(&self) -> BackendResult<Vec<u8>> {
        self.public_key().fingerprint()
    }

    /// Check if the private key is extractable
    fn is_private_extractable(&self) -> bool {
        self.private_key().is_extractable()
    }

    /// Check if the private key is sensitive
    fn is_private_sensitive(&self) -> bool {
        self.private_key().is_sensitive()
    }

    /// Check if the keys are stored in hardware
    fn is_hardware(&self) -> bool {
        self.private_key().is_hardware() || self.public_key().is_hardware()
    }
}

/// Trait representing an X.509 certificate.
///
/// This trait provides access to certificate information and
/// the associated public key.
pub trait Certificate: Send + Sync + std::fmt::Debug {
    /// The key type used by this certificate
    type Key: Key;

    /// Get the certificate subject
    fn subject(&self) -> BackendResult<String>;

    /// Get the certificate issuer
    fn issuer(&self) -> BackendResult<String>;

    /// Get the certificate serial number
    fn serial_number(&self) -> BackendResult<Vec<u8>>;

    /// Get the certificate validity period (not_before, not_after)
    fn validity(&self) -> BackendResult<(std::time::SystemTime, std::time::SystemTime)>;

    /// Get the public key from the certificate
    fn public_key(&self) -> BackendResult<Self::Key>;

    /// Get the certificate fingerprint (SHA-1)
    fn fingerprint_sha1(&self) -> BackendResult<Vec<u8>>;

    /// Get the certificate fingerprint (SHA-256)
    fn fingerprint_sha256(&self) -> BackendResult<Vec<u8>>;

    /// Export the certificate in DER format
    fn export_der(&self) -> BackendResult<Vec<u8>>;

    /// Export the certificate in PEM format
    fn export_pem(&self) -> BackendResult<String>;

    /// Verify the certificate signature using the provided public key
    ///
    /// # Arguments
    ///
    /// * `issuer_key` - The issuer's public key
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    fn verify_signature(&self, issuer_key: &Self::Key) -> BackendResult<bool>;

    /// Check if the certificate is currently valid (not expired)
    fn is_valid(&self) -> BackendResult<bool> {
        let now = std::time::SystemTime::now();
        let (not_before, not_after) = self.validity()?;
        Ok(now >= not_before && now <= not_after)
    }

    /// Get certificate extensions
    fn extensions(&self) -> BackendResult<HashMap<String, Vec<u8>>>;

    /// Check if the certificate has a specific key usage
    fn has_key_usage(&self, usage: KeyUsage) -> BackendResult<bool>;

    /// Get the certificate version
    fn version(&self) -> BackendResult<u32>;

    /// Get the signature algorithm used to sign the certificate
    fn signature_algorithm(&self) -> BackendResult<String>;

    /// Get the public key algorithm from the certificate
    fn public_key_algorithm(&self) -> BackendResult<KeyAlgorithm>;

    /// Check if this is a CA certificate
    fn is_ca(&self) -> BackendResult<bool> {
        // Check the Basic Constraints extension
        let extensions = self.extensions()?;
        if let Some(basic_constraints) = extensions.get("2.5.29.19") {
            // Basic Constraints OID
            // This is a simplified check - real implementation would parse ASN.1
            Ok(!basic_constraints.is_empty() && basic_constraints[0] != 0)
        } else {
            Ok(false)
        }
    }

    /// Check if this certificate is self-signed
    fn is_self_signed(&self) -> BackendResult<bool> {
        let subject = self.subject()?;
        let issuer = self.issuer()?;
        Ok(subject == issuer)
    }

    /// Get the certificate's key identifier (if present)
    fn key_identifier(&self) -> BackendResult<Option<Vec<u8>>> {
        let extensions = self.extensions()?;
        // Subject Key Identifier OID: 2.5.29.14
        Ok(extensions.get("2.5.29.14").cloned())
    }

    /// Get the authority key identifier (if present)
    fn authority_key_identifier(&self) -> BackendResult<Option<Vec<u8>>> {
        let extensions = self.extensions()?;
        // Authority Key Identifier OID: 2.5.29.35
        Ok(extensions.get("2.5.29.35").cloned())
    }
}

/// X.509 certificate key usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

impl CertKeyUsage {
    /// Get the bit position for this key usage in the key usage extension
    pub fn bit_position(&self) -> u8 {
        match self {
            CertKeyUsage::DigitalSignature => 0,
            CertKeyUsage::NonRepudiation => 1,
            CertKeyUsage::KeyEncipherment => 2,
            CertKeyUsage::DataEncipherment => 3,
            CertKeyUsage::KeyAgreement => 4,
            CertKeyUsage::KeyCertSign => 5,
            CertKeyUsage::CrlSign => 6,
            CertKeyUsage::EncipherOnly => 7,
            CertKeyUsage::DecipherOnly => 8,
        }
    }

    /// Get all key usage flags
    pub fn all() -> Vec<CertKeyUsage> {
        vec![
            CertKeyUsage::DigitalSignature,
            CertKeyUsage::NonRepudiation,
            CertKeyUsage::KeyEncipherment,
            CertKeyUsage::DataEncipherment,
            CertKeyUsage::KeyAgreement,
            CertKeyUsage::KeyCertSign,
            CertKeyUsage::CrlSign,
            CertKeyUsage::EncipherOnly,
            CertKeyUsage::DecipherOnly,
        ]
    }
}