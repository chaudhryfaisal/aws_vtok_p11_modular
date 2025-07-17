//! Key-related type definitions.
//!
//! This module defines enums and types related to cryptographic keys.

use serde::{Deserialize, Serialize};

/// Cryptographic key algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// RSA with 1024-bit key
    Rsa1024,
    /// RSA with 2048-bit key
    Rsa2048,
    /// RSA with 3072-bit key
    Rsa3072,
    /// RSA with 4096-bit key
    Rsa4096,
    /// RSA with 8192-bit key
    Rsa8192,
    /// ECDSA with P-224 curve
    EcdsaP224,
    /// ECDSA with P-256 curve (secp256r1)
    EcdsaP256,
    /// ECDSA with P-384 curve (secp384r1)
    EcdsaP384,
    /// ECDSA with P-521 curve (secp521r1)
    EcdsaP521,
    /// ECDSA with secp256k1 curve
    EcdsaSecp256k1,
    /// AES with 128-bit key
    Aes128,
    /// AES with 192-bit key
    Aes192,
    /// AES with 256-bit key
    Aes256,
    /// ChaCha20 with 256-bit key
    ChaCha20,
    /// Ed25519 signature algorithm
    Ed25519,
    /// X25519 key agreement algorithm
    X25519,
}

impl KeyAlgorithm {
    /// Get the key size in bits
    pub fn key_size_bits(&self) -> usize {
        match self {
            Self::Rsa1024 => 1024,
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::Rsa8192 => 8192,
            Self::EcdsaP224 => 224,
            Self::EcdsaP256 => 256,
            Self::EcdsaP384 => 384,
            Self::EcdsaP521 => 521,
            Self::EcdsaSecp256k1 => 256,
            Self::Aes128 => 128,
            Self::Aes192 => 192,
            Self::Aes256 => 256,
            Self::ChaCha20 => 256,
            Self::Ed25519 => 256,
            Self::X25519 => 256,
        }
    }

    /// Get the key size in bytes
    pub fn key_size_bytes(&self) -> usize {
        (self.key_size_bits() + 7) / 8
    }

    /// Check if this is an RSA algorithm
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::Rsa1024 | Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 | Self::Rsa8192
        )
    }

    /// Check if this is an ECDSA algorithm
    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            Self::EcdsaP224
                | Self::EcdsaP256
                | Self::EcdsaP384
                | Self::EcdsaP521
                | Self::EcdsaSecp256k1
        )
    }

    /// Check if this is a symmetric algorithm
    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            Self::Aes128 | Self::Aes192 | Self::Aes256 | Self::ChaCha20
        )
    }

    /// Check if this is an asymmetric algorithm
    pub fn is_asymmetric(&self) -> bool {
        !self.is_symmetric()
    }

    /// Check if this is an EdDSA algorithm
    pub fn is_eddsa(&self) -> bool {
        matches!(self, Self::Ed25519)
    }

    /// Check if this is a key agreement algorithm
    pub fn is_key_agreement(&self) -> bool {
        matches!(self, Self::X25519)
    }

    /// Get the curve name for ECDSA algorithms
    pub fn curve_name(&self) -> Option<&'static str> {
        match self {
            Self::EcdsaP224 => Some("secp224r1"),
            Self::EcdsaP256 => Some("secp256r1"),
            Self::EcdsaP384 => Some("secp384r1"),
            Self::EcdsaP521 => Some("secp521r1"),
            Self::EcdsaSecp256k1 => Some("secp256k1"),
            _ => None,
        }
    }

    /// Get the algorithm name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rsa1024 => "RSA-1024",
            Self::Rsa2048 => "RSA-2048",
            Self::Rsa3072 => "RSA-3072",
            Self::Rsa4096 => "RSA-4096",
            Self::Rsa8192 => "RSA-8192",
            Self::EcdsaP224 => "ECDSA-P224",
            Self::EcdsaP256 => "ECDSA-P256",
            Self::EcdsaP384 => "ECDSA-P384",
            Self::EcdsaP521 => "ECDSA-P521",
            Self::EcdsaSecp256k1 => "ECDSA-secp256k1",
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
            Self::ChaCha20 => "ChaCha20",
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
        }
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Type of cryptographic key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Public key (asymmetric cryptography)
    Public,
    /// Private key (asymmetric cryptography)
    Private,
    /// Secret/symmetric key
    Secret,
}

impl KeyType {
    /// Check if this is a public key
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Check if this is a private key
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }

    /// Check if this is a secret/symmetric key
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret)
    }

    /// Get the key type name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Private => "Private",
            Self::Secret => "Secret",
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Key usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyUsage {
    /// Key can be used for signing
    pub sign: bool,
    /// Key can be used for verification
    pub verify: bool,
    /// Key can be used for encryption
    pub encrypt: bool,
    /// Key can be used for decryption
    pub decrypt: bool,
    /// Key can be used for key derivation
    pub derive: bool,
    /// Key can be used for key wrapping
    pub wrap: bool,
    /// Key can be used for key unwrapping
    pub unwrap: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self {
            sign: false,
            verify: false,
            encrypt: false,
            decrypt: false,
            derive: false,
            wrap: false,
            unwrap: false,
        }
    }
}

impl KeyUsage {
    /// Create a new KeyUsage with all operations allowed
    pub fn all() -> Self {
        Self {
            sign: true,
            verify: true,
            encrypt: true,
            decrypt: true,
            derive: true,
            wrap: true,
            unwrap: true,
        }
    }

    /// Create a new KeyUsage for signing operations
    pub fn sign_verify() -> Self {
        Self {
            sign: true,
            verify: true,
            ..Default::default()
        }
    }

    /// Create a new KeyUsage for encryption operations
    pub fn encrypt_decrypt() -> Self {
        Self {
            encrypt: true,
            decrypt: true,
            ..Default::default()
        }
    }

    /// Create a new KeyUsage for key derivation
    pub fn derive_only() -> Self {
        Self {
            derive: true,
            ..Default::default()
        }
    }

    /// Check if any usage is allowed
    pub fn has_any_usage(&self) -> bool {
        self.sign || self.verify || self.encrypt || self.decrypt || self.derive || self.wrap || self.unwrap
    }
}