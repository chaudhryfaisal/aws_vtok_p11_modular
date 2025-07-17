//! Mechanism and algorithm type definitions.
//!
//! This module defines enums and types related to cryptographic mechanisms,
//! digest algorithms, and signature padding schemes.

use serde::{Deserialize, Serialize};
use crate::types::KeyAlgorithm;

/// Cryptographic mechanisms supported by backends
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mechanism {
    /// Pure digest mechanisms
    Digest(DigestAlgorithm),
    
    /// RSA PKCS#1 v1.5 signature/encryption
    RsaPkcs1 {
        /// Optional digest algorithm for signature mechanisms
        digest: Option<DigestAlgorithm>,
    },
    
    /// RSA PKCS#1 PSS signature
    RsaPkcs1Pss {
        /// Digest algorithm
        digest: DigestAlgorithm,
        /// MGF algorithm (typically same as digest)
        mgf: DigestAlgorithm,
        /// Salt length in bytes
        salt_len: usize,
    },
    
    /// RSA OAEP encryption
    RsaOaep {
        /// Hash algorithm
        hash: DigestAlgorithm,
        /// MGF algorithm
        mgf: DigestAlgorithm,
        /// Optional label
        label: Option<Vec<u8>>,
    },
    
    /// Raw RSA (no padding)
    RsaX509,
    
    /// ECDSA signature
    Ecdsa {
        /// Optional digest algorithm
        digest: Option<DigestAlgorithm>,
    },
    
    /// EdDSA signature (Ed25519)
    EdDsa,
    
    /// AES encryption modes
    Aes {
        /// AES mode
        mode: AesMode,
        /// Key size in bits
        key_size: usize,
    },
    
    /// ChaCha20 stream cipher
    ChaCha20,
    
    /// ChaCha20-Poly1305 AEAD
    ChaCha20Poly1305,
    
    /// HMAC with specified hash algorithm
    Hmac {
        /// Hash algorithm
        hash: DigestAlgorithm,
    },
    
    /// Key derivation function
    Kdf {
        /// KDF algorithm
        algorithm: KdfAlgorithm,
    },
    
    /// Elliptic Curve Diffie-Hellman
    Ecdh,
    
    /// X25519 key agreement
    X25519,
}

/// AES encryption modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AesMode {
    /// Electronic Codebook mode
    Ecb,
    /// Cipher Block Chaining mode
    Cbc,
    /// Counter mode
    Ctr,
    /// Galois/Counter Mode (AEAD)
    Gcm,
    /// Counter with CBC-MAC (AEAD)
    Ccm,
}

/// Key Derivation Function algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// PBKDF2 with HMAC
    Pbkdf2 {
        /// Hash algorithm for HMAC
        hash: DigestAlgorithm,
    },
    /// HKDF (HMAC-based Key Derivation Function)
    Hkdf {
        /// Hash algorithm
        hash: DigestAlgorithm,
    },
    /// Argon2 password hashing
    Argon2,
    /// scrypt password-based KDF
    Scrypt,
}

/// Digest (hash) algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    /// SHA-1 (deprecated, for compatibility only)
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// SHA-512/224
    Sha512_224,
    /// SHA-512/256
    Sha512_256,
    /// SHA3-224
    Sha3_224,
    /// SHA3-256
    Sha3_256,
    /// SHA3-384
    Sha3_384,
    /// SHA3-512
    Sha3_512,
    /// BLAKE2b with 256-bit output
    Blake2b256,
    /// BLAKE2b with 512-bit output
    Blake2b512,
    /// BLAKE2s with 256-bit output
    Blake2s256,
    /// MD5 (deprecated, for compatibility only)
    Md5,
}

/// RSA signature padding schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignaturePadding {
    /// PKCS#1 v1.5 padding
    Pkcs1v15,
    /// PKCS#1 PSS padding
    Pss {
        /// Salt length in bytes
        salt_len: usize,
    },
    /// No padding (raw)
    None,
}

impl Mechanism {
    /// Get the mechanism name as a string
    pub fn name(&self) -> String {
        match self {
            Self::Digest(alg) => format!("DIGEST-{}", alg.name()),
            Self::RsaPkcs1 { digest: Some(d) } => format!("RSA-PKCS1-{}", d.name()),
            Self::RsaPkcs1 { digest: None } => "RSA-PKCS1".to_string(),
            Self::RsaPkcs1Pss { digest, .. } => format!("RSA-PSS-{}", digest.name()),
            Self::RsaOaep { hash, .. } => format!("RSA-OAEP-{}", hash.name()),
            Self::RsaX509 => "RSA-X509".to_string(),
            Self::Ecdsa { digest: Some(d) } => format!("ECDSA-{}", d.name()),
            Self::Ecdsa { digest: None } => "ECDSA".to_string(),
            Self::EdDsa => "EdDSA".to_string(),
            Self::Aes { mode, key_size } => format!("AES{}-{:?}", key_size, mode),
            Self::ChaCha20 => "ChaCha20".to_string(),
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305".to_string(),
            Self::Hmac { hash } => format!("HMAC-{}", hash.name()),
            Self::Kdf { algorithm } => format!("KDF-{:?}", algorithm),
            Self::Ecdh => "ECDH".to_string(),
            Self::X25519 => "X25519".to_string(),
        }
    }

    /// Check if this mechanism is for signing
    pub fn is_sign_mechanism(&self) -> bool {
        matches!(
            self,
            Self::RsaPkcs1 { .. }
                | Self::RsaPkcs1Pss { .. }
                | Self::Ecdsa { .. }
                | Self::EdDsa
                | Self::Hmac { .. }
        )
    }

    /// Check if this mechanism is for encryption
    pub fn is_encrypt_mechanism(&self) -> bool {
        matches!(
            self,
            Self::RsaPkcs1 { digest: None }
                | Self::RsaOaep { .. }
                | Self::RsaX509
                | Self::Aes { .. }
                | Self::ChaCha20
                | Self::ChaCha20Poly1305
        )
    }

    /// Check if this mechanism is for digest
    pub fn is_digest_mechanism(&self) -> bool {
        matches!(self, Self::Digest(_))
    }

    /// Check if this mechanism is for key derivation
    pub fn is_kdf_mechanism(&self) -> bool {
        matches!(self, Self::Kdf { .. })
    }

    /// Check if this mechanism is for key agreement
    pub fn is_key_agreement_mechanism(&self) -> bool {
        matches!(self, Self::Ecdh | Self::X25519)
    }

    /// Check if this mechanism supports the given key algorithm
    pub fn supports_key_algorithm(&self, key_alg: KeyAlgorithm) -> bool {
        match (self, key_alg) {
            // RSA mechanisms
            (Self::RsaPkcs1 { .. } | Self::RsaPkcs1Pss { .. } | Self::RsaOaep { .. } | Self::RsaX509, alg) => {
                alg.is_rsa()
            }
            // ECDSA mechanisms
            (Self::Ecdsa { .. }, alg) => alg.is_ecdsa(),
            // EdDSA mechanisms
            (Self::EdDsa, KeyAlgorithm::Ed25519) => true,
            // AES mechanisms
            (Self::Aes { key_size, .. }, alg) => {
                matches!(
                    (key_size, alg),
                    (128, KeyAlgorithm::Aes128)
                        | (192, KeyAlgorithm::Aes192)
                        | (256, KeyAlgorithm::Aes256)
                )
            }
            // ChaCha20 mechanisms
            (Self::ChaCha20 | Self::ChaCha20Poly1305, KeyAlgorithm::ChaCha20) => true,
            // Key agreement
            (Self::Ecdh, alg) => alg.is_ecdsa(),
            (Self::X25519, KeyAlgorithm::X25519) => true,
            // HMAC can use any symmetric key
            (Self::Hmac { .. }, alg) => alg.is_symmetric(),
            // Digest doesn't use keys
            (Self::Digest(_), _) => false,
            // KDF can derive any type
            (Self::Kdf { .. }, _) => true,
            _ => false,
        }
    }

    /// Get the expected output size for this mechanism (if applicable)
    pub fn output_size(&self) -> Option<usize> {
        match self {
            Self::Digest(alg) => Some(alg.output_size()),
            Self::Hmac { hash } => Some(hash.output_size()),
            _ => None,
        }
    }
}

impl DigestAlgorithm {
    /// Get the output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Sha512_224 => 28,
            Self::Sha512_256 => 32,
            Self::Sha3_224 => 28,
            Self::Sha3_256 => 32,
            Self::Sha3_384 => 48,
            Self::Sha3_512 => 64,
            Self::Blake2b256 => 32,
            Self::Blake2b512 => 64,
            Self::Blake2s256 => 32,
            Self::Md5 => 16,
        }
    }

    /// Get the algorithm name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha224 => "SHA224",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
            Self::Sha512_224 => "SHA512-224",
            Self::Sha512_256 => "SHA512-256",
            Self::Sha3_224 => "SHA3-224",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b256 => "BLAKE2b-256",
            Self::Blake2b512 => "BLAKE2b-512",
            Self::Blake2s256 => "BLAKE2s-256",
            Self::Md5 => "MD5",
        }
    }

    /// Check if this algorithm is considered secure
    pub fn is_secure(&self) -> bool {
        !matches!(self, Self::Sha1 | Self::Md5)
    }
}

impl std::fmt::Display for Mechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for SignaturePadding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs1v15 => write!(f, "PKCS1v15"),
            Self::Pss { salt_len } => write!(f, "PSS(salt={})", salt_len),
            Self::None => write!(f, "None"),
        }
    }
}