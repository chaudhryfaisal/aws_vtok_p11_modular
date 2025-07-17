// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the `VtokBackend` trait, which abstracts all cryptographic operations
//! required by the vtok PKCS#11 provider. This allows the core logic to be
//! crypto-agnostic.

use std::any::Any;
use std::fmt::Debug;

/// A generic error type for backend operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    General,
    BadMechanism,
    KeyGen,
    KeyImport,
    CertImport,
    InvalidKey,
    InvalidCertificate,
    Digest,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Random,
    Unsupported,
    AttributeMissing,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Represents a cryptographic key handle.
/// The actual key data is managed by the backend.
pub trait Key: Send + Sync + RsaKey + EcKey {
    /// Returns self as `Any` to allow for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Returns the type of the key.
    fn key_type(&self) -> KeyType;
    /// Returns the public key.
    fn public_key(&self) -> Result<Box<dyn Key>>;
}

/// A trait for RSA keys.
pub trait RsaKey {
    /// Returns the modulus.
    fn modulus(&self) -> Vec<u8>;
    /// Returns the public exponent.
    fn public_exponent(&self) -> Vec<u8>;
    /// Returns the modulus size in bits.
    fn modulus_bits(&self) -> usize;
}

/// A trait for EC keys.
pub trait EcKey {
    /// Returns the parameters in X9.62 format.
    fn params_x962(&self) -> Vec<u8>;
    /// Returns the public point Q in X9.62 format.
    fn point_q_x962(&self) -> Vec<u8>;
}

/// Supported key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ec,
}

/// Attributes that can be retrieved from a key object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAttribute {
    RsaModulus,
    RsaPublicExponent,
    EcParams,
    EcPoint,
}

/// Represents an X.509 Certificate handle.
pub trait Certificate: Send + Sync {
    /// Returns the certificate category.
    fn category(&self) -> CertCategory;
    /// Returns the subject DN.
    fn subject(&self) -> Vec<u8>;
    /// Returns the issuer DN.
    fn issuer(&self) -> Vec<u8>;
    /// Returns the serial number.
    fn serial_number(&self) -> Vec<u8>;
    /// Returns the full certificate in DER format.
    fn to_der(&self) -> Vec<u8>;
}

/// Certificate categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertCategory {
    Unverified,
    Token,
    Authority,
    Other,
}

/// Attributes that can be retrieved from a certificate object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertAttribute {
    Subject,
    Issuer,
    SerialNumber,
    Value, // The full DER encoding
}

/// Context for multi-part digest operations.
pub trait DigestContext: Send + Sync {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>>;
}

/// Context for multi-part signing operations.
pub trait SignContext: Send + Sync {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>>;
}

/// Context for multi-part verification operations.
pub trait VerifyContext: Send + Sync {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(self: Box<Self>, signature: &[u8]) -> Result<()>;
}

/// The `VtokBackend` trait defines the interface for a crypto-agnostic backend
/// that provides all necessary cryptographic primitives for the PKCS#11 provider.
pub trait VtokBackend: Send + Sync + Any {
    // --- Key Management ---
    fn generate_rsa_key(&self, modulus_bits: usize, public_exponent: Option<&[u8]>) -> Result<Box<dyn Key>>;
    fn generate_ec_key(&self, curve_oid_der: &[u8]) -> Result<Box<dyn Key>>;
    fn load_private_key(&self, pem: &str) -> Result<Box<dyn Key>>;

    // --- Certificate Management ---
    fn load_certificates(&self, pem: &str) -> Result<Vec<Box<dyn Certificate>>>;

    // --- Single-Part (Stateless) Operations ---
    fn digest(&self, mechanism: &Mechanism, data: &[u8]) -> Result<Vec<u8>>;
    fn encrypt(&self, mechanism: &Mechanism, key: &dyn Key, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, mechanism: &Mechanism, key: &dyn Key, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn sign(&self, mechanism: &Mechanism, key: &dyn Key, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, mechanism: &Mechanism, key: &dyn Key, data: &[u8], signature: &[u8]) -> Result<()>;

    // --- Multi-Part (Stateful) Operations ---
    fn digest_init(&self, mechanism: &Mechanism) -> Result<Box<dyn DigestContext>>;
    fn sign_init(&self, mechanism: &Mechanism, key: &dyn Key) -> Result<Box<dyn SignContext>>;
    fn verify_init(&self, mechanism: &Mechanism, key: &dyn Key) -> Result<Box<dyn VerifyContext>>;

    // --- Random Number Generation ---
    fn generate_random(&self, len: usize) -> Result<Vec<u8>>;
}

/// A mechanism type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    RsaX509,
    RsaPkcs(Option<MechDigest>),
    RsaPkcsPss(Option<MechDigest>, Option<usize>),
    Ecdsa(Option<MechDigest>),
    Digest(MechDigest),
}

impl Mechanism {
    pub fn ck_type(&self) -> u64 {
        match self {
            Mechanism::RsaX509 => 3,
            Mechanism::RsaPkcs(_) => 1,
            Mechanism::RsaPkcsPss(_, _) => 0x47,
            Mechanism::Ecdsa(_) => 0x1041,
            Mechanism::Digest(d) => d.ck_type(),
        }
    }

    pub fn from_ckraw_mech(raw_mech: &u64) -> Option<Mechanism> {
        match *raw_mech {
            3 => Some(Mechanism::RsaX509),
            1 => Some(Mechanism::RsaPkcs(None)),
            0x47 => Some(Mechanism::RsaPkcsPss(None, None)),
            0x1041 => Some(Mechanism::Ecdsa(None)),
            _ => MechDigest::from_ckraw_mech(raw_mech).map(Mechanism::Digest),
        }
    }
}

/// Digest algorithm for a mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechDigest {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl MechDigest {
    pub fn ck_type(&self) -> u64 {
        match self {
            MechDigest::Sha1 => 0x220,
            MechDigest::Sha224 => 0x255,
            MechDigest::Sha256 => 0x250,
            MechDigest::Sha384 => 0x260,
            MechDigest::Sha512 => 0x270,
        }
    }

    pub fn from_ckraw_mech(raw_mech: &u64) -> Option<MechDigest> {
        match *raw_mech {
            0x220 => Some(MechDigest::Sha1),
            0x255 => Some(MechDigest::Sha224),
            0x250 => Some(MechDigest::Sha256),
            0x260 => Some(MechDigest::Sha384),
            0x270 => Some(MechDigest::Sha512),
            _ => None,
        }
    }
}
