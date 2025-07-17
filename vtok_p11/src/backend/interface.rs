// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the `VtokBackend` trait, which abstracts all cryptographic operations
//! required by the vtok PKCS#11 provider. This allows the core logic to be
//! crypto-agnostic.

use crate::backend::Mechanism;

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
pub trait Key: Send + Sync {
    /// Returns the type of the key.
    fn key_type(&self) -> Result<KeyType>;
    /// Returns the size of the key in bits.
    fn size_bits(&self) -> Result<usize>;
    /// Returns the size of a signature in bytes for this key, in the PKCS#11 format.
    fn signature_size(&self) -> Result<usize>;
    /// Retrieves a specific attribute of the key.
    fn get_attribute(&self, attribute: KeyAttribute) -> Result<Vec<u8>>;
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
    /// Retrieves a specific attribute of the certificate.
    fn get_attribute(&self, attribute: CertAttribute) -> Result<Vec<u8>>;
    /// Verifies the certificate against a public key.
    fn verify(&self, key: &dyn Key) -> Result<()>;
    /// Returns the certificate's public key.
    fn public_key(&self) -> Result<Box<dyn Key>>;
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
pub trait DigestContext: Send {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>>;
}

/// Context for multi-part signing operations.
pub trait SignContext: Send {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>>;
}

/// Context for multi-part verification operations.
pub trait VerifyContext: Send {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(self: Box<Self>, signature: &[u8]) -> Result<()>;
}

/// The `VtokBackend` trait defines the interface for a crypto-agnostic backend
/// that provides all necessary cryptographic primitives for the PKCS#11 provider.
pub trait VtokBackend: Send + Sync {
    // --- Key Management ---
    fn generate_rsa_key(&self, modulus_bits: usize, public_exponent: Option<&[u8]>) -> Result<Box<dyn Key>>;
    fn generate_ec_key(&self, curve_oid_der: &[u8]) -> Result<Box<dyn Key>>;
    fn import_key(&self, pem: &str) -> Result<Box<dyn Key>>;

    // --- Certificate Management ---
    fn import_cert(&self, pem: &str) -> Result<Vec<Box<dyn Certificate>>>;
    fn verify_cert_chain(&self, chain: &[&dyn Certificate]) -> Result<()>;

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