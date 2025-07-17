//! Core trait definitions for the vtok_backend abstraction layer.
//!
//! This module contains all the traits that define the interface between
//! the PKCS#11 layer and crypto backends. The traits are designed to be
//! composable, thread-safe, and extensible.

pub mod crypto;
pub mod key;
pub mod digest;
pub mod sign;
pub mod verify;
pub mod encrypt;
pub mod decrypt;

// Re-export all public traits
pub use crypto::CryptoBackend;
pub use key::{Key, KeyPair, Certificate};
pub use digest::DigestContext;
pub use sign::SignContext;
pub use verify::VerifyContext;
pub use encrypt::EncryptContext;
pub use decrypt::DecryptContext;