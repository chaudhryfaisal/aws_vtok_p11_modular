//! Mock crypto backend implementation.
//!
//! This module provides a concrete implementation of the vtok_backend traits
//! using mock implementations for all cryptographic operations. The mock
//! backend is designed for testing and development environments.

pub mod backend;
pub mod key;
pub mod context;
pub mod digest;
pub mod sign;
pub mod verify;
pub mod encrypt;
pub mod decrypt;

// Re-export main types
pub use backend::MockBackend;
pub use key::{MockKey, MockKeyPair, MockCertificate};
pub use context::*;