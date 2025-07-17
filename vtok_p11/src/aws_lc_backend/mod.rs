//! AWS-LC crypto backend implementation.
//!
//! This module provides a concrete implementation of the vtok_backend traits
//! using AWS-LC (aws-lc-rs) as the underlying cryptographic library.

pub mod backend;
pub mod key;
pub mod context;
pub mod digest;
pub mod sign;
pub mod verify;
pub mod encrypt;
pub mod decrypt;

// Re-export main types
pub use backend::AwsLcBackend;
pub use key::{AwsLcKey, AwsLcKeyPair, AwsLcCertificate};
pub use context::*;