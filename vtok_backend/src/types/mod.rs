//! Type definitions for the vtok_backend abstraction layer.
//!
//! This module contains all the types used by the backend traits,
//! including error types, enums for algorithms and mechanisms,
//! and other supporting types.

pub mod error;
pub mod key;
pub mod mechanism;
pub mod context;

// Re-export all public types
pub use error::{BackendError, BackendResult};
pub use key::{KeyAlgorithm, KeyType};
pub use mechanism::{Mechanism, DigestAlgorithm, SignaturePadding};
pub use context::*;