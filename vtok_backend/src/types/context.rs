//! Context-related types and structures.
//!
//! This module defines types used by operation contexts for maintaining
//! state and configuration during cryptographic operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Operation context state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContextState {
    /// Context has been initialized but no operations performed
    Initialized,
    /// Single-part operation is active
    SinglePartActive,
    /// Multi-part operation is active (can accept more data)
    MultiPartActive,
    /// Multi-part operation is ready for finalization
    MultiPartReady,
    /// Context has been finalized and cannot be used further
    Finalized,
}

impl ContextState {
    /// Check if the context can accept new data
    pub fn can_update(&self) -> bool {
        matches!(self, Self::Initialized | Self::MultiPartActive)
    }

    /// Check if the context can be finalized
    pub fn can_finalize(&self) -> bool {
        matches!(
            self,
            Self::Initialized | Self::MultiPartActive | Self::MultiPartReady
        )
    }

    /// Check if the context is finalized
    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized)
    }

    /// Check if a single-part operation can be performed
    pub fn can_single_part(&self) -> bool {
        matches!(self, Self::Initialized)
    }
}

/// Parameters for RSA PKCS#1 PSS padding
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RsaPssParams {
    /// Hash algorithm for the signature
    pub hash_algorithm: crate::types::DigestAlgorithm,
    /// Mask generation function algorithm
    pub mgf_algorithm: crate::types::DigestAlgorithm,
    /// Salt length in bytes
    pub salt_length: usize,
}

/// Parameters for RSA OAEP padding
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RsaOaepParams {
    /// Hash algorithm
    pub hash_algorithm: crate::types::DigestAlgorithm,
    /// Mask generation function algorithm
    pub mgf_algorithm: crate::types::DigestAlgorithm,
    /// Optional label (source encoding parameter)
    pub label: Option<Vec<u8>>,
}

/// Parameters for AES GCM mode
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AesGcmParams {
    /// Initialization vector
    pub iv: Vec<u8>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
    /// Tag length in bytes (typically 16)
    pub tag_length: usize,
}

/// Parameters for AES CCM mode
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AesCcmParams {
    /// Nonce
    pub nonce: Vec<u8>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
    /// Tag length in bytes
    pub tag_length: usize,
}

/// Parameters for ChaCha20-Poly1305 AEAD
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChaCha20Poly1305Params {
    /// Nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
}

/// Parameters for PBKDF2 key derivation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pbkdf2Params {
    /// Salt value
    pub salt: Vec<u8>,
    /// Number of iterations
    pub iterations: u32,
    /// Derived key length in bytes
    pub key_length: usize,
}

/// Parameters for HKDF key derivation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HkdfParams {
    /// Salt value (optional)
    pub salt: Option<Vec<u8>>,
    /// Info parameter
    pub info: Vec<u8>,
    /// Output key length in bytes
    pub key_length: usize,
}

/// Parameters for Argon2 password hashing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Salt value
    pub salt: Vec<u8>,
    /// Memory cost in KB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism factor
    pub parallelism: u32,
    /// Output length in bytes
    pub output_length: usize,
    /// Argon2 variant
    pub variant: Argon2Variant,
}

/// Argon2 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Argon2Variant {
    /// Argon2d - data-dependent
    Argon2d,
    /// Argon2i - data-independent
    Argon2i,
    /// Argon2id - hybrid
    Argon2id,
}

/// Parameters for scrypt key derivation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScryptParams {
    /// Salt value
    pub salt: Vec<u8>,
    /// CPU/memory cost parameter (N)
    pub n: u32,
    /// Block size parameter (r)
    pub r: u32,
    /// Parallelization parameter (p)
    pub p: u32,
    /// Output length in bytes
    pub key_length: usize,
}

/// Generic mechanism parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MechanismParams {
    /// No parameters
    None,
    /// RSA PSS parameters
    RsaPss(RsaPssParams),
    /// RSA OAEP parameters
    RsaOaep(RsaOaepParams),
    /// AES GCM parameters
    AesGcm(AesGcmParams),
    /// AES CCM parameters
    AesCcm(AesCcmParams),
    /// ChaCha20-Poly1305 parameters
    ChaCha20Poly1305(ChaCha20Poly1305Params),
    /// PBKDF2 parameters
    Pbkdf2(Pbkdf2Params),
    /// HKDF parameters
    Hkdf(HkdfParams),
    /// Argon2 parameters
    Argon2(Argon2Params),
    /// scrypt parameters
    Scrypt(ScryptParams),
    /// Raw bytes for custom parameters
    Raw(Vec<u8>),
}

impl Default for MechanismParams {
    fn default() -> Self {
        Self::None
    }
}

/// Context configuration for cryptographic operations
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Mechanism parameters
    pub params: MechanismParams,
    /// Additional attributes
    pub attributes: HashMap<String, Vec<u8>>,
    /// Buffer size hint for operations
    pub buffer_size_hint: Option<usize>,
    /// Whether to use hardware acceleration if available
    pub use_hardware: bool,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            params: MechanismParams::None,
            attributes: HashMap::new(),
            buffer_size_hint: None,
            use_hardware: true,
        }
    }
}

impl ContextConfig {
    /// Create a new context configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set mechanism parameters
    pub fn with_params(mut self, params: MechanismParams) -> Self {
        self.params = params;
        self
    }

    /// Add an attribute
    pub fn with_attribute(mut self, name: impl Into<String>, value: Vec<u8>) -> Self {
        self.attributes.insert(name.into(), value);
        self
    }

    /// Set buffer size hint
    pub fn with_buffer_size_hint(mut self, size: usize) -> Self {
        self.buffer_size_hint = Some(size);
        self
    }

    /// Set hardware acceleration preference
    pub fn with_hardware(mut self, use_hardware: bool) -> Self {
        self.use_hardware = use_hardware;
        self
    }
}

/// Progress information for long-running operations
#[derive(Debug, Clone)]
pub struct OperationProgress {
    /// Bytes processed so far
    pub bytes_processed: u64,
    /// Total bytes to process (if known)
    pub total_bytes: Option<u64>,
    /// Estimated completion percentage (0-100)
    pub percentage: Option<f32>,
    /// Operation-specific status message
    pub status_message: Option<String>,
}

impl OperationProgress {
    /// Create new progress information
    pub fn new(bytes_processed: u64) -> Self {
        Self {
            bytes_processed,
            total_bytes: None,
            percentage: None,
            status_message: None,
        }
    }

    /// Set total bytes
    pub fn with_total_bytes(mut self, total: u64) -> Self {
        self.total_bytes = Some(total);
        if total > 0 {
            self.percentage = Some((self.bytes_processed as f32 / total as f32) * 100.0);
        }
        self
    }

    /// Set status message
    pub fn with_status(mut self, message: impl Into<String>) -> Self {
        self.status_message = Some(message.into());
        self
    }

    /// Check if operation is complete
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.total_bytes {
            self.bytes_processed >= total
        } else {
            false
        }
    }
}