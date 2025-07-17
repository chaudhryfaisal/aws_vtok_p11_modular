//! Mock digest context implementation.

use vtok_backend::traits::DigestContext;
use vtok_backend::types::{BackendResult, BackendError, DigestAlgorithm, ContextState};
use sha2::{Sha256, Sha384, Sha512, Digest};

use crate::data::MockConfig;
use super::context::MockContext;

/// Mock digest context
#[derive(Debug)]
pub struct MockDigestContext {
    algorithm: DigestAlgorithm,
    context: MockContext,
    hasher: Box<dyn MockHasher>,
}

/// Trait for mock hashers to enable dynamic dispatch
trait MockHasher: Send + Sync + std::fmt::Debug {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
    fn output_size(&self) -> usize;
    fn clone_hasher(&self) -> Box<dyn MockHasher>;
}

/// SHA-256 mock hasher
#[derive(Debug, Clone)]
struct MockSha256Hasher {
    hasher: Sha256,
    deterministic: bool,
}

impl MockHasher for MockSha256Hasher {
    fn update(&mut self, data: &[u8]) {
        if self.deterministic {
            // For deterministic mode, use a simple XOR-based "hash"
            // This is not cryptographically secure but provides consistent results
            self.hasher.update(data);
        } else {
            self.hasher.update(data);
        }
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        if self.deterministic {
            // Return deterministic hash for testing
            vec![0x42; 32] // Fixed 32-byte output for SHA-256
        } else {
            self.hasher.finalize().to_vec()
        }
    }

    fn output_size(&self) -> usize {
        32
    }

    fn clone_hasher(&self) -> Box<dyn MockHasher> {
        Box::new(self.clone())
    }
}

/// SHA-384 mock hasher
#[derive(Debug, Clone)]
struct MockSha384Hasher {
    hasher: Sha384,
    deterministic: bool,
}

impl MockHasher for MockSha384Hasher {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        if self.deterministic {
            vec![0x43; 48] // Fixed 48-byte output for SHA-384
        } else {
            self.hasher.finalize().to_vec()
        }
    }

    fn output_size(&self) -> usize {
        48
    }

    fn clone_hasher(&self) -> Box<dyn MockHasher> {
        Box::new(self.clone())
    }
}

/// SHA-512 mock hasher
#[derive(Debug, Clone)]
struct MockSha512Hasher {
    hasher: Sha512,
    deterministic: bool,
}

impl MockHasher for MockSha512Hasher {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        if self.deterministic {
            vec![0x44; 64] // Fixed 64-byte output for SHA-512
        } else {
            self.hasher.finalize().to_vec()
        }
    }

    fn output_size(&self) -> usize {
        64
    }

    fn clone_hasher(&self) -> Box<dyn MockHasher> {
        Box::new(self.clone())
    }
}

impl MockDigestContext {
    /// Create a new mock digest context
    pub fn new(algorithm: DigestAlgorithm, config: &MockConfig) -> BackendResult<Self> {
        let context = MockContext::new(config);
        
        let hasher: Box<dyn MockHasher> = match algorithm {
            DigestAlgorithm::Sha256 => Box::new(MockSha256Hasher {
                hasher: Sha256::new(),
                deterministic: config.deterministic,
            }),
            DigestAlgorithm::Sha384 => Box::new(MockSha384Hasher {
                hasher: Sha384::new(),
                deterministic: config.deterministic,
            }),
            DigestAlgorithm::Sha512 => Box::new(MockSha512Hasher {
                hasher: Sha512::new(),
                deterministic: config.deterministic,
            }),
            _ => return Err(BackendError::UnsupportedAlgorithm(format!(
                "Digest algorithm {:?} not supported in mock",
                algorithm
            ))),
        };

        Ok(Self {
            algorithm,
            context,
            hasher,
        })
    }
}

impl DigestContext for MockDigestContext {
    fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    fn state(&self) -> ContextState {
        ContextState::MultiPartActive
    }

    async fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("digest_update") {
            return Err(error);
        }

        self.hasher.update(data);
        Ok(())
    }

    async fn finalize(mut self) -> BackendResult<Vec<u8>> {
        if let Some(error) = self.context.should_inject_error("digest_finalize") {
            return Err(error);
        }

        Ok(self.hasher.finalize())
    }

    fn output_size(&self) -> usize {
        self.hasher.output_size()
    }

    async fn reset(&mut self) -> BackendResult<()> {
        if let Some(error) = self.context.should_inject_error("digest_reset") {
            return Err(error);
        }

        // Create a new hasher of the same type
        self.hasher = match self.algorithm {
            DigestAlgorithm::Sha256 => Box::new(MockSha256Hasher {
                hasher: Sha256::new(),
                deterministic: self.context.is_deterministic(),
            }),
            DigestAlgorithm::Sha384 => Box::new(MockSha384Hasher {
                hasher: Sha384::new(),
                deterministic: self.context.is_deterministic(),
            }),
            DigestAlgorithm::Sha512 => Box::new(MockSha512Hasher {
                hasher: Sha512::new(),
                deterministic: self.context.is_deterministic(),
            }),
            _ => return Err(BackendError::UnsupportedAlgorithm(format!(
                "Digest algorithm {:?} not supported in mock",
                self.algorithm
            ))),
        };

        Ok(())
    }

    fn supports_reset(&self) -> bool {
        true
    }
}

impl Clone for MockDigestContext {
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            context: self.context.clone(),
            hasher: self.hasher.clone_hasher(),
        }
    }
}