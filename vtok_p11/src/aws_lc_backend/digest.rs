//! AWS-LC digest context implementation.

use aws_lc_rs::digest;
use vtok_backend::traits::DigestContext;
use vtok_backend::types::{
    BackendResult, BackendError, DigestAlgorithm, ContextState, OperationProgress,
};

/// AWS-LC digest context
pub struct AwsLcDigestContext {
    algorithm: DigestAlgorithm,
    context: Option<digest::Context>,
    state: ContextState,
    bytes_processed: u64,
}

impl AwsLcDigestContext {
    /// Create a new digest context
    pub fn new(algorithm: DigestAlgorithm) -> BackendResult<Self> {
        let digest_alg = match algorithm {
            DigestAlgorithm::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            DigestAlgorithm::Sha224 => &digest::SHA224,
            DigestAlgorithm::Sha256 => &digest::SHA256,
            DigestAlgorithm::Sha384 => &digest::SHA384,
            DigestAlgorithm::Sha512 => &digest::SHA512,
            DigestAlgorithm::Sha512_224 => &digest::SHA512_256, // Use SHA512_256 as fallback
            DigestAlgorithm::Sha512_256 => &digest::SHA512_256,
            _ => {
                return Err(BackendError::UnsupportedAlgorithm(format!(
                    "Digest algorithm {:?} not supported",
                    algorithm
                )));
            }
        };

        let context = digest::Context::new(digest_alg);
        Ok(Self {
            algorithm,
            context: Some(context),
            state: ContextState::Initialized,
            bytes_processed: 0,
        })
    }
}

impl std::fmt::Debug for AwsLcDigestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsLcDigestContext")
            .field("algorithm", &self.algorithm)
            .field("state", &self.state)
            .field("bytes_processed", &self.bytes_processed)
            .finish()
    }
}

impl DigestContext for AwsLcDigestContext {
    fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    fn state(&self) -> ContextState {
        self.state
    }

    async fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        if !self.state.can_update() {
            return Err(BackendError::InvalidState(format!(
                "Cannot update digest in state {:?}",
                self.state
            )));
        }

        if let Some(ref mut context) = self.context {
            context.update(data);
            self.bytes_processed += data.len() as u64;
            self.state = ContextState::MultiPartActive;
            Ok(())
        } else {
            Err(BackendError::InvalidState("Digest context not available".to_string()))
        }
    }

    async fn finalize(mut self) -> BackendResult<Vec<u8>> {
        if !self.state.can_finalize() {
            return Err(BackendError::InvalidState(format!(
                "Cannot finalize digest in state {:?}",
                self.state
            )));
        }

        if let Some(context) = self.context.take() {
            let digest_result = context.finish();
            self.state = ContextState::Finalized;
            Ok(digest_result.as_ref().to_vec())
        } else {
            Err(BackendError::InvalidState("Digest context not available".to_string()))
        }
    }

    fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    fn progress(&self) -> OperationProgress {
        OperationProgress::new(self.bytes_processed)
    }

    fn supports_incremental(&self) -> bool {
        true
    }

    fn supports_reset(&self) -> bool {
        false
    }
}