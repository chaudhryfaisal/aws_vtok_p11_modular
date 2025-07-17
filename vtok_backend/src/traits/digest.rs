//! Digest context trait for hash operations.
//!
//! This module defines the trait for digest (hash) operations.
//! Digest contexts maintain state for incremental hashing operations.

use crate::types::{BackendError, BackendResult, DigestAlgorithm, ContextState, OperationProgress};

/// Trait for digest (hash) operation contexts.
///
/// This trait provides an interface for incremental hash operations,
/// allowing data to be processed in chunks and producing a final digest.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access, though individual digest contexts are typically used by a single
/// thread for the duration of an operation.
///
/// # Example
///
/// ```rust
/// use vtok_backend::traits::DigestContext;
/// use vtok_backend::types::DigestAlgorithm;
///
/// async fn hash_data<D: DigestContext>(
///     mut digest_ctx: D,
///     data: &[u8]
/// ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
///     digest_ctx.update(data).await?;
///     let hash = digest_ctx.finalize().await?;
///     Ok(hash)
/// }
/// ```
pub trait DigestContext: Send + Sync + std::fmt::Debug {
    /// Get the digest algorithm used by this context
    fn algorithm(&self) -> DigestAlgorithm;

    /// Get the expected output size in bytes
    fn output_size(&self) -> usize {
        self.algorithm().output_size()
    }

    /// Get the current context state
    fn state(&self) -> ContextState;

    /// Update the digest with additional data
    ///
    /// This method can be called multiple times to process data incrementally.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to add to the digest
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DigestUpdate` if the update operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    /// Returns `BackendError::InvalidState` if the context is in an invalid state.
    async fn update(&mut self, data: &[u8]) -> BackendResult<()>;

    /// Finalize the digest and return the hash value
    ///
    /// After calling this method, the context cannot be used for further operations.
    ///
    /// # Returns
    ///
    /// The final hash value
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DigestFinalize` if the finalization fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    async fn finalize(self) -> BackendResult<Vec<u8>>;

    /// Compute the digest of data in a single operation
    ///
    /// This is a convenience method that combines update and finalize.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    ///
    /// # Returns
    ///
    /// The hash value
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DigestOperation` if the operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been used.
    async fn digest(mut self, data: &[u8]) -> BackendResult<Vec<u8>>
    where
        Self: Sized,
    {
        self.update(data).await?;
        self.finalize().await
    }

    /// Get the current digest state (if supported)
    ///
    /// This method allows getting an intermediate hash value without
    /// finalizing the context. Not all implementations may support this.
    ///
    /// # Returns
    ///
    /// The current hash value
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if not supported.
    async fn digest_state(&self) -> BackendResult<Vec<u8>> {
        Err(BackendError::UnsupportedOperation(
            "digest_state not supported".to_string()
        ))
    }

    /// Check if the context supports cloning
    fn supports_cloning(&self) -> bool {
        false
    }

    /// Reset the digest context to its initial state
    ///
    /// This allows reusing the context for a new digest operation.
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if reset is not supported.
    async fn reset(&mut self) -> BackendResult<()> {
        Err(BackendError::UnsupportedOperation(
            "context reset not supported".to_string()
        ))
    }

    /// Get the number of bytes processed so far
    fn bytes_processed(&self) -> u64 {
        0
    }

    /// Get operation progress information
    fn progress(&self) -> OperationProgress {
        OperationProgress::new(self.bytes_processed())
    }

    /// Check if the context supports incremental operations
    fn supports_incremental(&self) -> bool {
        true
    }

    /// Check if the context supports state extraction
    fn supports_state_extraction(&self) -> bool {
        false
    }

    /// Check if the context supports reset
    fn supports_reset(&self) -> bool {
        false
    }

    /// Get the block size for this digest algorithm (if applicable)
    fn block_size(&self) -> Option<usize> {
        match self.algorithm() {
            DigestAlgorithm::Sha1 => Some(64),
            DigestAlgorithm::Sha224 => Some(64),
            DigestAlgorithm::Sha256 => Some(64),
            DigestAlgorithm::Sha384 => Some(128),
            DigestAlgorithm::Sha512 => Some(128),
            DigestAlgorithm::Sha512_224 => Some(128),
            DigestAlgorithm::Sha512_256 => Some(128),
            DigestAlgorithm::Sha3_224 => Some(144),
            DigestAlgorithm::Sha3_256 => Some(136),
            DigestAlgorithm::Sha3_384 => Some(104),
            DigestAlgorithm::Sha3_512 => Some(72),
            DigestAlgorithm::Blake2b256 => Some(128),
            DigestAlgorithm::Blake2b512 => Some(128),
            DigestAlgorithm::Blake2s256 => Some(64),
            DigestAlgorithm::Md5 => Some(64),
        }
    }

    /// Update with multiple data chunks
    ///
    /// This is a convenience method for processing multiple chunks of data.
    ///
    /// # Arguments
    ///
    /// * `chunks` - Iterator over data chunks
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DigestUpdate` if any update operation fails.
    async fn update_chunks<'a, I>(&mut self, chunks: I) -> BackendResult<()>
    where
        I: IntoIterator<Item = &'a [u8]>,
        Self: Sized,
    {
        for chunk in chunks {
            self.update(chunk).await?;
        }
        Ok(())
    }

    /// Verify a digest against expected value
    ///
    /// This method finalizes the digest and compares it with the expected value.
    ///
    /// # Arguments
    ///
    /// * `expected` - The expected digest value
    ///
    /// # Returns
    ///
    /// `true` if the digest matches the expected value
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DigestFinalize` if finalization fails.
    async fn verify(self, expected: &[u8]) -> BackendResult<bool>
    where
        Self: Sized,
    {
        let actual = self.finalize().await?;
        Ok(actual.as_slice() == expected)
    }

    /// Get algorithm-specific parameters
    fn algorithm_params(&self) -> std::collections::HashMap<String, Vec<u8>> {
        std::collections::HashMap::new()
    }

    /// Set algorithm-specific parameters
    ///
    /// # Arguments
    ///
    /// * `params` - Algorithm-specific parameters
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if parameter setting is not supported.
    /// Returns `BackendError::InvalidParameters` if the parameters are invalid.
    fn set_algorithm_params(&mut self, _params: std::collections::HashMap<String, Vec<u8>>) -> BackendResult<()> {
        Err(BackendError::UnsupportedOperation(
            "parameter setting not supported".to_string()
        ))
    }
}

/// Convenience trait for digest contexts that support streaming
#[cfg(feature = "async-io")]
pub trait StreamingDigestContext: DigestContext {
    /// Process data from a reader
    ///
    /// # Arguments
    ///
    /// * `reader` - The data source
    /// * `buffer_size` - Buffer size for reading (optional)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::IoError` if reading fails.
    /// Returns `BackendError::DigestUpdate` if digest update fails.
    async fn update_from_reader<R>(&mut self, reader: &mut R, buffer_size: Option<usize>) -> BackendResult<()>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        
        let buf_size = buffer_size.unwrap_or(8192);
        let mut buffer = vec![0u8; buf_size];
        
        loop {
            let bytes_read = reader.read(&mut buffer).await
                .map_err(|e| BackendError::IoError(e.to_string()))?;
            
            if bytes_read == 0 {
                break;
            }
            
            self.update(&buffer[..bytes_read]).await?;
        }
        
        Ok(())
    }
}

// Blanket implementation for all DigestContext implementations
#[cfg(feature = "async-io")]
impl<T: DigestContext> StreamingDigestContext for T {}