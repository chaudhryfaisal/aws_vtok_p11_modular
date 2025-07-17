//! Verify context trait for signature verification operations.
//!
//! This module defines the trait for digital signature verification operations.
//! Verify contexts maintain state for incremental verification operations.

use crate::types::{BackendError, BackendResult, Mechanism, ContextState, OperationProgress};
use crate::traits::Key;

/// Trait for signature verification operation contexts.
///
/// This trait provides an interface for digital signature verification operations,
/// supporting both single-part and multi-part verification.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access, though individual verify contexts are typically used by a single
/// thread for the duration of an operation.
///
/// # Example
///
/// ```rust
/// use vtok_backend::traits::VerifyContext;
///
/// async fn verify_signature<V: VerifyContext>(
///     mut verify_ctx: V,
///     data: &[u8],
///     signature: &[u8]
/// ) -> Result<bool, Box<dyn std::error::Error>> {
///     verify_ctx.update(data).await?;
///     let is_valid = verify_ctx.finalize(signature).await?;
///     Ok(is_valid)
/// }
/// ```
pub trait VerifyContext: Send + Sync + std::fmt::Debug {
    /// Get the verification mechanism used by this context
    fn mechanism(&self) -> &Mechanism;

    /// Get the expected signature size in bytes
    fn signature_size(&self) -> usize;

    /// Get the current context state
    fn state(&self) -> ContextState;

    /// Update the verification context with additional data
    ///
    /// This method can be called multiple times to process data incrementally
    /// for multi-part verification operations.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to add to the verification computation
    ///
    /// # Errors
    ///
    /// Returns `BackendError::VerifyOperation` if the update operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    /// Returns `BackendError::InvalidState` if the context is in an invalid state.
    async fn update(&mut self, data: &[u8]) -> BackendResult<()>;

    /// Finalize the verification operation and check the signature
    ///
    /// After calling this method, the context cannot be used for further operations.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Errors
    ///
    /// Returns `BackendError::VerifyOperation` if the verification operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    async fn finalize(self, signature: &[u8]) -> BackendResult<bool>;

    /// Verify a signature in a single operation
    ///
    /// This is a convenience method that combines update and finalize for single-part operations.
    ///
    /// # Arguments
    ///
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Errors
    ///
    /// Returns `BackendError::VerifyOperation` if the verification operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been used.
    async fn verify(mut self, data: &[u8], signature: &[u8]) -> BackendResult<bool>
    where
        Self: Sized,
    {
        self.update(data).await?;
        self.finalize(signature).await
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
        match self.mechanism() {
            Mechanism::RsaPkcs1 { digest: Some(_) } => true,
            Mechanism::RsaPkcs1Pss { .. } => true,
            Mechanism::Ecdsa { digest: Some(_) } => true,
            Mechanism::Hmac { .. } => true,
            _ => false,
        }
    }

    /// Check if the context supports single-part operations
    fn supports_single_part(&self) -> bool {
        true
    }

    /// Get the key algorithm used for verification
    fn key_algorithm(&self) -> crate::types::KeyAlgorithm;

    /// Get the key size in bits
    fn key_size(&self) -> usize;

    /// Reset the verification context to its initial state
    ///
    /// This allows reusing the context for a new verification operation.
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if reset is not supported.
    async fn reset(&mut self) -> BackendResult<()> {
        Err(BackendError::UnsupportedOperation(
            "context reset not supported".to_string()
        ))
    }

    /// Check if the context supports reset
    fn supports_reset(&self) -> bool {
        false
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
    /// Returns `BackendError::VerifyOperation` if any update operation fails.
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

    /// Get mechanism-specific parameters
    fn mechanism_params(&self) -> std::collections::HashMap<String, Vec<u8>> {
        std::collections::HashMap::new()
    }

    /// Set mechanism-specific parameters
    ///
    /// # Arguments
    ///
    /// * `params` - Mechanism-specific parameters
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if parameter setting is not supported.
    /// Returns `BackendError::InvalidParameters` if the parameters are invalid.
    fn set_mechanism_params(&mut self, _params: std::collections::HashMap<String, Vec<u8>>) -> BackendResult<()> {
        Err(BackendError::UnsupportedOperation(
            "parameter setting not supported".to_string()
        ))
    }

    /// Get the maximum data size that can be verified in a single operation
    fn max_data_size(&self) -> Option<usize> {
        match self.mechanism() {
            Mechanism::RsaPkcs1 { digest: None } => {
                // For raw RSA, max data size is key_size - 11 bytes (PKCS#1 v1.5 padding)
                Some((self.key_size() / 8).saturating_sub(11))
            }
            Mechanism::RsaX509 => {
                // For raw RSA without padding, max data size is key size
                Some(self.key_size() / 8)
            }
            _ => None, // No limit for hash-based signatures
        }
    }

    /// Check if the given data size is valid for this verification context
    fn is_valid_data_size(&self, data_size: usize) -> bool {
        if let Some(max_size) = self.max_data_size() {
            data_size <= max_size
        } else {
            true
        }
    }

    /// Get the digest algorithm used (if any)
    fn digest_algorithm(&self) -> Option<crate::types::DigestAlgorithm> {
        match self.mechanism() {
            Mechanism::RsaPkcs1 { digest } => *digest,
            Mechanism::RsaPkcs1Pss { digest, .. } => Some(*digest),
            Mechanism::Ecdsa { digest } => *digest,
            Mechanism::Hmac { hash } => Some(*hash),
            _ => None,
        }
    }

    /// Check if this is a recoverable signature scheme
    fn is_recoverable(&self) -> bool {
        // Most signature schemes are not recoverable
        false
    }

    /// Get signature format information
    fn signature_format(&self) -> crate::traits::sign::SignatureFormat {
        match self.mechanism() {
            Mechanism::RsaPkcs1 { .. } | Mechanism::RsaPkcs1Pss { .. } | Mechanism::RsaX509 => {
                crate::traits::sign::SignatureFormat::Raw
            }
            Mechanism::Ecdsa { .. } => crate::traits::sign::SignatureFormat::EcdsaRaw,
            Mechanism::EdDsa => crate::traits::sign::SignatureFormat::Raw,
            Mechanism::Hmac { .. } => crate::traits::sign::SignatureFormat::Raw,
            _ => crate::traits::sign::SignatureFormat::Unknown,
        }
    }

    /// Verify signature with message recovery (if supported)
    ///
    /// # Arguments
    ///
    /// * `signature` - The recoverable signature
    ///
    /// # Returns
    ///
    /// The recovered message if verification succeeds
    ///
    /// # Errors
    ///
    /// Returns `BackendError::VerifyOperation` if verification fails.
    /// Returns `BackendError::UnsupportedOperation` if recovery is not supported.
    async fn verify_recover(self, signature: &[u8]) -> BackendResult<Vec<u8>>
    where
        Self: Sized,
    {
        Err(BackendError::UnsupportedOperation(
            "message recovery not supported".to_string()
        ))
    }
}

/// Convenience trait for verify contexts that support streaming
#[cfg(feature = "async-io")]
pub trait StreamingVerifyContext: VerifyContext {
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
    /// Returns `BackendError::VerifyOperation` if verification update fails.
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

    /// Verify signature for data from a reader
    ///
    /// # Arguments
    ///
    /// * `reader` - The data source
    /// * `signature` - The signature to verify
    /// * `buffer_size` - Buffer size for reading (optional)
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Errors
    ///
    /// Returns `BackendError::IoError` if reading fails.
    /// Returns `BackendError::VerifyOperation` if verification fails.
    async fn verify_from_reader<R>(
        mut self,
        reader: &mut R,
        signature: &[u8],
        buffer_size: Option<usize>
    ) -> BackendResult<bool>
    where
        R: tokio::io::AsyncRead + Unpin,
        Self: Sized,
    {
        self.update_from_reader(reader, buffer_size).await?;
        self.finalize(signature).await
    }
}

// Blanket implementation for all VerifyContext implementations
#[cfg(feature = "async-io")]
impl<T: VerifyContext> StreamingVerifyContext for T {}