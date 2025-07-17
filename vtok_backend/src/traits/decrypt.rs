//! Decrypt context trait for decryption operations.
//!
//! This module defines the trait for decryption operations.
//! Decrypt contexts maintain state for incremental decryption operations.

use crate::types::{BackendError, BackendResult, Mechanism, ContextState, OperationProgress};
use crate::traits::Key;

/// Trait for decryption operation contexts.
///
/// This trait provides an interface for decryption operations,
/// supporting both single-part and multi-part decryption.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access, though individual decrypt contexts are typically used by a single
/// thread for the duration of an operation.
///
/// # Example
///
/// ```rust
/// use vtok_backend::traits::DecryptContext;
///
/// async fn decrypt_data<D: DecryptContext>(
///     mut decrypt_ctx: D,
///     ciphertext: &[u8]
/// ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
///     decrypt_ctx.update(ciphertext).await?;
///     let plaintext = decrypt_ctx.finalize().await?;
///     Ok(plaintext)
/// }
/// ```
pub trait DecryptContext: Send + Sync + std::fmt::Debug {
    /// Get the decryption mechanism used by this context
    fn mechanism(&self) -> &Mechanism;

    /// Get the current context state
    fn state(&self) -> ContextState;

    /// Update the decryption context with additional ciphertext
    ///
    /// This method can be called multiple times to process data incrementally
    /// for multi-part decryption operations.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// Decrypted data chunk (for streaming ciphers) or empty vector (for block ciphers)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DecryptOperation` if the update operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    /// Returns `BackendError::InvalidState` if the context is in an invalid state.
    async fn update(&mut self, ciphertext: &[u8]) -> BackendResult<Vec<u8>>;

    /// Finalize the decryption operation and return any remaining plaintext
    ///
    /// After calling this method, the context cannot be used for further operations.
    ///
    /// # Returns
    ///
    /// Final decrypted data (with padding removed if applicable)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DecryptOperation` if the finalization fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    async fn finalize(self) -> BackendResult<Vec<u8>>;

    /// Decrypt data in a single operation
    ///
    /// This is a convenience method that combines update and finalize for single-part operations.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// The decrypted data
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DecryptOperation` if the decryption operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been used.
    async fn decrypt(mut self, ciphertext: &[u8]) -> BackendResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut result = self.update(ciphertext).await?;
        let final_data = self.finalize().await?;
        result.extend_from_slice(&final_data);
        Ok(result)
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
            Mechanism::Aes { .. } => true,
            Mechanism::ChaCha20 => true,
            Mechanism::ChaCha20Poly1305 => true,
            _ => false,
        }
    }

    /// Check if the context supports single-part operations
    fn supports_single_part(&self) -> bool {
        true
    }

    /// Get the key algorithm used for decryption
    fn key_algorithm(&self) -> crate::types::KeyAlgorithm;

    /// Get the key size in bits
    fn key_size(&self) -> usize;

    /// Reset the decryption context to its initial state
    ///
    /// This allows reusing the context for a new decryption operation.
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

    /// Update with multiple ciphertext chunks
    ///
    /// This is a convenience method for processing multiple chunks of ciphertext.
    ///
    /// # Arguments
    ///
    /// * `chunks` - Iterator over ciphertext chunks
    ///
    /// # Returns
    ///
    /// All decrypted data chunks concatenated
    ///
    /// # Errors
    ///
    /// Returns `BackendError::DecryptOperation` if any update operation fails.
    async fn update_chunks<'a, I>(&mut self, chunks: I) -> BackendResult<Vec<u8>>
    where
        I: IntoIterator<Item = &'a [u8]>,
        Self: Sized,
    {
        let mut result = Vec::new();
        for chunk in chunks {
            let decrypted_chunk = self.update(chunk).await?;
            result.extend_from_slice(&decrypted_chunk);
        }
        Ok(result)
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

    /// Get the maximum ciphertext size that can be decrypted in a single operation
    fn max_ciphertext_size(&self) -> Option<usize> {
        match self.mechanism() {
            Mechanism::RsaPkcs1 { .. } | Mechanism::RsaOaep { .. } | Mechanism::RsaX509 => {
                // For RSA, max ciphertext size is key size
                Some(self.key_size() / 8)
            }
            _ => None, // No limit for symmetric ciphers
        }
    }

    /// Check if the given ciphertext size is valid for this decryption context
    fn is_valid_ciphertext_size(&self, ciphertext_size: usize) -> bool {
        if let Some(max_size) = self.max_ciphertext_size() {
            ciphertext_size <= max_size
        } else {
            true
        }
    }

    /// Get the block size for block ciphers (if applicable)
    fn block_size(&self) -> Option<usize> {
        match self.mechanism() {
            Mechanism::Aes { .. } => Some(16), // AES block size is always 16 bytes
            _ => None,
        }
    }

    /// Check if this is an AEAD (Authenticated Encryption with Associated Data) cipher
    fn is_aead(&self) -> bool {
        matches!(
            self.mechanism(),
            Mechanism::Aes { mode: crate::types::mechanism::AesMode::Gcm, .. } |
            Mechanism::Aes { mode: crate::types::mechanism::AesMode::Ccm, .. } |
            Mechanism::ChaCha20Poly1305
        )
    }

    /// Set additional authenticated data (for AEAD ciphers)
    ///
    /// # Arguments
    ///
    /// * `aad` - Additional authenticated data
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if not an AEAD cipher.
    /// Returns `BackendError::InvalidState` if called at the wrong time.
    async fn set_aad(&mut self, _aad: &[u8]) -> BackendResult<()> {
        if self.is_aead() {
            Err(BackendError::UnsupportedOperation(
                "AAD setting not implemented".to_string()
            ))
        } else {
            Err(BackendError::UnsupportedOperation(
                "not an AEAD cipher".to_string()
            ))
        }
    }

    /// Set the authentication tag (for AEAD ciphers)
    ///
    /// This should be called before finalization for AEAD ciphers.
    ///
    /// # Arguments
    ///
    /// * `tag` - The authentication tag
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if not an AEAD cipher.
    /// Returns `BackendError::InvalidState` if called at the wrong time.
    async fn set_tag(&mut self, _tag: &[u8]) -> BackendResult<()> {
        if self.is_aead() {
            Err(BackendError::UnsupportedOperation(
                "tag setting not implemented".to_string()
            ))
        } else {
            Err(BackendError::UnsupportedOperation(
                "not an AEAD cipher".to_string()
            ))
        }
    }

    /// Get the expected output size for the given ciphertext size
    ///
    /// # Arguments
    ///
    /// * `ciphertext_size` - Size of ciphertext data
    ///
    /// # Returns
    ///
    /// Expected output size (may be smaller due to padding removal)
    fn output_size(&self, ciphertext_size: usize) -> usize {
        match self.mechanism() {
            Mechanism::RsaPkcs1 { .. } => {
                // RSA PKCS#1 v1.5: output is at most key_size - 11
                (self.key_size() / 8).saturating_sub(11)
            }
            Mechanism::RsaOaep { .. } => {
                // RSA OAEP: output depends on hash function
                // Simplified calculation: key_size - 2*hash_size - 2
                (self.key_size() / 8).saturating_sub(66) // Assuming SHA-256 (32 bytes)
            }
            Mechanism::RsaX509 => {
                // Raw RSA: output is key size
                self.key_size() / 8
            }
            Mechanism::Aes { mode: crate::types::mechanism::AesMode::Gcm, .. } => {
                // GCM: ciphertext size - 16 byte tag
                ciphertext_size.saturating_sub(16)
            }
            Mechanism::ChaCha20Poly1305 => {
                // ChaCha20-Poly1305: ciphertext size - 16 byte tag
                ciphertext_size.saturating_sub(16)
            }
            _ => {
                // For other ciphers, output size is at most input size
                ciphertext_size
            }
        }
    }

    /// Verify authentication tag (for AEAD ciphers)
    ///
    /// This is typically called automatically during finalization for AEAD ciphers.
    ///
    /// # Arguments
    ///
    /// * `tag` - The authentication tag to verify
    ///
    /// # Returns
    ///
    /// `true` if the tag is valid, `false` otherwise
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if not an AEAD cipher.
    async fn verify_tag(&self, _tag: &[u8]) -> BackendResult<bool> {
        Err(BackendError::UnsupportedOperation(
            "tag verification not supported".to_string()
        ))
    }
}

/// Convenience trait for decrypt contexts that support streaming
#[cfg(feature = "async-io")]
pub trait StreamingDecryptContext: DecryptContext {
    /// Process ciphertext from a reader and write plaintext to a writer
    ///
    /// # Arguments
    ///
    /// * `reader` - The ciphertext source
    /// * `writer` - The plaintext destination
    /// * `buffer_size` - Buffer size for reading (optional)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::IoError` if reading or writing fails.
    /// Returns `BackendError::DecryptOperation` if decryption fails.
    async fn decrypt_stream<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        buffer_size: Option<usize>
    ) -> BackendResult<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let buf_size = buffer_size.unwrap_or(8192);
        let mut buffer = vec![0u8; buf_size];
        
        loop {
            let bytes_read = reader.read(&mut buffer).await
                .map_err(|e| BackendError::IoError(e.to_string()))?;
            
            if bytes_read == 0 {
                break;
            }
            
            let decrypted_data = self.update(&buffer[..bytes_read]).await?;
            if !decrypted_data.is_empty() {
                writer.write_all(&decrypted_data).await
                    .map_err(|e| BackendError::IoError(e.to_string()))?;
            }
        }
        
        Ok(())
    }
}

// Blanket implementation for all DecryptContext implementations
#[cfg(feature = "async-io")]
impl<T: DecryptContext> StreamingDecryptContext for T {}