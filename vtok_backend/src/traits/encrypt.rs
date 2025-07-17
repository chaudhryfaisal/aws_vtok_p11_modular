//! Encrypt context trait for encryption operations.
//!
//! This module defines the trait for encryption operations.
//! Encrypt contexts maintain state for incremental encryption operations.

use crate::types::{BackendError, BackendResult, Mechanism, ContextState, OperationProgress};
use crate::traits::Key;

/// Trait for encryption operation contexts.
///
/// This trait provides an interface for encryption operations,
/// supporting both single-part and multi-part encryption.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access, though individual encrypt contexts are typically used by a single
/// thread for the duration of an operation.
///
/// # Example
///
/// ```rust
/// use vtok_backend::traits::EncryptContext;
///
/// async fn encrypt_data<E: EncryptContext>(
///     mut encrypt_ctx: E,
///     data: &[u8]
/// ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
///     encrypt_ctx.update(data).await?;
///     let ciphertext = encrypt_ctx.finalize().await?;
///     Ok(ciphertext)
/// }
/// ```
pub trait EncryptContext: Send + Sync + std::fmt::Debug {
    /// Get the encryption mechanism used by this context
    fn mechanism(&self) -> &Mechanism;

    /// Get the current context state
    fn state(&self) -> ContextState;

    /// Update the encryption context with additional data
    ///
    /// This method can be called multiple times to process data incrementally
    /// for multi-part encryption operations.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    ///
    /// # Returns
    ///
    /// Encrypted data chunk (for streaming ciphers) or empty vector (for block ciphers)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::EncryptOperation` if the update operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    /// Returns `BackendError::InvalidState` if the context is in an invalid state.
    async fn update(&mut self, data: &[u8]) -> BackendResult<Vec<u8>>;

    /// Finalize the encryption operation and return any remaining ciphertext
    ///
    /// After calling this method, the context cannot be used for further operations.
    ///
    /// # Returns
    ///
    /// Final encrypted data (including padding and authentication tags if applicable)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::EncryptOperation` if the finalization fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been finalized.
    async fn finalize(self) -> BackendResult<Vec<u8>>;

    /// Encrypt data in a single operation
    ///
    /// This is a convenience method that combines update and finalize for single-part operations.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted data
    ///
    /// # Errors
    ///
    /// Returns `BackendError::EncryptOperation` if the encryption operation fails.
    /// Returns `BackendError::ContextFinalized` if the context has already been used.
    async fn encrypt(mut self, data: &[u8]) -> BackendResult<Vec<u8>>
    where
        Self: Sized,
    {
        let mut result = self.update(data).await?;
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

    /// Get the key algorithm used for encryption
    fn key_algorithm(&self) -> crate::types::KeyAlgorithm;

    /// Get the key size in bits
    fn key_size(&self) -> usize;

    /// Reset the encryption context to its initial state
    ///
    /// This allows reusing the context for a new encryption operation.
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
    /// # Returns
    ///
    /// All encrypted data chunks concatenated
    ///
    /// # Errors
    ///
    /// Returns `BackendError::EncryptOperation` if any update operation fails.
    async fn update_chunks<'a, I>(&mut self, chunks: I) -> BackendResult<Vec<u8>>
    where
        I: IntoIterator<Item = &'a [u8]>,
        Self: Sized,
    {
        let mut result = Vec::new();
        for chunk in chunks {
            let encrypted_chunk = self.update(chunk).await?;
            result.extend_from_slice(&encrypted_chunk);
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

    /// Get the maximum data size that can be encrypted in a single operation
    fn max_data_size(&self) -> Option<usize> {
        match self.mechanism() {
            Mechanism::RsaPkcs1 { digest: None } => {
                // For RSA PKCS#1 v1.5, max data size is key_size - 11 bytes
                Some((self.key_size() / 8).saturating_sub(11))
            }
            Mechanism::RsaOaep { .. } => {
                // For RSA OAEP, max data size depends on hash function
                // Simplified calculation: key_size - 2*hash_size - 2
                Some((self.key_size() / 8).saturating_sub(66)) // Assuming SHA-256 (32 bytes)
            }
            Mechanism::RsaX509 => {
                // For raw RSA without padding, max data size is key size
                Some(self.key_size() / 8)
            }
            _ => None, // No limit for symmetric ciphers
        }
    }

    /// Check if the given data size is valid for this encryption context
    fn is_valid_data_size(&self, data_size: usize) -> bool {
        if let Some(max_size) = self.max_data_size() {
            data_size <= max_size
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

    /// Get the authentication tag (for AEAD ciphers)
    ///
    /// This should be called after finalization for AEAD ciphers.
    ///
    /// # Returns
    ///
    /// The authentication tag
    ///
    /// # Errors
    ///
    /// Returns `BackendError::UnsupportedOperation` if not an AEAD cipher.
    /// Returns `BackendError::InvalidState` if called before finalization.
    fn get_tag(&self) -> BackendResult<Vec<u8>> {
        Err(BackendError::UnsupportedOperation(
            "tag retrieval not supported".to_string()
        ))
    }

    /// Get the expected output size for the given input size
    ///
    /// # Arguments
    ///
    /// * `input_size` - Size of input data
    ///
    /// # Returns
    ///
    /// Expected output size (may be larger due to padding)
    fn output_size(&self, input_size: usize) -> usize {
        match self.mechanism() {
            Mechanism::RsaPkcs1 { .. } | Mechanism::RsaOaep { .. } | Mechanism::RsaX509 => {
                // RSA output is always key size
                self.key_size() / 8
            }
            Mechanism::Aes { mode: crate::types::mechanism::AesMode::Ecb, .. } |
            Mechanism::Aes { mode: crate::types::mechanism::AesMode::Cbc, .. } => {
                // Block ciphers with padding
                let block_size = self.block_size().unwrap_or(16);
                ((input_size + block_size) / block_size) * block_size
            }
            Mechanism::Aes { mode: crate::types::mechanism::AesMode::Gcm, .. } => {
                // GCM: same size + 16 byte tag
                input_size + 16
            }
            Mechanism::ChaCha20Poly1305 => {
                // ChaCha20-Poly1305: same size + 16 byte tag
                input_size + 16
            }
            _ => {
                // Stream ciphers: same size
                input_size
            }
        }
    }
}

/// Convenience trait for encrypt contexts that support streaming
#[cfg(feature = "async-io")]
pub trait StreamingEncryptContext: EncryptContext {
    /// Process data from a reader and write to a writer
    ///
    /// # Arguments
    ///
    /// * `reader` - The data source
    /// * `writer` - The encrypted data destination
    /// * `buffer_size` - Buffer size for reading (optional)
    ///
    /// # Errors
    ///
    /// Returns `BackendError::IoError` if reading or writing fails.
    /// Returns `BackendError::EncryptOperation` if encryption fails.
    async fn encrypt_stream<R, W>(
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
            
            let encrypted_data = self.update(&buffer[..bytes_read]).await?;
            if !encrypted_data.is_empty() {
                writer.write_all(&encrypted_data).await
                    .map_err(|e| BackendError::IoError(e.to_string()))?;
            }
        }
        
        Ok(())
    }
}

// Blanket implementation for all EncryptContext implementations
#[cfg(feature = "async-io")]
impl<T: EncryptContext> StreamingEncryptContext for T {}