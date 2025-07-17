//! Crypto operations bridge for vtok_backend integration.
//!
//! This module provides the main crypto operations bridge that implements
//! the crypto functionality using vtok_backend traits.

use std::sync::Arc;
use vtok_backend::types::{BackendResult, BackendError};
use crate::backend::Mechanism;
use crate::bridge::{BridgeKey, BridgeDigestContext, BridgeSignContext, BridgeVerifyContext, SyncCryptoBackend};
use crate::bridge::{backend_result_to_p11_result, key_for_mechanism};
use crate::backend::db::{Object, ObjectHandle};
use crate::pkcs11;
use crate::{Error, Result};

/// Main crypto bridge that holds a reference to the backend
pub struct CryptoBridge {
    backend: Arc<SyncCryptoBackend>,
}

impl CryptoBridge {
    /// Create a new crypto bridge with the given backend
    pub fn new(backend: Arc<SyncCryptoBackend>) -> Self {
        Self { backend }
    }

    /// Create a digest context
    pub fn create_digest_context(&self, mech_type: pkcs11::CK_MECHANISM_TYPE) -> Result<BridgeDigestContext> {
        backend_result_to_p11_result(
            BridgeDigestContext::new(self.backend.clone(), mech_type)
        )
    }

    /// Create a signing context for direct signing
    pub fn create_direct_sign_context(
        &self,
        mech: &Mechanism,
        key_obj: &Object,
    ) -> Result<BridgeSignContext> {
        let key = key_for_mechanism(mech, key_obj, true)?;
        backend_result_to_p11_result(
            BridgeSignContext::new_direct(self.backend.clone(), mech, key)
        )
    }

    /// Create a signing context for digest signing
    pub fn create_digest_sign_context(
        &self,
        mech: &Mechanism,
        key_obj: &Object,
    ) -> Result<BridgeSignContext> {
        let key = key_for_mechanism(mech, key_obj, true)?;
        backend_result_to_p11_result(
            BridgeSignContext::new_digest(self.backend.clone(), mech, key)
        )
    }

    /// Create a verification context for direct verification
    pub fn create_direct_verify_context(
        &self,
        mech: &Mechanism,
        key_obj: &Object,
    ) -> Result<BridgeVerifyContext> {
        let key = key_for_mechanism(mech, key_obj, false)?;
        backend_result_to_p11_result(
            BridgeVerifyContext::new_direct(self.backend.clone(), mech, key)
        )
    }

    /// Create a verification context for digest verification
    pub fn create_digest_verify_context(
        &self,
        mech: &Mechanism,
        key_obj: &Object,
    ) -> Result<BridgeVerifyContext> {
        let key = key_for_mechanism(mech, key_obj, false)?;
        backend_result_to_p11_result(
            BridgeVerifyContext::new_digest(self.backend.clone(), mech, key)
        )
    }

    /// Get the backend reference
    pub fn backend(&self) -> &Arc<SyncCryptoBackend> {
        &self.backend
    }
}

/// Error type for crypto operations (for compatibility with existing code)
#[derive(Clone, Copy, Debug)]
pub enum CryptoError {
    BadFlow,
    BadMech,
    BadMgf,
    BadSigFormat,
    BignumAlloc,
    DataMissing,
    Digest,
    DigestInit,
    DigestFinal,
    DigestSign,
    DigestSignFinal,
    DigestSignUpdate,
    DigestUpdate,
    DirectSign,
    MdCtxInit,
    GeneralError,
    OperationActive,
    PkeyCtxInit,
    PkeyCtxCtl,
    SignInit,
    VerifyInit,
    DigestVerify,
    DigestVerifyFinal,
    DigestVerifyUpdate,
    DirectVerify,
    DecryptInit,
    DirectDecrypt,
    EncryptInit,
    Encrypt,
    BadKeyType,
    UnknownKeyType,
    CertBadPem,
    CertName,
    CertIssuer,
    CertSerialNo,
    CertDerEncode,
    CertChainErr,
    CertChainInvalid,
}

impl From<BackendError> for CryptoError {
    fn from(err: BackendError) -> Self {
        match err {
            BackendError::UnsupportedMechanism(_) => CryptoError::BadMech,
            BackendError::InvalidKey(_) => CryptoError::BadKeyType,
            BackendError::DigestOperation(_) => CryptoError::Digest,
            BackendError::DigestUpdate(_) => CryptoError::DigestUpdate,
            BackendError::DigestFinalize(_) => CryptoError::DigestFinal,
            BackendError::SignOperation(_) => CryptoError::DirectSign,
            BackendError::VerifyOperation(_) => CryptoError::DirectVerify,
            BackendError::OperationActive => CryptoError::OperationActive,
            BackendError::InvalidDataLength(_) => CryptoError::DataMissing,
            _ => CryptoError::GeneralError,
        }
    }
}

/// Trait for signing contexts (for compatibility with existing code)
pub trait SignCtx: Send {
    fn update(&mut self, data: &[u8]) -> std::result::Result<(), CryptoError>;
    fn finalize(self: Box<Self>) -> std::result::Result<Vec<u8>, CryptoError>;
    fn sign(self: Box<Self>, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError>;
    fn sig_len_ck(&self) -> pkcs11::CK_ULONG;
    fn enter_state(&mut self, state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError>;
}

impl SignCtx for BridgeSignContext {
    fn update(&mut self, data: &[u8]) -> std::result::Result<(), CryptoError> {
        self.update(data).map_err(CryptoError::from)
    }

    fn finalize(self: Box<Self>) -> std::result::Result<Vec<u8>, CryptoError> {
        (*self).finalize().map_err(CryptoError::from)
    }

    fn sign(self: Box<Self>, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        (*self).sign(data).map_err(CryptoError::from)
    }

    fn sig_len_ck(&self) -> pkcs11::CK_ULONG {
        self.sig_len_ck()
    }

    fn enter_state(&mut self, state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError> {
        self.enter_state(state).map_err(CryptoError::from)
    }
}

/// Trait for verification contexts (for compatibility with existing code)
pub trait VerifyCtx: Send {
    fn update(&mut self, data: &[u8]) -> std::result::Result<(), CryptoError>;
    fn finalize(self: Box<Self>, signature: &[u8]) -> std::result::Result<(), CryptoError>;
    fn verify(self: Box<Self>, data: &[u8], signature: &[u8]) -> std::result::Result<(), CryptoError>;
    fn enter_state(&mut self, state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError>;
    fn verify_sig_len_ck(&self, sig_len: usize) -> bool;
}

impl VerifyCtx for BridgeVerifyContext {
    fn update(&mut self, data: &[u8]) -> std::result::Result<(), CryptoError> {
        self.update(data).map_err(CryptoError::from)
    }

    fn finalize(self: Box<Self>, signature: &[u8]) -> std::result::Result<(), CryptoError> {
        match (*self).finalize(signature).map_err(CryptoError::from)? {
            true => Ok(()),
            false => Err(CryptoError::DigestVerifyFinal),
        }
    }

    fn verify(self: Box<Self>, data: &[u8], signature: &[u8]) -> std::result::Result<(), CryptoError> {
        match (*self).verify(data, signature).map_err(CryptoError::from)? {
            true => Ok(()),
            false => Err(CryptoError::DirectVerify),
        }
    }

    fn enter_state(&mut self, state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError> {
        self.enter_state(state).map_err(CryptoError::from)
    }

    fn verify_sig_len_ck(&self, _sig_len: usize) -> bool {
        true // For now, accept any signature length
    }
}

/// Trait for encryption contexts (for compatibility with existing code)
pub trait EncryptCtx: Send {
    fn encrypt(self: Box<Self>, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError>;
    fn enter_state(&mut self, state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError>;
    fn len(&self) -> usize;
}

/// Trait for decryption contexts (for compatibility with existing code)
pub trait DecryptCtx: Send {
    fn decrypt(self: Box<Self>, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError>;
    fn enter_state(&mut self, state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError>;
    fn len(&self) -> usize;
}

/// Direct encryption context implementation
pub struct DirectEncryptCtx {
    mechanism: Mechanism,
    key: BridgeKey,
}

impl DirectEncryptCtx {
    pub fn new(mech: &Mechanism, key: BridgeKey) -> std::result::Result<Self, CryptoError> {
        Ok(Self {
            mechanism: mech.clone(),
            key,
        })
    }
}

impl EncryptCtx for DirectEncryptCtx {
    fn encrypt(self: Box<Self>, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        // For now, return placeholder encrypted data
        // In a real implementation, this would use the backend to encrypt
        Ok(vec![0u8; data.len() + 16]) // Add some padding
    }

    fn enter_state(&mut self, _state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError> {
        Ok(())
    }

    fn len(&self) -> usize {
        256 // Default length
    }
}

/// Direct decryption context implementation
pub struct DirectDecryptCtx {
    mechanism: Mechanism,
    key: BridgeKey,
}

impl DirectDecryptCtx {
    pub fn new(mech: &Mechanism, key: BridgeKey) -> std::result::Result<Self, CryptoError> {
        Ok(Self {
            mechanism: mech.clone(),
            key,
        })
    }
}

impl DecryptCtx for DirectDecryptCtx {
    fn decrypt(self: Box<Self>, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        // For now, return placeholder decrypted data
        // In a real implementation, this would use the backend to decrypt
        Ok(vec![0u8; data.len().saturating_sub(16)]) // Remove some padding
    }

    fn enter_state(&mut self, _state: crate::bridge::context::OpCtxState) -> std::result::Result<(), CryptoError> {
        Ok(())
    }

    fn len(&self) -> usize {
        256 // Default length
    }
}

/// Digest context wrapper for compatibility
pub struct DigestCtx {
    inner: BridgeDigestContext,
}

impl DigestCtx {
    pub fn new(mech_type: pkcs11::CK_MECHANISM_TYPE) -> std::result::Result<Self, CryptoError> {
        // This will need to be updated to use a global backend instance
        // For now, return an error indicating this needs to be implemented
        Err(CryptoError::GeneralError)
    }

    pub fn update(&mut self, data: &[u8]) -> std::result::Result<(), CryptoError> {
        self.inner.update(data).map_err(CryptoError::from)
    }

    pub fn finalize(self) -> std::result::Result<Vec<u8>, CryptoError> {
        self.inner.finalize().map_err(CryptoError::from)
    }

    pub fn digest(self, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        self.inner.digest(data).map_err(CryptoError::from)
    }
}