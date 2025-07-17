//! Bridge module for connecting PKCS#11 operations to vtok_backend traits.
//!
//! This module provides the abstraction layer between the PKCS#11 protocol
//! implementation and the cryptographic backend. It translates PKCS#11
//! operations into vtok_backend trait calls and handles error conversion.

pub mod crypto;
pub mod key;
pub mod context;
pub mod sync_wrapper;

// Re-export key types for convenience
pub use crypto::*;
pub use key::*;
pub use context::*;
pub use sync_wrapper::*;

use vtok_backend::types::{BackendError, BackendResult};
use crate::pkcs11;
use crate::Error;

/// Convert a BackendError to a PKCS#11 Error
pub fn backend_error_to_p11_error(err: BackendError) -> Error {
    match err {
        BackendError::UnsupportedAlgorithm(_) => Error::MechanismInvalid,
        BackendError::UnsupportedMechanism(_) => Error::MechanismInvalid,
        BackendError::UnsupportedOperation(_) => Error::MechanismInvalid,
        BackendError::InvalidKey(_) => Error::KeyHandleInvalid,
        BackendError::InvalidKeyData(_) => Error::KeyTypeInconsistent,
        BackendError::KeyNotExtractable => Error::CkError(pkcs11::CKR_ATTRIBUTE_SENSITIVE),
        BackendError::KeySensitive => Error::CkError(pkcs11::CKR_ATTRIBUTE_SENSITIVE),
        BackendError::InvalidCertificate(_) => Error::CkError(pkcs11::CKR_DATA_INVALID),
        BackendError::DigestOperation(_) => Error::CkError(pkcs11::CKR_FUNCTION_FAILED),
        BackendError::DigestUpdate(_) => Error::CkError(pkcs11::CKR_FUNCTION_FAILED),
        BackendError::DigestFinalize(_) => Error::CkError(pkcs11::CKR_FUNCTION_FAILED),
        BackendError::SignOperation(_) => Error::CkError(pkcs11::CKR_FUNCTION_FAILED),
        BackendError::VerifyOperation(_) => Error::CkError(pkcs11::CKR_SIGNATURE_INVALID),
        BackendError::EncryptOperation(_) => Error::CkError(pkcs11::CKR_FUNCTION_FAILED),
        BackendError::DecryptOperation(_) => Error::CkError(pkcs11::CKR_FUNCTION_FAILED),
        BackendError::OperationActive => Error::CkError(pkcs11::CKR_OPERATION_ACTIVE),
        BackendError::ContextFinalized => Error::OperationNotInitialized,
        BackendError::InvalidState(_) => Error::CkError(pkcs11::CKR_OPERATION_NOT_INITIALIZED),
        BackendError::InvalidParameters(_) => Error::CkError(pkcs11::CKR_ARGUMENTS_BAD),
        BackendError::BufferTooSmall { .. } => Error::CkError(pkcs11::CKR_BUFFER_TOO_SMALL),
        BackendError::InvalidDataLength(_) => Error::CkError(pkcs11::CKR_DATA_LEN_RANGE),
        BackendError::NotInitialized => Error::CkError(pkcs11::CKR_CRYPTOKI_NOT_INITIALIZED),
        BackendError::OutOfMemory => Error::CkError(pkcs11::CKR_HOST_MEMORY),
        _ => Error::GeneralError,
    }
}

/// Convert a BackendResult to a PKCS#11 Result
pub fn backend_result_to_p11_result<T>(result: BackendResult<T>) -> crate::Result<T> {
    result.map_err(backend_error_to_p11_error)
}