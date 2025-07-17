//! Context management bridge for vtok_backend integration.
//!
//! This module provides context wrappers that manage the state of cryptographic operations
//! using the synchronous wrapper around vtok_backend traits.

use std::sync::Arc;
use vtok_backend::types::{BackendResult, DigestAlgorithm};
use crate::backend::Mechanism;
use crate::bridge::{BridgeKey, SyncCryptoBackend};
use crate::pkcs11;

/// Operation Context state. An operation context state is stored
/// in order to avoid misbehaving applications calling the incorrect
/// cryptographic interfaces (i.e. C_SignInit() -> C_Sign() -> C_SignUpdate())
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCtxState {
    Initialized,
    SinglepartActive,
    MultipartActive,
    MultipartReady,
}

/// Bridge digest context that manages digest operations
pub struct BridgeDigestContext {
    backend: Arc<SyncCryptoBackend>,
    algorithm: DigestAlgorithm,
    state: OpCtxState,
    data: Vec<u8>,
}

impl BridgeDigestContext {
    pub fn new(backend: Arc<SyncCryptoBackend>, mech_type: pkcs11::CK_MECHANISM_TYPE) -> BackendResult<Self> {
        let algorithm = match mech_type {
            pkcs11::CKM_SHA_1 => DigestAlgorithm::Sha1,
            pkcs11::CKM_SHA224 => DigestAlgorithm::Sha224,
            pkcs11::CKM_SHA256 => DigestAlgorithm::Sha256,
            pkcs11::CKM_SHA384 => DigestAlgorithm::Sha384,
            pkcs11::CKM_SHA512 => DigestAlgorithm::Sha512,
            _ => return Err(vtok_backend::types::BackendError::unsupported_mechanism(format!("Digest mechanism: {}", mech_type))),
        };

        Ok(Self {
            backend,
            algorithm,
            state: OpCtxState::Initialized,
            data: Vec::new(),
        })
    }

    pub fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        self.state = OpCtxState::MultipartActive;
        self.data.extend_from_slice(data);
        Ok(())
    }

    pub fn finalize(self) -> BackendResult<Vec<u8>> {
        // For now, return a placeholder hash
        // In a real implementation, this would use the backend to compute the hash
        match self.algorithm {
            DigestAlgorithm::Sha256 => Ok(vec![0u8; 32]), // SHA-256 produces 32 bytes
            DigestAlgorithm::Sha1 => Ok(vec![0u8; 20]),   // SHA-1 produces 20 bytes
            DigestAlgorithm::Sha224 => Ok(vec![0u8; 28]), // SHA-224 produces 28 bytes
            DigestAlgorithm::Sha384 => Ok(vec![0u8; 48]), // SHA-384 produces 48 bytes
            DigestAlgorithm::Sha512 => Ok(vec![0u8; 64]), // SHA-512 produces 64 bytes
            DigestAlgorithm::Sha512_224 => Ok(vec![0u8; 28]), // SHA-512/224 produces 28 bytes
            DigestAlgorithm::Sha512_256 => Ok(vec![0u8; 32]), // SHA-512/256 produces 32 bytes
            DigestAlgorithm::Sha3_224 => Ok(vec![0u8; 28]), // SHA3-224 produces 28 bytes
            DigestAlgorithm::Sha3_256 => Ok(vec![0u8; 32]), // SHA3-256 produces 32 bytes
            DigestAlgorithm::Sha3_384 => Ok(vec![0u8; 48]), // SHA3-384 produces 48 bytes
            DigestAlgorithm::Sha3_512 => Ok(vec![0u8; 64]), // SHA3-512 produces 64 bytes
            DigestAlgorithm::Blake2b512 => Ok(vec![0u8; 64]), // BLAKE2b-512 produces 64 bytes
            DigestAlgorithm::Blake2b256 => Ok(vec![0u8; 32]), // BLAKE2b-256 produces 32 bytes
            DigestAlgorithm::Blake2s256 => Ok(vec![0u8; 32]), // BLAKE2s-256 produces 32 bytes
            DigestAlgorithm::Md5 => Ok(vec![0u8; 16]), // MD5 produces 16 bytes
        }
    }

    pub fn digest(mut self, data: &[u8]) -> BackendResult<Vec<u8>> {
        self.state = OpCtxState::SinglepartActive;
        self.data.extend_from_slice(data);
        self.finalize()
    }

    pub fn enter_state(&mut self, new_state: OpCtxState) -> BackendResult<()> {
        match (self.state, new_state) {
            (OpCtxState::Initialized, OpCtxState::SinglepartActive) => {
                self.state = new_state;
                Ok(())
            }
            (OpCtxState::Initialized, OpCtxState::MultipartActive) => {
                self.state = new_state;
                Ok(())
            }
            (OpCtxState::MultipartActive, OpCtxState::MultipartReady) => {
                self.state = new_state;
                Ok(())
            }
            _ => Err(vtok_backend::types::BackendError::InvalidState(
                format!("Cannot transition from {:?} to {:?}", self.state, new_state)
            )),
        }
    }

    pub fn len(&self) -> usize {
        // Return the digest length based on the algorithm
        match self.algorithm {
            DigestAlgorithm::Sha256 => 32,
            DigestAlgorithm::Sha1 => 20,
            DigestAlgorithm::Sha224 => 28,
            DigestAlgorithm::Sha384 => 48,
            DigestAlgorithm::Sha512 => 64,
            DigestAlgorithm::Sha512_224 => 28,
            DigestAlgorithm::Sha512_256 => 32,
            DigestAlgorithm::Sha3_224 => 28,
            DigestAlgorithm::Sha3_256 => 32,
            DigestAlgorithm::Sha3_384 => 48,
            DigestAlgorithm::Sha3_512 => 64,
            DigestAlgorithm::Blake2b512 => 64,
            DigestAlgorithm::Blake2b256 => 32,
            DigestAlgorithm::Blake2s256 => 32,
            DigestAlgorithm::Md5 => 16,
        }
    }
}

/// Bridge sign context that manages signing operations
pub struct BridgeSignContext {
    backend: Arc<SyncCryptoBackend>,
    mechanism: Mechanism,
    key: BridgeKey,
    state: OpCtxState,
    sig_len: usize,
    data: Vec<u8>,
}

impl BridgeSignContext {
    pub fn new_direct(
        backend: Arc<SyncCryptoBackend>,
        mech: &Mechanism,
        key: BridgeKey,
    ) -> BackendResult<Self> {
        let sig_len = estimate_signature_length(mech);
        
        Ok(Self {
            backend,
            mechanism: mech.clone(),
            key,
            state: OpCtxState::Initialized,
            sig_len,
            data: Vec::new(),
        })
    }

    pub fn new_digest(
        backend: Arc<SyncCryptoBackend>,
        mech: &Mechanism,
        key: BridgeKey,
    ) -> BackendResult<Self> {
        let sig_len = estimate_signature_length(mech);
        
        Ok(Self {
            backend,
            mechanism: mech.clone(),
            key,
            state: OpCtxState::Initialized,
            sig_len,
            data: Vec::new(),
        })
    }

    pub fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        self.state = OpCtxState::MultipartActive;
        self.data.extend_from_slice(data);
        Ok(())
    }

    pub fn finalize(mut self) -> BackendResult<Vec<u8>> {
        self.state = OpCtxState::MultipartReady;
        // For now, return a placeholder signature
        // In a real implementation, this would use the backend to sign the data
        Ok(vec![0u8; self.sig_len])
    }

    pub fn sign(mut self, data: &[u8]) -> BackendResult<Vec<u8>> {
        self.state = OpCtxState::SinglepartActive;
        self.data.extend_from_slice(data);
        // For now, return a placeholder signature
        // In a real implementation, this would use the backend to sign the data
        Ok(vec![0u8; self.sig_len])
    }

    pub fn sig_len_ck(&self) -> pkcs11::CK_ULONG {
        self.sig_len as pkcs11::CK_ULONG
    }

    pub fn enter_state(&mut self, new_state: OpCtxState) -> BackendResult<()> {
        match (self.state, new_state) {
            (OpCtxState::Initialized, OpCtxState::SinglepartActive) => {
                self.state = new_state;
                Ok(())
            }
            (OpCtxState::Initialized, OpCtxState::MultipartActive) => {
                self.state = new_state;
                Ok(())
            }
            (OpCtxState::MultipartActive, OpCtxState::MultipartReady) => {
                self.state = new_state;
                Ok(())
            }
            _ => Err(vtok_backend::types::BackendError::InvalidState(
                format!("Cannot transition from {:?} to {:?}", self.state, new_state)
            )),
        }
    }

}

/// Bridge verify context that manages verification operations
pub struct BridgeVerifyContext {
    backend: Arc<SyncCryptoBackend>,
    mechanism: Mechanism,
    key: BridgeKey,
    state: OpCtxState,
    data: Vec<u8>,
}

impl BridgeVerifyContext {
    pub fn new_direct(
        backend: Arc<SyncCryptoBackend>,
        mech: &Mechanism,
        key: BridgeKey,
    ) -> BackendResult<Self> {
        Ok(Self {
            backend,
            mechanism: mech.clone(),
            key,
            state: OpCtxState::Initialized,
            data: Vec::new(),
        })
    }

    pub fn new_digest(
        backend: Arc<SyncCryptoBackend>,
        mech: &Mechanism,
        key: BridgeKey,
    ) -> BackendResult<Self> {
        Ok(Self {
            backend,
            mechanism: mech.clone(),
            key,
            state: OpCtxState::Initialized,
            data: Vec::new(),
        })
    }

    pub fn update(&mut self, data: &[u8]) -> BackendResult<()> {
        self.state = OpCtxState::MultipartActive;
        self.data.extend_from_slice(data);
        Ok(())
    }

    pub fn finalize(mut self, _signature: &[u8]) -> BackendResult<bool> {
        self.state = OpCtxState::MultipartReady;
        // For now, return true (verification successful)
        // In a real implementation, this would use the backend to verify the signature
        Ok(true)
    }

    pub fn verify(mut self, data: &[u8], _signature: &[u8]) -> BackendResult<bool> {
        self.state = OpCtxState::SinglepartActive;
        self.data.extend_from_slice(data);
        // For now, return true (verification successful)
        // In a real implementation, this would use the backend to verify the signature
        Ok(true)
    }

    pub fn enter_state(&mut self, new_state: OpCtxState) -> BackendResult<()> {
        match (self.state, new_state) {
            (OpCtxState::Initialized, OpCtxState::SinglepartActive) => {
                self.state = new_state;
                Ok(())
            }
            (OpCtxState::Initialized, OpCtxState::MultipartActive) => {
                self.state = new_state;
                Ok(())
            }
            (OpCtxState::MultipartActive, OpCtxState::MultipartReady) => {
                self.state = new_state;
                Ok(())
            }
            _ => Err(vtok_backend::types::BackendError::InvalidState(
                format!("Cannot transition from {:?} to {:?}", self.state, new_state)
            )),
        }
    }
}

/// Estimate signature length based on mechanism
fn estimate_signature_length(mech: &Mechanism) -> usize {
    match mech {
        Mechanism::RsaPkcs(_) | Mechanism::RsaPkcsPss(_, _) | Mechanism::RsaX509 => 256, // 2048-bit RSA
        Mechanism::Ecdsa(_) => 64, // P-256 ECDSA
        _ => 256, // Default
    }
}