//! Complete PKCS#11 provider with mock cryptographic backend
//!
//! This crate provides a standalone PKCS#11 provider that uses mock
//! implementations for all cryptographic operations. It's designed for
//! testing, development, and CI/CD environments where real cryptography
//! is not needed but PKCS#11 compatibility is required.
//!
//! # Features
//!
//! - Deterministic behavior for reproducible tests
//! - Configurable error injection for testing error handling
//! - Performance simulation for load testing
//! - Thread-safe mock operations
//! - Complete PKCS#11 C API compatibility

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate lazy_static;
#[macro_use]
extern crate log;

use std::sync::{Arc, Mutex, Once};
use lazy_static::lazy_static;

// Re-export vtok_p11 for PKCS#11 core functionality
pub use vtok_p11::*;

// Our mock backend implementation
pub mod backend;

// Provider integration
mod provider;

// Mock data management
pub mod data;

// Utility features
pub mod utils;

use backend::MockBackend;
use provider::MockProvider;

/// Global provider instance
lazy_static! {
    static ref PROVIDER: Arc<Mutex<Option<MockProvider>>> = Arc::new(Mutex::new(None));
}

static INIT: Once = Once::new();

/// Initialize the PKCS#11 provider with mock backend
fn ensure_provider_initialized() -> Result<(), vtok_p11::Error> {
    INIT.call_once(|| {
        env_logger::init();
        
        match MockBackend::new() {
            Ok(backend) => {
                let provider = MockProvider::new(backend);
                if let Ok(mut guard) = PROVIDER.lock() {
                    *guard = Some(provider);
                    info!("Mock PKCS#11 provider initialized successfully");
                } else {
                    error!("Failed to acquire provider lock during initialization");
                }
            }
            Err(e) => {
                error!("Failed to create mock backend: {:?}", e);
            }
        }
    });
    
    Ok(())
}

/// Get the global provider instance
fn get_provider() -> Result<Arc<Mutex<Option<MockProvider>>>, vtok_p11::Error> {
    ensure_provider_initialized()?;
    Ok(PROVIDER.clone())
}

// Export all PKCS#11 C API functions
// These will delegate to the vtok_p11 implementation with our mock backend

use vtok_p11::pkcs11::*;

/// C_Initialize - Initialize the PKCS#11 library
#[no_mangle]
pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    ensure_provider_initialized().unwrap_or(());
    vtok_p11::api::C_Initialize(pInitArgs)
}

/// C_Finalize - Finalize the PKCS#11 library
#[no_mangle]
pub extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    vtok_p11::api::C_Finalize(pReserved)
}

/// C_GetInfo - Get general information about the PKCS#11 library
#[no_mangle]
pub extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    vtok_p11::api::C_GetInfo(pInfo)
}

/// C_GetFunctionList - Get the list of function pointers
#[no_mangle]
pub extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    vtok_p11::api::C_GetFunctionList(ppFunctionList)
}

/// C_GetSlotList - Get the list of slots
#[no_mangle]
pub extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::token::C_GetSlotList(tokenPresent, pSlotList, pulCount)
}

/// C_GetSlotInfo - Get information about a slot
#[no_mangle]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    vtok_p11::api::token::C_GetSlotInfo(slotID, pInfo)
}

/// C_GetTokenInfo - Get information about a token
#[no_mangle]
pub extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    vtok_p11::api::token::C_GetTokenInfo(slotID, pInfo)
}

/// C_GetMechanismList - Get the list of mechanisms supported by a token
#[no_mangle]
pub extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::token::C_GetMechanismList(slotID, pMechanismList, pulCount)
}

/// C_GetMechanismInfo - Get information about a mechanism
#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    vtok_p11::api::token::C_GetMechanismInfo(slotID, type_, pInfo)
}

/// C_InitToken - Initialize a token
#[no_mangle]
pub extern "C" fn C_InitToken(
    slotID: CK_SLOT_ID,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV {
    vtok_p11::api::token::C_InitToken(slotID, pPin, ulPinLen, pLabel)
}

/// C_OpenSession - Open a session
#[no_mangle]
pub extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    vtok_p11::api::session::C_OpenSession(slotID, flags, pApplication, Notify, phSession)
}

/// C_CloseSession - Close a session
#[no_mangle]
pub extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    vtok_p11::api::session::C_CloseSession(hSession)
}

/// C_CloseAllSessions - Close all sessions for a slot
#[no_mangle]
pub extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    vtok_p11::api::session::C_CloseAllSessions(slotID)
}

/// C_GetSessionInfo - Get session information
#[no_mangle]
pub extern "C" fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) -> CK_RV {
    vtok_p11::api::session::C_GetSessionInfo(hSession, pInfo)
}

/// C_Login - Log into a token
#[no_mangle]
pub extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::token::C_Login(hSession, userType, pPin, ulPinLen)
}

/// C_Logout - Log out from a token
#[no_mangle]
pub extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    vtok_p11::api::token::C_Logout(hSession)
}

// Object management functions
/// C_FindObjectsInit - Initialize object search
#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::object::C_FindObjectsInit(hSession, pTemplate, ulCount)
}

/// C_FindObjects - Find objects
#[no_mangle]
pub extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::object::C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount)
}

/// C_FindObjectsFinal - Finalize object search
#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    vtok_p11::api::object::C_FindObjectsFinal(hSession)
}

/// C_GetAttributeValue - Get attribute values
#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::object::C_GetAttributeValue(hSession, hObject, pTemplate, ulCount)
}

/// C_GetObjectSize - Get object size
#[no_mangle]
pub extern "C" fn C_GetObjectSize(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::object::C_GetObjectSize(hSession, hObject, pulSize)
}

// Cryptographic functions
/// C_DigestInit - Initialize digest operation
#[no_mangle]
pub extern "C" fn C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) -> CK_RV {
    vtok_p11::api::digest::C_DigestInit(hSession, pMechanism)
}

/// C_Digest - Perform digest operation
#[no_mangle]
pub extern "C" fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::digest::C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen)
}

/// C_DigestUpdate - Update digest operation
#[no_mangle]
pub extern "C" fn C_DigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::digest::C_DigestUpdate(hSession, pPart, ulPartLen)
}

/// C_DigestFinal - Finalize digest operation
#[no_mangle]
pub extern "C" fn C_DigestFinal(
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::digest::C_DigestFinal(hSession, pDigest, pulDigestLen)
}

/// C_SignInit - Initialize signing operation
#[no_mangle]
pub extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    vtok_p11::api::sign::C_SignInit(hSession, pMechanism, hKey)
}

/// C_Sign - Perform signing operation
#[no_mangle]
pub extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::sign::C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
}

/// C_SignUpdate - Update signing operation
#[no_mangle]
pub extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::sign::C_SignUpdate(hSession, pPart, ulPartLen)
}

/// C_SignFinal - Finalize signing operation
#[no_mangle]
pub extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::sign::C_SignFinal(hSession, pSignature, pulSignatureLen)
}

/// C_VerifyInit - Initialize verification operation
#[no_mangle]
pub extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    vtok_p11::api::verify::C_VerifyInit(hSession, pMechanism, hKey)
}

/// C_Verify - Perform verification operation
#[no_mangle]
pub extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::verify::C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen)
}

/// C_VerifyUpdate - Update verification operation
#[no_mangle]
pub extern "C" fn C_VerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::verify::C_VerifyUpdate(hSession, pPart, ulPartLen)
}

/// C_VerifyFinal - Finalize verification operation
#[no_mangle]
pub extern "C" fn C_VerifyFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    vtok_p11::api::verify::C_VerifyFinal(hSession, pSignature, ulSignatureLen)
}

/// C_EncryptInit - Initialize encryption operation
#[no_mangle]
pub extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    vtok_p11::api::encrypt::C_EncryptInit(hSession, pMechanism, hKey)
}

/// C_Encrypt - Perform encryption operation
#[no_mangle]
pub extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::encrypt::C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)
}

/// C_DecryptInit - Initialize decryption operation
#[no_mangle]
pub extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    vtok_p11::api::decrypt::C_DecryptInit(hSession, pMechanism, hKey)
}

/// C_Decrypt - Perform decryption operation
#[no_mangle]
pub extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    vtok_p11::api::decrypt::C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen)
}

// Additional functions that return CKR_FUNCTION_NOT_SUPPORTED
macro_rules! not_supported {
    ($name:ident, $($param:ident: $type:ty),*) => {
        #[no_mangle]
        pub extern "C" fn $name($($param: $type),*) -> CK_RV {
            CKR_FUNCTION_NOT_SUPPORTED
        }
    };
}

not_supported!(C_InitPIN, hSession: CK_SESSION_HANDLE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG);
not_supported!(C_SetPIN, hSession: CK_SESSION_HANDLE, pOldPin: CK_UTF8CHAR_PTR, ulOldLen: CK_ULONG, pNewPin: CK_UTF8CHAR_PTR, ulNewLen: CK_ULONG);
not_supported!(C_GetOperationState, hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, pulOperationStateLen: CK_ULONG_PTR);
not_supported!(C_SetOperationState, hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, ulOperationStateLen: CK_ULONG, hEncryptionKey: CK_OBJECT_HANDLE, hAuthenticationKey: CK_OBJECT_HANDLE);
not_supported!(C_CreateObject, hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phObject: CK_OBJECT_HANDLE_PTR);
not_supported!(C_CopyObject, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phNewObject: CK_OBJECT_HANDLE_PTR);
not_supported!(C_DestroyObject, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE);
not_supported!(C_SetAttributeValue, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG);
not_supported!(C_EncryptUpdate, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR);
not_supported!(C_EncryptFinal, hSession: CK_SESSION_HANDLE, pLastEncryptedPart: CK_BYTE_PTR, pulLastEncryptedPartLen: CK_ULONG_PTR);
not_supported!(C_DecryptUpdate, hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR);
not_supported!(C_DecryptFinal, hSession: CK_SESSION_HANDLE, pLastPart: CK_BYTE_PTR, pulLastPartLen: CK_ULONG_PTR);
not_supported!(C_DigestKey, hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE);
not_supported!(C_SignRecoverInit, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
not_supported!(C_SignRecover, hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR);
not_supported!(C_VerifyRecoverInit, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
not_supported!(C_VerifyRecover, hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR);
not_supported!(C_DigestEncryptUpdate, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR);
not_supported!(C_DecryptDigestUpdate, hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR);
not_supported!(C_SignEncryptUpdate, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR);
not_supported!(C_DecryptVerifyUpdate, hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR);
not_supported!(C_GenerateKey, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR);
not_supported!(C_GenerateKeyPair, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pPublicKeyTemplate: CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount: CK_ULONG, pPrivateKeyTemplate: CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount: CK_ULONG, phPublicKey: CK_OBJECT_HANDLE_PTR, phPrivateKey: CK_OBJECT_HANDLE_PTR);
not_supported!(C_WrapKey, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hWrappingKey: CK_OBJECT_HANDLE, hKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, pulWrappedKeyLen: CK_ULONG_PTR);
not_supported!(C_UnwrapKey, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hUnwrappingKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, ulWrappedKeyLen: CK_ULONG, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR);
not_supported!(C_DeriveKey, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hBaseKey: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR);
not_supported!(C_SeedRandom, hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG);
not_supported!(C_GenerateRandom, hSession: CK_SESSION_HANDLE, RandomData: CK_BYTE_PTR, ulRandomLen: CK_ULONG);
not_supported!(C_GetFunctionStatus, hSession: CK_SESSION_HANDLE);
not_supported!(C_CancelFunction, hSession: CK_SESSION_HANDLE);
not_supported!(C_WaitForSlotEvent, flags: CK_FLAGS, pSlot: CK_SLOT_ID_PTR, pReserved: CK_VOID_PTR);