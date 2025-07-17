// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::util::copy_data_to_ck_out_slice;
use crate::backend::Mechanism;
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;
use log::trace;

/// See PKCS#11 v2.40 Section 5.9 Decryption functions

pub extern "C" fn C_DecryptInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_DecryptInit() called");

    if pMechanism.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };
    let mech = match Mechanism::from_ckraw_mech(&raw_mech.mechanism) {
        Some(mech) => mech,
        None => return pkcs11::CKR_MECHANISM_INVALID,
    };

    lock_session_mut!(hSession, _session_guard, session);
    // TODO: The VtokBackend trait doesn't have a decrypt_init method yet.
    // session
    //     .decrypt_init(&mech, hKey.into())
    //     .map(|_| pkcs11::CKR_OK)
    //     .unwrap_or_else(|e| e.into())
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_Decrypt(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pEncryptedData: pkcs11::CK_BYTE_PTR,
    ulEncryptedDataLen: pkcs11::CK_ULONG,
    pData: pkcs11::CK_BYTE_PTR,
    pulDataLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_Decrypt() called");

    lock_session_mut!(hSession, _session_guard, session);

    // TODO: implement this properly
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}
