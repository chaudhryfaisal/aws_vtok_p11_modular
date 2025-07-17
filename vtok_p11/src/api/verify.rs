// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::backend::{Mechanism, VtokBackend};
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;
use log::trace;

/// See PKCS#11 v2.40 5.11 Signing and MACing functions

pub extern "C" fn C_VerifyInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_VerifyInit() called");

    if pMechanism.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };
    let mech = match Mechanism::from_ckraw_mech(&raw_mech.type_()) {
        Some(mech) => mech,
        None => return pkcs11::CKR_MECHANISM_INVALID,
    };

    lock_session_mut!(hSession, _session_guard, session);

    session
        .verify_init(&mech, hKey.into())
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Verify(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: pkcs11::CK_BYTE_PTR,
    ulDataLen: pkcs11::CK_ULONG,
    pSignature: pkcs11::CK_BYTE_PTR,
    ulSignatureLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_Verify() called");

    lock_session_mut!(hSession, _session_guard, session);

    let mut verify_ctx = match session.verify_ctx().take() {
        Some(ctx) => ctx,
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };

    let data_slice = ck_in_buf_to_slice!(pData, ulDataLen, {});
    if let Err(_) = verify_ctx.update(data_slice) {
        return pkcs11::CKR_GENERAL_ERROR;
    }

    let sig_slice = ck_in_buf_to_slice!(pSignature, ulSignatureLen, {});
    match verify_ctx.finalize(sig_slice) {
        Ok(_) => pkcs11::CKR_OK,
        Err(_) => pkcs11::CKR_SIGNATURE_INVALID,
    }
}

pub extern "C" fn C_VerifyUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: pkcs11::CK_BYTE_PTR,
    ulPartLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_VerifyUpdate() called");

    lock_session_mut!(hSession, _session_guard, session);

    let data_slice = ck_in_buf_to_slice!(pPart, ulPartLen, {});
    session
        .verify_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| ctx.update(data_slice).map_err(|_| Error::GeneralError))
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_VerifyFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pSignature: pkcs11::CK_BYTE_PTR,
    ulSignatureLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_VerifyFinal() called");

    lock_session_mut!(hSession, _session_guard, session);

    let verify_ctx = match session.verify_ctx().take() {
        Some(ctx) => ctx,
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };

    let sig_slice = ck_in_buf_to_slice!(pSignature, ulSignatureLen, {});
    match verify_ctx.finalize(sig_slice) {
        Ok(_) => pkcs11::CKR_OK,
        Err(_) => pkcs11::CKR_SIGNATURE_INVALID,
    }
}
