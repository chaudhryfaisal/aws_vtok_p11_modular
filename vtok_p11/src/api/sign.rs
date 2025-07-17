// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::util::copy_data_to_ck_out_slice;
use crate::backend::{Mechanism, VtokBackend};
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;
use log::{error, trace};

/// See PKCS#11 v2.40 5.11 Signing and MACing functions

pub extern "C" fn C_SignInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: *mut pkcs11::CK_MECHANISM,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_SignInit() called");

    if pMechanism.is_null() {
        error!("C_SignInit() called with NULL mech");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }
    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };
    let mech = match Mechanism::from_ckraw_mech(&raw_mech.type_()) {
        Some(mech) => mech,
        None => return pkcs11::CKR_MECHANISM_INVALID,
    };

    lock_session_mut!(hSession, _session_guard, session);
    session
        .sign_init(&mech, hKey.into())
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Sign(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: *mut pkcs11::CK_BYTE,
    ulDataLen: pkcs11::CK_ULONG,
    pSignature: *mut pkcs11::CK_BYTE,
    pulSignatureLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_Sign() called");

    lock_session_mut!(hSession, _session_guard, session);

    let mut sign_ctx = match session.sign_ctx().take() {
        Some(ctx) => ctx,
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };

    let in_slice = ck_in_buf_to_slice!(pData, ulDataLen, {});
    if let Err(_) = sign_ctx.update(in_slice) {
        return pkcs11::CKR_GENERAL_ERROR;
    }

    let signature = match sign_ctx.finalize() {
        Ok(signature) => signature,
        Err(_) => return pkcs11::CKR_GENERAL_ERROR,
    };

    let out_slice = ck_out_buf_to_mut_slice!(pSignature, pulSignatureLen, signature.len(), {});
    copy_data_to_ck_out_slice(&signature, out_slice, pulSignatureLen)
}

pub extern "C" fn C_SignUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: *mut pkcs11::CK_BYTE,
    ulPartLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_SignUpdate() called");
    if pPart.is_null() {
        error!("C_SignUpdate() called with null data ptr.");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_session_mut!(hSession, _session_guard, session);
    let in_slice = ck_in_buf_to_slice!(pPart, ulPartLen, {
        session.sign_ctx().take();
    });
    session
        .sign_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| ctx.update(in_slice).map_err(|_| Error::GeneralError))
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_SignFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pSignature: *mut pkcs11::CK_BYTE,
    pulSignatureLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_SignFinal() called");

    lock_session_mut!(hSession, _session_guard, session);

    let sign_ctx = match session.sign_ctx().take() {
        Some(ctx) => ctx,
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };

    let signature = match sign_ctx.finalize() {
        Ok(signature) => signature,
        Err(_) => return pkcs11::CKR_GENERAL_ERROR,
    };

    let out_slice = ck_out_buf_to_mut_slice!(pSignature, pulSignatureLen, signature.len(), {});
    copy_data_to_ck_out_slice(&signature, out_slice, pulSignatureLen)
}
