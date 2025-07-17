// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::util::copy_data_to_ck_out_slice;
use crate::backend::Mechanism;
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;
use log::{error, trace};

/// See PKCS#11 v2.40 Section 5.10 Message digesting functions

pub extern "C" fn C_DigestInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: *mut pkcs11::CK_MECHANISM,
) -> pkcs11::CK_RV {
    trace!("C_DigestInit() called");

    if pMechanism.is_null() {
        error!("C_DigestInit() called with NULL mech ptr");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }
    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };
    let mech = match Mechanism::from_ckraw_mech(&raw_mech.mechanism) {
        Some(mech) => mech,
        None => return pkcs11::CKR_MECHANISM_INVALID,
    };

    lock_session_mut!(hSession, _session_guard, session);
    session
        .digest_init(&mech)
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Digest(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: *mut pkcs11::CK_BYTE,
    ulDataLen: pkcs11::CK_ULONG,
    pDigest: *mut pkcs11::CK_BYTE,
    pulDigestLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_Digest() called");

    lock_session_mut!(hSession, _session_guard, session);

    let mut digest_ctx = match session.digest_ctx().take() {
        Some(ctx) => ctx,
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };

    let in_slice = ck_in_buf_to_slice!(pData, ulDataLen, {});
    if let Err(_) = digest_ctx.update(in_slice) {
        return pkcs11::CKR_GENERAL_ERROR;
    }

    let digest = match digest_ctx.finalize() {
        Ok(digest) => digest,
        Err(_) => return pkcs11::CKR_GENERAL_ERROR,
    };

    let out_slice = ck_out_buf_to_mut_slice!(pDigest, pulDigestLen, digest.len(), {});
    copy_data_to_ck_out_slice(&digest, out_slice, pulDigestLen)
}

pub extern "C" fn C_DigestUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: *mut pkcs11::CK_BYTE,
    ulPartLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_DigestUpdate() called");

    lock_session_mut!(hSession, _session_guard, session);
    let in_slice = ck_in_buf_to_slice!(pPart, ulPartLen, {
        session.digest_ctx().take();
    });
    session
        .digest_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| ctx.update(in_slice).map_err(|_| Error::GeneralError))
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_DigestFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pDigest: *mut pkcs11::CK_BYTE,
    pulDigestLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_DigestFinal() called");

    lock_session_mut!(hSession, _session_guard, session);

    let digest_ctx = match session.digest_ctx().take() {
        Some(ctx) => ctx,
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };

    let digest = match digest_ctx.finalize() {
        Ok(digest) => digest,
        Err(_) => return pkcs11::CKR_GENERAL_ERROR,
    };

    let out_slice = ck_out_buf_to_mut_slice!(pDigest, pulDigestLen, digest.len(), {});
    copy_data_to_ck_out_slice(&digest, out_slice, pulDigestLen)
}
