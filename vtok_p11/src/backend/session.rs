// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp;

use super::db::{Db, Object, ObjectHandle, ObjectKind};
use super::session_trait::SessionTrait;
use super::Mechanism;
use crate::pkcs11;
use crate::util::CkRawAttrTemplate;
use crate::{Error, Result};
use std::any::Any;
use std::sync::Arc;
use vtok_p11_trait::{
    self as crypto, CertAttribute, Certificate, DigestContext, Key, KeyAttribute, KeyType,
    SignContext, VerifyContext, VtokBackend,
};

struct EnumCtx {
    handles: Vec<ObjectHandle>,
    index: usize,
}

impl EnumCtx {
    fn new(handles: Vec<ObjectHandle>) -> Self {
        Self { handles, index: 0 }
    }
    fn next_chunk(&mut self, count: usize) -> &[ObjectHandle] {
        let end = cmp::min(self.index + count, self.handles.len());
        let ret = &self.handles[self.index..end];
        self.index += ret.len();
        ret
    }
}

#[derive(Clone, Copy)]
pub enum SessionState {
    RoPublic,
    RoUser,
}

/// The active session states
/// New sessions start with R/O Public state and once
/// the user logins, the session shall enter R/O User Functions
/// state. Logout will cause the state to transition back to
/// the R/O Public state.
impl SessionState {
    fn to_ck_state(&self) -> pkcs11::CK_STATE {
        match self {
            Self::RoPublic => pkcs11::CKS_RO_PUBLIC_SESSION,
            Self::RoUser => pkcs11::CKS_RO_USER_FUNCTIONS,
        }
    }
}

/// The session container. Holds the provisioned object database
/// and also the operation context currently active (if any).
/// The enumeration context is used only when user requests to
/// find all objects attached. The other contexts are during actual
/// session cryptopgrahic operations. Due to the nature of the Cryptoki
/// PKCS#11 specification all operation contexts (digest, sign, verify,
/// encrypt, decrypt) are mutually exclusive.
pub struct Session<B: VtokBackend> {
    slot_id: pkcs11::CK_SLOT_ID,
    state: SessionState,
    db: Db,
    enum_ctx: Option<EnumCtx>,
    digest_ctx: Option<Box<dyn DigestContext>>,
    sign_ctx: Option<Box<dyn SignContext>>,
    verify_ctx: Option<Box<dyn VerifyContext>>,
    // TODO: Add Encrypt/Decrypt context to VtokBackend trait
    // decrypt_ctx: Option<Box<dyn DecryptContext>>,
    // encrypt_ctx: Option<Box<dyn EncryptContext>>,
    backend: Arc<B>,
}

impl<B: VtokBackend> Session<B> {
    pub fn new(
        slot_id: pkcs11::CK_SLOT_ID,
        db: Db,
        state: SessionState,
        backend: Arc<B>,
    ) -> Self {
        Self {
            slot_id,
            state,
            db,
            enum_ctx: None,
            digest_ctx: None,
            sign_ctx: None,
            verify_ctx: None,
            // decrypt_ctx: None,
            // encrypt_ctx: None,
            backend,
        }
    }

    pub fn ck_info(&self) -> pkcs11::CK_SESSION_INFO {
        pkcs11::CK_SESSION_INFO {
            slotID: self.slot_id,
            state: self.state.to_ck_state(),
            flags: pkcs11::CKF_SERIAL_SESSION,
            ulDeviceError: pkcs11::CKR_OK,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn set_state(&mut self, state: SessionState) {
        self.state = state
    }

    pub fn object(&self, handle: ObjectHandle) -> Option<&Object> {
        self.db.object(handle)
    }

    /// Enumerate session objects, possibly matching a given template.
    /// If no template is provided, all available objects are enumerated.
    pub fn enum_init(&mut self, template: Option<CkRawAttrTemplate>) {
        let enable_private = self.check_user_logged_in().is_ok();
        let handles: Vec<ObjectHandle> = self
            .db
            .enumerate()
            .filter_map(|(h, o)| {
                let pass = (enable_private || !o.is_private())
                    && template
                        .as_ref()
                        .map(|tpl| o.match_attr_template(tpl))
                        // Per the PKCS#11 2.40 spec, mechanism objects should not be listed
                        // unless specifically searched for by using a template with
                        // CKA_CLASS = CKO_MECHANISM.
                        .unwrap_or(!o.is_mechanism());
                if pass {
                    Some(h)
                } else {
                    None
                }
            })
            .collect();
        self.enum_ctx = Some(EnumCtx::new(handles));
    }

    pub fn enum_next_chunk(&mut self, count: usize) -> Option<&[ObjectHandle]> {
        self.enum_ctx.as_mut().map(|x| x.next_chunk(count))
    }

    /// Enumeration is already in progress
    pub fn enum_active(&self) -> bool {
        self.enum_ctx.is_some()
    }

    /// Finalize an active enumeration operation
    pub fn enum_finalize(&mut self) -> Result<()> {
        self.enum_ctx
            .take()
            .ok_or(Error::CkError(pkcs11::CKR_OPERATION_NOT_INITIALIZED))?;
        Ok(())
    }

    /// Initialize a digest context for a digest operation
    pub fn digest_init(&mut self, mech: &Mechanism) -> Result<()> {
        self.digest_ctx = Some(
            self.backend
                .digest_init(mech)
                .map_err(|_| Error::CkError(pkcs11::CKR_MECHANISM_INVALID))?,
        );
        Ok(())
    }

    pub fn digest_ctx(&mut self) -> &mut Option<Box<dyn DigestContext>> {
        &mut self.digest_ctx
    }

    /// Initialize a signing context for a signing operation
    pub fn sign_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        self.check_user_logged_in()?;
        let key = self.key_for_mech(mech, key_handle)?;
        self.sign_ctx = Some(
            self.backend
                .sign_init(mech, key.as_ref())
                .map_err(|_| Error::CkError(pkcs11::CKR_GENERAL_ERROR))?,
        );
        Ok(())
    }

    pub fn sign_ctx(&mut self) -> &mut Option<Box<dyn SignContext>> {
        &mut self.sign_ctx
    }

    /// Initialize a verification context for a verification operation
    pub fn verify_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        self.check_user_logged_in()?;
        let key = self.key_for_mech(mech, key_handle)?;
        self.verify_ctx = Some(
            self.backend
                .verify_init(mech, key.as_ref())
                .map_err(|_| Error::CkError(pkcs11::CKR_GENERAL_ERROR))?,
        );
        Ok(())
    }

    pub fn verify_ctx(&mut self) -> &mut Option<Box<dyn VerifyContext>> {
        &mut self.verify_ctx
    }

    /// Helper for checking if the user has been logged in. Some cryptograhic
    /// operations (i.e. signing with private keys) require login.
    fn check_user_logged_in(&self) -> Result<()> {
        match self.state {
            SessionState::RoUser => Ok(()),
            _ => Err(Error::UserNotLoggedIn),
        }
    }

    fn key_for_mech(&self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<Box<dyn Key>> {
        let key_obj = self.db.object(key_handle).ok_or(Error::KeyHandleInvalid)?;
        let pem = match (mech, key_obj.kind()) {
            (
                Mechanism::RsaX509 | Mechanism::RsaPkcs(..) | Mechanism::RsaPkcsPss(..),
                ObjectKind::RsaPrivateKey(pem),
            ) => Ok(pem.as_str()),
            (
                Mechanism::RsaX509 | Mechanism::RsaPkcs(..) | Mechanism::RsaPkcsPss(..),
                ObjectKind::RsaPublicKey(pem),
            ) => Ok(pem.as_str()),
            (Mechanism::Ecdsa(..), ObjectKind::EcPrivateKey(pem)) => Ok(pem.as_str()),
            (Mechanism::Ecdsa(..), ObjectKind::EcPublicKey(pem)) => Ok(pem.as_str()),
            _ => Err(Error::KeyTypeInconsistent),
        }?;
        self.backend
            .load_private_key(pem)
            .map_err(|_| Error::KeyHandleInvalid)
    }
}

impl<B: VtokBackend + 'static> SessionTrait for Session<B> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn ck_info(&self) -> pkcs11::CK_SESSION_INFO {
        Session::ck_info(self)
    }

    fn state(&self) -> SessionState {
        Session::state(self)
    }

    fn set_state(&mut self, state: SessionState) {
        Session::set_state(self, state)
    }

    fn object(&self, handle: ObjectHandle) -> Option<&Object> {
        Session::object(self, handle)
    }

    fn enum_init(&mut self, template: Option<CkRawAttrTemplate>) {
        Session::enum_init(self, template)
    }

    fn enum_next_chunk(&mut self, count: usize) -> Option<&[ObjectHandle]> {
        Session::enum_next_chunk(self, count)
    }

    fn enum_active(&self) -> bool {
        Session::enum_active(self)
    }

    fn enum_finalize(&mut self) -> Result<()> {
        Session::enum_finalize(self)
    }

    fn digest_init(&mut self, mech: &Mechanism) -> Result<()> {
        Session::digest_init(self, mech)
    }

    fn digest_ctx(&mut self) -> &mut Option<Box<dyn DigestContext>> {
        Session::digest_ctx(self)
    }

    fn sign_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        Session::sign_init(self, mech, key_handle)
    }

    fn sign_ctx(&mut self) -> &mut Option<Box<dyn SignContext>> {
        Session::sign_ctx(self)
    }

    fn verify_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()> {
        Session::verify_init(self, mech, key_handle)
    }

    fn verify_ctx(&mut self) -> &mut Option<Box<dyn VerifyContext>> {
        Session::verify_ctx(self)
    }
}
