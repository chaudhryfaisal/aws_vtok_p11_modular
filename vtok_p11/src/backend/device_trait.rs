// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::backend::session_trait::SessionTrait;
use crate::pkcs11;
use crate::Result;
use std::any::Any;
use std::sync::{Arc, Mutex};
use vtok_p11_trait::VtokBackend;

/// A trait that exposes the public, non-generic methods of the `Device` struct.
/// This is used for type erasure of the global `DEVICE` static.
pub trait DeviceTrait: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn ck_info(&self) -> pkcs11::CK_INFO;
    fn slot_count(&self, token_present: bool) -> usize;
    fn ck_slot_ids(&self, token_present: bool) -> Vec<pkcs11::CK_SLOT_ID>;
    fn slot(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Option<Arc<Mutex<dyn Any + Send + Sync>>>;

    fn open_session(
        &mut self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_SESSION_HANDLE>;
    fn close_session(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()>;
    fn close_all_slot_sessions(&mut self, slot_id: pkcs11::CK_SLOT_ID);

    fn session(
        &self,
        handle: pkcs11::CK_SESSION_HANDLE,
    ) -> Option<Arc<Mutex<dyn SessionTrait + Send + Sync>>>;
    fn session_mut(
        &mut self,
        handle: pkcs11::CK_SESSION_HANDLE,
    ) -> Option<Arc<Mutex<dyn SessionTrait + Send + Sync>>>;

    fn login(&mut self, handle: pkcs11::CK_SESSION_HANDLE, pin: &str) -> Result<()>;
    fn logout(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()>;
}