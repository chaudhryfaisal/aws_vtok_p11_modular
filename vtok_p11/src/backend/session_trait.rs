// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::backend::db::{Object, ObjectHandle};
use crate::backend::session::SessionState;
use crate::backend::Mechanism;
use crate::pkcs11;
use crate::util::CkRawAttrTemplate;
use crate::Result;
use std::any::Any;
use vtok_p11_trait::{DigestContext, SignContext, VerifyContext};

pub trait SessionTrait: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn ck_info(&self) -> pkcs11::CK_SESSION_INFO;
    fn state(&self) -> SessionState;
    fn set_state(&mut self, state: SessionState);
    fn object(&self, handle: ObjectHandle) -> Option<&Object>;
    fn enum_init(&mut self, template: Option<CkRawAttrTemplate>);
    fn enum_next_chunk(&mut self, count: usize) -> Option<&[ObjectHandle]>;
    fn enum_active(&self) -> bool;
    fn enum_finalize(&mut self) -> Result<()>;
    fn digest_init(&mut self, mech: &Mechanism) -> Result<()>;
    fn digest_ctx(&mut self) -> &mut Option<Box<dyn DigestContext>>;
    fn sign_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()>;
    fn sign_ctx(&mut self) -> &mut Option<Box<dyn SignContext>>;
    fn verify_init(&mut self, mech: &Mechanism, key_handle: ObjectHandle) -> Result<()>;
    fn verify_ctx(&mut self) -> &mut Option<Box<dyn VerifyContext>>;
}