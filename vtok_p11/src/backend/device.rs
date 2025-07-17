// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vtok_common::config::Config;
use log::{error, trace};

use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use super::{DeviceTrait, Session, SessionTrait, Slot, Token, VtokBackend};
use crate::defs;
use crate::pkcs11;
use crate::{Error, Result};
use std::any::Any;

/// The root device container. Holds a known number of device slots.
/// A successful provisioning operation will attach a token to the respective
/// slot. Newly created sessions are attached to their respective slots and
/// the user authenticates against the token PIN from those slots respectively.
pub struct Device<B: VtokBackend> {
    slots: Vec<Slot<B>>,
    session_slot_map: HashMap<pkcs11::CK_SESSION_HANDLE, pkcs11::CK_SLOT_ID>,
    next_session_handle: pkcs11::CK_SESSION_HANDLE,
    config_update_time: SystemTime,
    backend: Arc<B>,
}

impl<B: VtokBackend + 'static> Device<B> {
    pub fn new(backend: B) -> Result<Self> {
        let config = Config::load_ro().map_err(|_| Error::GeneralError)?;
        let config_update_time = Config::modification_time().map_err(|_| Error::GeneralError)?;
        let backend = Arc::new(backend);

        let mut slots = Vec::with_capacity(defs::MAX_SLOTS);
        for (slot_id, slot_config) in config.slots().iter().enumerate() {
            slots.push(match slot_config {
                None => Slot::new(slot_id as pkcs11::CK_SLOT_ID),
                Some(token_config) => Slot::new_with_token(
                    slot_id as pkcs11::CK_SLOT_ID,
                    Token::from_config(
                        slot_id as pkcs11::CK_SLOT_ID,
                        &token_config,
                        backend.clone(),
                    )
                    .map_err(Error::TokenError)?,
                ),
            });
        }

        Ok(Self {
            slots,
            session_slot_map: HashMap::new(),
            next_session_handle: 1,
            config_update_time,
            backend,
        })
    }

    pub fn ck_info(&self) -> pkcs11::CK_INFO {
        pkcs11::CK_INFO {
            cryptokiVersion: defs::CRYPTOKI_VERSION,
            manufacturerID: ck_padded_str!(defs::DEVICE_MANUFACTURER, 32),
            flags: 0,
            libraryDescription: ck_padded_str!(defs::DEVICE_DESCRIPTION, 32),
            libraryVersion: defs::DEVICE_VERSION,
        }
    }

    pub fn ck_slot_ids(&self, must_have_token: bool) -> Vec<pkcs11::CK_SLOT_ID> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| {
                if must_have_token && !slot.has_token() {
                    None
                } else {
                    Some(idx as pkcs11::CK_SLOT_ID)
                }
            })
            .collect()
    }

    pub fn slot_count(&self, must_have_token: bool) -> usize {
        self.slots
            .iter()
            .filter(|slot| !must_have_token || slot.has_token())
            .count()
    }

    pub fn open_session(
        &mut self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_SESSION_HANDLE> {
        let handle = self.next_session_handle;

        self.slot_mut(slot_id)
            .ok_or(Error::CkError(pkcs11::CKR_SLOT_ID_INVALID))?
            .token_mut()
            .ok_or(Error::CkError(pkcs11::CKR_TOKEN_NOT_PRESENT))?
            .open_session(handle)
            .map_err(Error::TokenError)?;

        self.session_slot_map.insert(handle, slot_id);
        self.next_session_handle += 1;

        Ok(handle)
    }

    pub fn close_session(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        let slot_id = *self
            .session_slot_map
            .get(&handle)
            .ok_or(Error::SessionHandleInvalid)?;
        self.token_mut(slot_id)?
            .close_session(handle)
            .map_err(Error::TokenError)?;
        self.session_slot_map.remove(&handle);
        Ok(())
    }

    pub fn close_all_slot_sessions(&mut self, slot_id: pkcs11::CK_SLOT_ID) -> Result<()> {
        self.token_mut(slot_id)
            .map(|tok| tok.close_all_sessions())?;
        self.session_slot_map.retain(|_, &mut sid| sid != slot_id);
        Ok(())
    }

    pub fn session(&self, handle: pkcs11::CK_SESSION_HANDLE) -> Option<Arc<Mutex<Session<B>>>> {
        self.session_slot_map
            .get(&handle)
            .and_then(|&slot_id| self.token(slot_id).ok())
            .and_then(|token| token.session(handle))
    }

    pub fn session_mut(
        &mut self,
        handle: pkcs11::CK_SESSION_HANDLE,
    ) -> Option<Arc<Mutex<Session<B>>>> {
        let slot_id = *self.session_slot_map.get(&handle)?;

        // If the session handle is valid, try to synchronize all the slots with the current state.
        self.reload_slots();

        match self.token(slot_id) {
            Ok(token) => token.session(handle),
            Err(_) => None,
        }
    }

    fn do_reload_slots(&mut self) -> bool {
        let config = match Config::load_ro() {
            Ok(config) => config,
            Err(_) => {
                error!("Failed to reload slots: Unable to load configuration.");
                return false;
            }
        };

        for (slot_id, new_slot_config) in config.slots().iter().enumerate() {
            match (new_slot_config, self.slot(slot_id as u64)) {
                // The token is not in use anymore.
                (None, Some(_token_config)) => {
                    self.close_all_slot_sessions(slot_id as u64);
                    self.slots[slot_id] = Slot::new(slot_id as u64);
                }
                // A new token is available in the database.
                (Some(new_token_config), None) => {
                    if let Ok(new_token) = Token::from_config(
                        slot_id as pkcs11::CK_SLOT_ID,
                        &new_token_config,
                        self.backend.clone(),
                    ) {
                        Slot::new_with_token(slot_id as pkcs11::CK_SLOT_ID, new_token);
                    } else {
                        error!("Could not create a new slot at index {}!", slot_id);
                    }
                }
                // The token exists both in the slot data and the database.
                // Check if a refresh is needed.
                (Some(new_token_config), Some(_token_config)) => {
                    if let Ok(token) =
                        self.token_unchecked_mut(slot_id as pkcs11::CK_SLOT_ID)
                    {
                        //TODO: Implement an update/try_update method as well.
                        token.refresh(new_token_config.expiry_ts);
                    }
                }
                (_, _) => {
                    // The slot is up-to-date.
                }
            }
        }

        true
    }

    fn reload_slots(&mut self) {
        if let Ok(mtime) = Config::modification_time() {
            if mtime != self.config_update_time {
                trace!("Detected configuration update. Reloading slot information...");
                if self.do_reload_slots() {
                    self.config_update_time = mtime;
                    trace!("The slots have been successfully updated.");
                }
            }
        }
    }

    pub fn login(&mut self, session_handle: pkcs11::CK_SESSION_HANDLE, pin: &str) -> Result<()> {
        let slot_id = *self
            .session_slot_map
            .get(&session_handle)
            .ok_or(Error::SessionHandleInvalid)?;
        self.token_mut(slot_id)?
            .login(session_handle, pin)
            .map_err(Error::TokenError)
    }

    pub fn logout(&mut self, session_handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        let slot_id = *self
            .session_slot_map
            .get(&session_handle)
            .ok_or(Error::SessionHandleInvalid)?;
        self.token_mut(slot_id)?
            .logout(session_handle)
            .map_err(Error::TokenError)
    }

    pub fn slot(&self, slot_id: pkcs11::CK_SLOT_ID) -> Option<&Slot<B>> {
        if (slot_id as usize) >= self.slots.len() {
            return None;
        }
        Some(&self.slots[slot_id as usize])
    }

    pub fn slot_mut(&mut self, slot_id: pkcs11::CK_SLOT_ID) -> Option<&mut Slot<B>> {
        if (slot_id as usize) >= self.slots.len() {
            return None;
        }
        Some(&mut self.slots[slot_id as usize])
    }

    pub fn token(&self, slot_id: pkcs11::CK_SLOT_ID) -> Result<&Token<B>> {
        self.slot(slot_id)
            .ok_or(Error::SlotIdInvalid)
            .and_then(|slot| slot.token().ok_or(Error::TokenNotPresent))
    }

    pub fn token_mut(&mut self, slot_id: pkcs11::CK_SLOT_ID) -> Result<&mut Token<B>> {
        self.slot_mut(slot_id)
            .ok_or(Error::SlotIdInvalid)
            .and_then(|slot| slot.token_mut().ok_or(Error::TokenNotPresent))
    }

    pub fn token_unchecked_mut(&mut self, slot_id: pkcs11::CK_SLOT_ID) -> Result<&mut Token<B>> {
        self.slot_mut(slot_id)
            .ok_or(Error::SlotIdInvalid)
            .and_then(|slot| slot.token_unchecked_mut().ok_or(Error::TokenNotPresent))
    }
}

impl<B: VtokBackend + 'static> DeviceTrait for Device<B> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn ck_info(&self) -> pkcs11::CK_INFO {
        self.ck_info()
    }

    fn slot_count(&self, token_present: bool) -> usize {
        self.slot_count(token_present)
    }

    fn ck_slot_ids(&self, token_present: bool) -> Vec<pkcs11::CK_SLOT_ID> {
        self.ck_slot_ids(token_present)
    }

    fn slot(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Option<Arc<Mutex<dyn Any + Send + Sync>>> {
        self.slot(slot_id)
            .map(|s| Arc::new(Mutex::new(s.clone())) as Arc<Mutex<dyn Any + Send + Sync>>)
    }

    fn open_session(
        &mut self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_SESSION_HANDLE> {
        self.open_session(slot_id)
    }

    fn close_session(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        self.close_session(handle)
    }

    fn close_all_slot_sessions(&mut self, slot_id: pkcs11::CK_SLOT_ID) {
        self.close_all_slot_sessions(slot_id).unwrap()
    }

    fn session(
        &self,
        handle: pkcs11::CK_SESSION_HANDLE,
    ) -> Option<Arc<Mutex<dyn SessionTrait + Send + Sync>>> {
        self.session(handle)
            .map(|s| s as Arc<Mutex<dyn SessionTrait + Send + Sync>>)
    }

    fn session_mut(
        &mut self,
        handle: pkcs11::CK_SESSION_HANDLE,
    ) -> Option<Arc<Mutex<dyn SessionTrait + Send + Sync>>> {
        self.session_mut(handle)
            .map(|s| s as Arc<Mutex<dyn SessionTrait + Send + Sync>>)
    }

    fn login(&mut self, handle: pkcs11::CK_SESSION_HANDLE, pin: &str) -> Result<()> {
        self.login(handle, pin)
    }

    fn logout(&mut self, handle: pkcs11::CK_SESSION_HANDLE) -> Result<()> {
        self.logout(handle)
    }
}
