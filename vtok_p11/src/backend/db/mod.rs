// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vtok_common::config;
use log::warn;

use vtok_p11_trait::{self as crypto, CertCategory, EcKey, RsaKey};
use crate::defs;
use crate::pkcs11;

pub mod object;

pub use object::{Object, ObjectHandle, ObjectKind};

// NOTE: for now, we use these *Info structs to construct key objects. The source PEM is
// preserved, so that a crypto::Pkey (an EVP_PKEY wrapper) can be constructed whenever
// it is needed (e.g. at operation context initialization).
// If the PEM to EVP_PKEY conversion turns out to impact performance, we could construct
// the crypto::Pkey object at DB creation time, and replace the *Info structs with it,
// provided we also implement a proper cloning mechanism for crypto::Pkey. This is needed
// in order to make sure that each session gets its own copy of each key, and maintain
// thread safety.
// Cloning could be done via RSAPrivateKey_dup() and EC_KEY_dup(), together with a TryClone
// trait, since these operations can fail.
#[derive(Clone)]
pub struct RsaKeyInfo {
    pub priv_pem: String,
    pub id: pkcs11::CK_BYTE,
    pub label: String,
    pub num_bits: pkcs11::CK_ULONG,
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

#[derive(Clone)]
pub struct EcKeyInfo {
    pub priv_pem: String,
    pub id: pkcs11::CK_BYTE,
    pub label: String,
    pub params_x962: Vec<u8>,
    pub point_q_x962: Vec<u8>,
}

#[derive(Clone)]
pub struct CertInfo {
    pub categ: CertCategory,
    pub id: pkcs11::CK_BYTE,
    pub label: String,
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub serno_der: Vec<u8>,
    pub cert_der: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    GeneralError,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Db {
    token_pin: String,
    objects: Vec<Object>,
}

impl Db {
    pub fn from_token_config<B: crypto::VtokBackend>(
        token_config: &config::Token,
        backend: &B,
    ) -> Result<Self> {
        let mut objects = Vec::new();

        for mech in defs::TOKEN_MECH_LIST.iter() {
            objects.push(Object::new_mechanism(*mech));
        }

        for key_config in token_config.private_keys.iter() {
            let key = match backend.load_private_key(&key_config.pem) {
                Ok(key) => key,
                Err(_) => {
                    warn!("Failed to load private key: {}", key_config.label);
                    continue;
                }
            };

            let key_type = key.key_type();
            let public_key = match key.public_key() {
                Ok(pub_key) => Some(pub_key),
                Err(_) => {
                    warn!(
                        "Failed to get public key from private key: {}",
                        key_config.label
                    );
                    None
                }
            };

            match key_type {
                crypto::KeyType::Rsa => {
                    let rsa_key = key.as_any().downcast_ref::<dyn RsaKey>().unwrap();
                    let info = RsaKeyInfo {
                        id: key_config.id,
                        label: key_config.label.clone(),
                        priv_pem: key_config.pem.to_string(),
                        num_bits: rsa_key.modulus_bits() as u64,
                        modulus: rsa_key.modulus(),
                        public_exponent: rsa_key.public_exponent(),
                    };
                    objects.push(Object::new_rsa_private_key(info.clone()));
                    if let Some(pub_key) = public_key {
                        let rsa_pub_key =
                            pub_key.as_any().downcast_ref::<dyn RsaKey>().unwrap();
                        let pub_info = RsaKeyInfo {
                            id: key_config.id,
                            label: key_config.label.clone(),
                            priv_pem: "".to_string(),
                            num_bits: rsa_pub_key.modulus_bits() as u64,
                            modulus: rsa_pub_key.modulus(),
                            public_exponent: rsa_pub_key.public_exponent(),
                        };
                        objects.push(Object::new_rsa_public_key(pub_info));
                    }
                }
                crypto::KeyType::Ec => {
                    let ec_key = key.as_any().downcast_ref::<dyn EcKey>().unwrap();
                    let info = EcKeyInfo {
                        id: key_config.id,
                        label: key_config.label.clone(),
                        priv_pem: key_config.pem.to_string(),
                        params_x962: ec_key.params_x962(),
                        point_q_x962: ec_key.point_q_x962(),
                    };
                    objects.push(Object::new_ec_private_key(info.clone()));
                    if let Some(pub_key) = public_key {
                        let ec_pub_key =
                            pub_key.as_any().downcast_ref::<dyn EcKey>().unwrap();
                        let pub_info = EcKeyInfo {
                            id: key_config.id,
                            label: key_config.label.clone(),
                            priv_pem: "".to_string(),
                            params_x962: ec_pub_key.params_x962(),
                            point_q_x962: ec_pub_key.point_q_x962(),
                        };
                        objects.push(Object::new_ec_public_key(pub_info));
                    }
                }
            }

            if let Some(x509_pem) = &key_config.cert_pem {
                if let Ok(certs) = backend.load_certificates(x509_pem) {
                    for (pos, cert) in certs.iter().enumerate() {
                        let (categ, id) = {
                            if pos == 0 {
                                (CertCategory::Token, key_config.id)
                            } else {
                                (CertCategory::Authority, key_config.id + pos as u8)
                            }
                        };
                        let x509_obj = CertInfo {
                            categ,
                            id,
                            label: format!("acm-ne-cert-{}", pos).to_string(),
                            subject_der: cert.subject(),
                            issuer_der: cert.issuer(),
                            serno_der: cert.serial_number(),
                            cert_der: cert.to_der(),
                        };
                        objects.push(Object::new_x509_cert(x509_obj));
                    }
                } else {
                    warn!("X509 certificate chain verification failed.");
                }
            }
        }

        Ok(Self {
            token_pin: token_config.pin.clone(),
            objects,
        })
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (ObjectHandle, &Object)> {
        self.objects
            .iter()
            .enumerate()
            .map(|(i, o)| (ObjectHandle::from(i), o))
    }

    pub fn object(&self, handle: ObjectHandle) -> Option<&Object> {
        if self.objects.len() <= usize::from(handle) {
            return None;
        }
        Some(&self.objects[usize::from(handle)])
    }

    pub fn token_pin(&self) -> &str {
        self.token_pin.as_str()
    }
}
