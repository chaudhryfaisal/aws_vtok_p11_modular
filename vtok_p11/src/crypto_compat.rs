//! Compatibility module for old crypto types
//! This provides placeholder implementations to get the code compiling
//! In a real implementation, these would be properly integrated with vtok_backend

#[derive(Clone, Copy, Debug)]
pub enum CertCategory {
    Unverified,
    Token,
    Authority,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub enum KeyAlgo {
    Rsa,
    Ec,
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    GeneralError,
    InvalidKey,
    InvalidCert,
}

pub struct Pkey {
    // Placeholder implementation
}

impl Pkey {
    pub fn from_private_pem(_pem: &str) -> Result<Self, Error> {
        Ok(Self {})
    }

    pub fn algo(&self) -> Result<KeyAlgo, Error> {
        Ok(KeyAlgo::Rsa) // Default to RSA for now
    }

    pub fn num_bits(&self) -> Result<u32, Error> {
        Ok(2048) // Default RSA size
    }

    pub fn rsa_modulus(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0u8; 256]) // Placeholder modulus
    }

    pub fn rsa_public_exponent(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0x01, 0x00, 0x01]) // Standard RSA exponent 65537
    }

    pub fn ec_params_x962(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0u8; 32]) // Placeholder EC params
    }

    pub fn ec_point_q_x962(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0u8; 65]) // Placeholder EC point
    }
}

pub struct X509 {
    // Placeholder implementation
}

impl X509 {
    pub fn subject_name(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0u8; 32]) // Placeholder subject
    }

    pub fn issuer(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0u8; 32]) // Placeholder issuer
    }

    pub fn serial_no(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0u8; 16]) // Placeholder serial number
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0u8; 256]) // Placeholder DER encoding
    }
}

pub struct X509Chain {
    certs: Vec<X509>,
}

impl X509Chain {
    pub fn chain_from_pem(_pem: &str) -> Result<Self, Error> {
        Ok(Self {
            certs: vec![X509 {}],
        })
    }

    pub fn multiple_certs(&self) -> bool {
        self.certs.len() > 1
    }

    pub fn verify_chain(&self) -> Result<(), Error> {
        Ok(()) // Placeholder verification
    }

    pub fn verify(&self, _pkey: Pkey) -> Result<(), Error> {
        Ok(()) // Placeholder verification
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (usize, &X509)> {
        self.certs.iter().enumerate()
    }
}