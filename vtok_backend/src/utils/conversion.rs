//! Type conversion utilities between PKCS#11 and backend types.
//!
//! This module provides functions to convert between PKCS#11 types
//! and the backend abstraction types, enabling seamless integration
//! between the PKCS#11 layer and crypto backends.

use crate::types::{
    KeyAlgorithm, KeyType, Mechanism, DigestAlgorithm, 
    mechanism::{AesMode, KdfAlgorithm},
    BackendError, BackendResult,
};

/// Convert PKCS#11 key type to backend KeyType
pub fn pkcs11_key_type_to_backend(ck_key_type: u32) -> BackendResult<KeyType> {
    match ck_key_type {
        0x00000000 => Ok(KeyType::Public),  // CKK_RSA, CKK_EC (public)
        0x00000001 => Ok(KeyType::Private), // CKK_RSA, CKK_EC (private)
        0x00000010 => Ok(KeyType::Secret),  // CKK_GENERIC_SECRET
        0x00000020 => Ok(KeyType::Secret),  // CKK_AES
        _ => Err(BackendError::UnsupportedAlgorithm(format!(
            "Unsupported PKCS#11 key type: 0x{:08X}",
            ck_key_type
        ))),
    }
}

/// Convert backend KeyType to PKCS#11 key type
pub fn backend_key_type_to_pkcs11(key_type: KeyType, algorithm: KeyAlgorithm) -> u32 {
    match (key_type, algorithm) {
        (KeyType::Public, alg) if alg.is_rsa() => 0x00000000,  // CKK_RSA
        (KeyType::Private, alg) if alg.is_rsa() => 0x00000000, // CKK_RSA
        (KeyType::Public, alg) if alg.is_ecdsa() => 0x00000003, // CKK_EC
        (KeyType::Private, alg) if alg.is_ecdsa() => 0x00000003, // CKK_EC
        (KeyType::Secret, alg) if alg.is_symmetric() => match alg {
            KeyAlgorithm::Aes128 | KeyAlgorithm::Aes192 | KeyAlgorithm::Aes256 => 0x0000001F, // CKK_AES
            KeyAlgorithm::ChaCha20 => 0x00000010, // CKK_GENERIC_SECRET
            _ => 0x00000010, // CKK_GENERIC_SECRET
        },
        _ => 0x00000010, // CKK_GENERIC_SECRET (fallback)
    }
}

/// Convert PKCS#11 mechanism type to backend Mechanism
pub fn pkcs11_mechanism_to_backend(ck_mechanism: u32, params: Option<&[u8]>) -> BackendResult<Mechanism> {
    match ck_mechanism {
        // Digest mechanisms
        0x00000220 => Ok(Mechanism::Digest(DigestAlgorithm::Sha1)),
        0x00000255 => Ok(Mechanism::Digest(DigestAlgorithm::Sha224)),
        0x00000250 => Ok(Mechanism::Digest(DigestAlgorithm::Sha256)),
        0x00000260 => Ok(Mechanism::Digest(DigestAlgorithm::Sha384)),
        0x00000270 => Ok(Mechanism::Digest(DigestAlgorithm::Sha512)),
        
        // RSA mechanisms
        0x00000001 => Ok(Mechanism::RsaPkcs1 { digest: None }),
        0x00000006 => Ok(Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha1) }),
        0x00000040 => Ok(Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha224) }),
        0x00000041 => Ok(Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) }),
        0x00000042 => Ok(Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha384) }),
        0x00000043 => Ok(Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha512) }),
        
        // RSA PSS mechanisms
        0x0000000D => {
            // Parse PSS parameters if provided
            Ok(Mechanism::RsaPkcs1Pss {
                digest: DigestAlgorithm::Sha256, // Default
                mgf: DigestAlgorithm::Sha256,
                salt_len: 32,
            })
        }
        
        // RSA OAEP mechanisms
        0x00000009 => {
            Ok(Mechanism::RsaOaep {
                hash: DigestAlgorithm::Sha256, // Default
                mgf: DigestAlgorithm::Sha256,
                label: None,
            })
        }
        
        // Raw RSA
        0x00000003 => Ok(Mechanism::RsaX509),
        
        // ECDSA mechanisms
        0x00001041 => Ok(Mechanism::Ecdsa { digest: None }),
        0x00001042 => Ok(Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha1) }),
        0x00001043 => Ok(Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha224) }),
        0x00001044 => Ok(Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) }),
        0x00001045 => Ok(Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha384) }),
        0x00001046 => Ok(Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha512) }),
        
        // AES mechanisms
        0x00001080 => Ok(Mechanism::Aes { mode: AesMode::Ecb, key_size: 128 }),
        0x00001081 => Ok(Mechanism::Aes { mode: AesMode::Cbc, key_size: 128 }),
        0x00001082 => Ok(Mechanism::Aes { mode: AesMode::Ctr, key_size: 128 }),
        0x00001087 => Ok(Mechanism::Aes { mode: AesMode::Gcm, key_size: 128 }),
        
        // HMAC mechanisms
        0x00000221 => Ok(Mechanism::Hmac { hash: DigestAlgorithm::Sha1 }),
        0x00000256 => Ok(Mechanism::Hmac { hash: DigestAlgorithm::Sha224 }),
        0x00000251 => Ok(Mechanism::Hmac { hash: DigestAlgorithm::Sha256 }),
        0x00000261 => Ok(Mechanism::Hmac { hash: DigestAlgorithm::Sha384 }),
        0x00000271 => Ok(Mechanism::Hmac { hash: DigestAlgorithm::Sha512 }),
        
        _ => Err(BackendError::UnsupportedMechanism(format!(
            "Unsupported PKCS#11 mechanism: 0x{:08X}",
            ck_mechanism
        ))),
    }
}

/// Convert backend Mechanism to PKCS#11 mechanism type
pub fn backend_mechanism_to_pkcs11(mechanism: &Mechanism) -> u32 {
    match mechanism {
        // Digest mechanisms
        Mechanism::Digest(DigestAlgorithm::Sha1) => 0x00000220,
        Mechanism::Digest(DigestAlgorithm::Sha224) => 0x00000255,
        Mechanism::Digest(DigestAlgorithm::Sha256) => 0x00000250,
        Mechanism::Digest(DigestAlgorithm::Sha384) => 0x00000260,
        Mechanism::Digest(DigestAlgorithm::Sha512) => 0x00000270,
        
        // RSA mechanisms
        Mechanism::RsaPkcs1 { digest: None } => 0x00000001,
        Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha1) } => 0x00000006,
        Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha224) } => 0x00000040,
        Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) } => 0x00000041,
        Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha384) } => 0x00000042,
        Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha512) } => 0x00000043,
        
        // RSA PSS mechanisms
        Mechanism::RsaPkcs1Pss { .. } => 0x0000000D,
        
        // RSA OAEP mechanisms
        Mechanism::RsaOaep { .. } => 0x00000009,
        
        // Raw RSA
        Mechanism::RsaX509 => 0x00000003,
        
        // ECDSA mechanisms
        Mechanism::Ecdsa { digest: None } => 0x00001041,
        Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha1) } => 0x00001042,
        Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha224) } => 0x00001043,
        Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) } => 0x00001044,
        Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha384) } => 0x00001045,
        Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha512) } => 0x00001046,
        
        // EdDSA
        Mechanism::EdDsa => 0x00001057, // CKM_EDDSA
        
        // AES mechanisms
        Mechanism::Aes { mode: AesMode::Ecb, .. } => 0x00001080,
        Mechanism::Aes { mode: AesMode::Cbc, .. } => 0x00001081,
        Mechanism::Aes { mode: AesMode::Ctr, .. } => 0x00001082,
        Mechanism::Aes { mode: AesMode::Gcm, .. } => 0x00001087,
        Mechanism::Aes { mode: AesMode::Ccm, .. } => 0x00001088,
        
        // ChaCha20
        Mechanism::ChaCha20 => 0x00004004, // Vendor-specific
        Mechanism::ChaCha20Poly1305 => 0x00004005, // Vendor-specific
        
        // HMAC mechanisms
        Mechanism::Hmac { hash: DigestAlgorithm::Sha1 } => 0x00000221,
        Mechanism::Hmac { hash: DigestAlgorithm::Sha224 } => 0x00000256,
        Mechanism::Hmac { hash: DigestAlgorithm::Sha256 } => 0x00000251,
        Mechanism::Hmac { hash: DigestAlgorithm::Sha384 } => 0x00000261,
        Mechanism::Hmac { hash: DigestAlgorithm::Sha512 } => 0x00000271,
        
        // Key derivation
        Mechanism::Kdf { .. } => 0x00000390, // CKM_PKCS5_PBKD2
        
        // Key agreement
        Mechanism::Ecdh => 0x00001050, // CKM_ECDH1_DERIVE
        Mechanism::X25519 => 0x00004006, // Vendor-specific
        
        _ => 0x80000000, // CKM_VENDOR_DEFINED
    }
}

/// Convert PKCS#11 key size to backend KeyAlgorithm
pub fn pkcs11_key_size_to_algorithm(key_type: u32, key_size_bits: usize) -> BackendResult<KeyAlgorithm> {
    match key_type {
        0x00000000 => { // CKK_RSA
            match key_size_bits {
                1024 => Ok(KeyAlgorithm::Rsa1024),
                2048 => Ok(KeyAlgorithm::Rsa2048),
                3072 => Ok(KeyAlgorithm::Rsa3072),
                4096 => Ok(KeyAlgorithm::Rsa4096),
                8192 => Ok(KeyAlgorithm::Rsa8192),
                _ => Err(BackendError::UnsupportedAlgorithm(format!(
                    "Unsupported RSA key size: {} bits",
                    key_size_bits
                ))),
            }
        }
        0x00000003 => { // CKK_EC
            match key_size_bits {
                224 => Ok(KeyAlgorithm::EcdsaP224),
                256 => Ok(KeyAlgorithm::EcdsaP256),
                384 => Ok(KeyAlgorithm::EcdsaP384),
                521 => Ok(KeyAlgorithm::EcdsaP521),
                _ => Err(BackendError::UnsupportedAlgorithm(format!(
                    "Unsupported EC key size: {} bits",
                    key_size_bits
                ))),
            }
        }
        0x0000001F => { // CKK_AES
            match key_size_bits {
                128 => Ok(KeyAlgorithm::Aes128),
                192 => Ok(KeyAlgorithm::Aes192),
                256 => Ok(KeyAlgorithm::Aes256),
                _ => Err(BackendError::UnsupportedAlgorithm(format!(
                    "Unsupported AES key size: {} bits",
                    key_size_bits
                ))),
            }
        }
        0x00000010 => { // CKK_GENERIC_SECRET
            match key_size_bits {
                256 => Ok(KeyAlgorithm::ChaCha20),
                _ => Err(BackendError::UnsupportedAlgorithm(format!(
                    "Unsupported generic secret key size: {} bits",
                    key_size_bits
                ))),
            }
        }
        _ => Err(BackendError::UnsupportedAlgorithm(format!(
            "Unsupported PKCS#11 key type: 0x{:08X}",
            key_type
        ))),
    }
}

/// Convert backend error to PKCS#11 return value
pub fn backend_error_to_pkcs11(error: &BackendError) -> u32 {
    match error {
        BackendError::General(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::UnsupportedAlgorithm(_) => 0x00000070, // CKR_MECHANISM_INVALID
        BackendError::UnsupportedMechanism(_) => 0x00000070, // CKR_MECHANISM_INVALID
        BackendError::UnsupportedOperation(_) => 0x00000054, // CKR_FUNCTION_NOT_SUPPORTED
        BackendError::KeyGeneration(_) => 0x00000062, // CKR_KEY_FUNCTION_NOT_PERMITTED
        BackendError::KeyDerivation(_) => 0x00000062, // CKR_KEY_FUNCTION_NOT_PERMITTED
        BackendError::InvalidKeyData(_) => 0x00000068, // CKR_KEY_SIZE_RANGE
        BackendError::InvalidKey(_) => 0x00000060, // CKR_KEY_HANDLE_INVALID
        BackendError::KeyNotExtractable => 0x00000069, // CKR_KEY_NOT_WRAPPABLE
        BackendError::KeySensitive => 0x0000006A, // CKR_KEY_UNEXTRACTABLE
        BackendError::InvalidCertificate(_) => 0x00000090, // CKR_ATTRIBUTE_VALUE_INVALID
        BackendError::DigestOperation(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::DigestUpdate(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::DigestFinalize(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::SignOperation(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::VerifyOperation(_) => 0x000000C0, // CKR_SIGNATURE_INVALID
        BackendError::EncryptOperation(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::DecryptOperation(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::RandomGeneration(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::ContextFinalized => 0x00000063, // CKR_OPERATION_NOT_INITIALIZED
        BackendError::OperationActive => 0x00000090, // CKR_OPERATION_ACTIVE
        BackendError::InvalidState(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::InvalidParameters(_) => 0x00000007, // CKR_ARGUMENTS_BAD
        BackendError::BufferTooSmall { .. } => 0x00000150, // CKR_BUFFER_TOO_SMALL
        BackendError::InvalidDataLength(_) => 0x00000020, // CKR_DATA_LEN_RANGE
        BackendError::ReadOnlyAttribute(_) => 0x00000012, // CKR_ATTRIBUTE_READ_ONLY
        BackendError::InitializationFailed(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::NotInitialized => 0x00000006, // CKR_CRYPTOKI_NOT_INITIALIZED
        BackendError::HardwareError(_) => 0x00000030, // CKR_DEVICE_ERROR
        BackendError::IoError(_) => 0x00000030, // CKR_DEVICE_ERROR
        BackendError::Timeout => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::OutOfMemory => 0x00000002, // CKR_HOST_MEMORY
        BackendError::Internal(_) => 0x00000005, // CKR_GENERAL_ERROR
        BackendError::MockError(_) => 0x00000005, // CKR_GENERAL_ERROR
    }
}

/// Convert bytes to hexadecimal string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert hexadecimal string to bytes
pub fn hex_to_bytes(hex: &str) -> BackendResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(BackendError::InvalidParameters(
            "Hex string must have even length".to_string()
        ));
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hex_byte = std::str::from_utf8(chunk)
            .map_err(|_| BackendError::InvalidParameters("Invalid hex string".to_string()))?;
        let byte = u8::from_str_radix(hex_byte, 16)
            .map_err(|_| BackendError::InvalidParameters("Invalid hex character".to_string()))?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Constant-time comparison of byte slices
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

/// Secure zero memory
pub fn secure_zero(data: &mut [u8]) {
    // Use volatile write to prevent compiler optimization
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

/// Pad data to block size using PKCS#7 padding
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + padding_len);
    padded.extend_from_slice(data);
    padded.resize(data.len() + padding_len, padding_len as u8);
    padded
}

/// Remove PKCS#7 padding from data
pub fn pkcs7_unpad(data: &[u8]) -> BackendResult<Vec<u8>> {
    if data.is_empty() {
        return Err(BackendError::InvalidDataLength("Empty data".to_string()));
    }
    
    let padding_len = *data.last().unwrap() as usize;
    if padding_len == 0 || padding_len > data.len() {
        return Err(BackendError::InvalidDataLength("Invalid padding".to_string()));
    }
    
    // Verify padding
    for &byte in &data[data.len() - padding_len..] {
        if byte != padding_len as u8 {
            return Err(BackendError::InvalidDataLength("Invalid padding".to_string()));
        }
    }
    
    Ok(data[..data.len() - padding_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "0123456789abcdef");
        
        let converted_back = hex_to_bytes(&hex).unwrap();
        assert_eq!(bytes, converted_back);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];
        
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3]));
    }

    #[test]
    fn test_pkcs7_padding() {
        let data = vec![1, 2, 3, 4, 5];
        let padded = pkcs7_pad(&data, 8);
        assert_eq!(padded, vec![1, 2, 3, 4, 5, 3, 3, 3]);
        
        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }
}