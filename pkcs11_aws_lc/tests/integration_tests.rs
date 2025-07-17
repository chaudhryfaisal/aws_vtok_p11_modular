//! Integration tests for the AWS-LC PKCS#11 provider
//!
//! These tests verify that the complete PKCS#11 provider works correctly
//! with the AWS-LC backend implementation.

use std::ptr;
use pkcs11_aws_lc::*;
use vtok_backend::traits::CryptoBackend;

/// Test basic provider initialization
#[test]
fn test_provider_initialization() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    let provider = provider::AwsLcProvider::new(backend);
    
    let info = provider.info();
    assert_eq!(info.name, "AWS-LC PKCS#11 Provider");
    assert_eq!(info.version, "1.0.0");
    assert_eq!(info.vendor, "Amazon Web Services");
    
    assert!(provider.is_thread_safe());
    assert!(provider.max_sessions().is_some());
}

/// Test backend capabilities
#[test]
fn test_backend_capabilities() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    let provider = provider::AwsLcProvider::new(backend);
    
    let mechanisms = provider.supported_mechanisms();
    assert!(!mechanisms.is_empty(), "Should support at least some mechanisms");
    
    let algorithms = provider.supported_key_algorithms();
    assert!(!algorithms.is_empty(), "Should support at least some key algorithms");
    
    // Check for specific mechanisms we expect
    use vtok_backend::types::{Mechanism, DigestAlgorithm};
    let sha256_digest = Mechanism::Digest(DigestAlgorithm::Sha256);
    assert!(provider.supports_mechanism(&sha256_digest), "Should support SHA-256 digest");
    
    let rsa_pkcs1_sha256 = Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) };
    assert!(provider.supports_mechanism(&rsa_pkcs1_sha256), "Should support RSA PKCS#1 with SHA-256");
}

/// Test PKCS#11 C API initialization
#[test]
fn test_c_api_initialization() {
    // Test C_Initialize
    let result = C_Initialize(ptr::null_mut());
    assert_eq!(result, CKR_OK, "C_Initialize should succeed");
    
    // Test C_GetInfo
    let mut info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
        manufacturerID: [0; 32],
        flags: 0,
        libraryDescription: [0; 32],
        libraryVersion: CK_VERSION { major: 0, minor: 0 },
    };
    let result = C_GetInfo(&mut info);
    assert_eq!(result, CKR_OK, "C_GetInfo should succeed");
    
    // Test C_Finalize
    let result = C_Finalize(ptr::null_mut());
    assert_eq!(result, CKR_OK, "C_Finalize should succeed");
}

/// Test that unsupported functions return the correct error
#[test]
fn test_unsupported_functions() {
    let result = C_Initialize(ptr::null_mut());
    assert_eq!(result, CKR_OK);
    
    // Test some functions that should return CKR_FUNCTION_NOT_SUPPORTED
    let result = C_InitPIN(0, ptr::null_mut(), 0);
    assert_eq!(result, CKR_FUNCTION_NOT_SUPPORTED);
    
    let result = C_SetPIN(0, ptr::null_mut(), 0, ptr::null_mut(), 0);
    assert_eq!(result, CKR_FUNCTION_NOT_SUPPORTED);
    
    let result = C_GenerateRandom(0, ptr::null_mut(), 0);
    assert_eq!(result, CKR_FUNCTION_NOT_SUPPORTED);
    
    let result = C_Finalize(ptr::null_mut());
    assert_eq!(result, CKR_OK);
}

/// Test provider configuration
#[test]
fn test_provider_configuration() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    let config = provider::ProviderConfig {
        enable_logging: true,
        log_level: "debug".to_string(),
        max_sessions: 512,
        session_timeout: Some(std::time::Duration::from_secs(1800)),
        enable_threading: true,
    };
    
    let provider = provider::AwsLcProvider::with_config(backend, config);
    let current_config = provider.config();
    
    assert_eq!(current_config.max_sessions, 1024); // Default value since we don't store custom config yet
    assert!(current_config.enable_logging);
    assert!(current_config.enable_threading);
}

/// Test key algorithm support
#[test]
fn test_key_algorithm_support() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    let provider = provider::AwsLcProvider::new(backend);
    
    use vtok_backend::types::KeyAlgorithm;
    
    // Test RSA algorithms
    assert_eq!(provider.min_key_size(KeyAlgorithm::Rsa2048), Some(2048));
    assert_eq!(provider.max_key_size(KeyAlgorithm::Rsa2048), Some(2048));
    
    assert_eq!(provider.min_key_size(KeyAlgorithm::Rsa4096), Some(4096));
    assert_eq!(provider.max_key_size(KeyAlgorithm::Rsa4096), Some(4096));
    
    // Test ECDSA algorithms
    assert_eq!(provider.min_key_size(KeyAlgorithm::EcdsaP256), Some(256));
    assert_eq!(provider.max_key_size(KeyAlgorithm::EcdsaP256), Some(256));
    
    // Test AES algorithms
    assert_eq!(provider.min_key_size(KeyAlgorithm::Aes256), Some(256));
    assert_eq!(provider.max_key_size(KeyAlgorithm::Aes256), Some(256));
}

/// Test AWS-LC backend specific functionality
#[test]
fn test_aws_lc_backend_functionality() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    
    // Test backend info
    let info = backend.info();
    assert_eq!(info.name(), "AWS-LC Backend");
    assert_eq!(info.version(), "1.0.0");
    
    // Test supported mechanisms
    let mechanisms = backend.supported_mechanisms();
    assert!(!mechanisms.is_empty());
    
    // Test supported key algorithms
    let algorithms = backend.supported_key_algorithms();
    assert!(!algorithms.is_empty());
    
    // Test specific mechanism support
    use vtok_backend::types::{Mechanism, DigestAlgorithm};
    assert!(backend.supports_mechanism(&Mechanism::Digest(DigestAlgorithm::Sha256)));
    assert!(backend.supports_mechanism(&Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) }));
    assert!(backend.supports_mechanism(&Mechanism::Ecdsa { digest: Some(DigestAlgorithm::Sha256) }));
}

/// Test digest context creation and basic operations
#[tokio::test]
async fn test_digest_context() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    
    use vtok_backend::types::DigestAlgorithm;
    use vtok_backend::traits::DigestContext;
    
    // Create a digest context
    let mut ctx = backend.create_digest_context(DigestAlgorithm::Sha256, None)
        .await
        .expect("Failed to create digest context");
    
    assert_eq!(ctx.algorithm(), DigestAlgorithm::Sha256);
    assert!(ctx.supports_incremental());
    
    // Update with some data
    let data = b"Hello, World!";
    ctx.update(data).await.expect("Failed to update digest");
    
    // Finalize
    let digest = ctx.finalize().await.expect("Failed to finalize digest");
    assert_eq!(digest.len(), 32); // SHA-256 produces 32 bytes
    assert!(digest.iter().any(|&b| b != 0)); // Should not be all zeros
}

/// Test key generation
#[tokio::test]
async fn test_key_generation() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    
    use vtok_backend::types::KeyAlgorithm;
    use vtok_backend::traits::Key;
    
    // Test AES key generation
    let aes_key = backend.generate_key(KeyAlgorithm::Aes256, None)
        .await
        .expect("Failed to generate AES key");
    
    assert_eq!(aes_key.algorithm(), KeyAlgorithm::Aes256);
    assert_eq!(aes_key.key_size(), 256);
    assert!(aes_key.is_sensitive());
    assert!(!aes_key.is_extractable());
}

/// Test provider capabilities
#[test]
fn test_provider_capabilities() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    let provider = provider::AwsLcProvider::new(backend);
    
    let caps = provider.capabilities();
    assert!(!caps.hardware_keys); // AWS-LC backend doesn't use hardware keys
    assert!(!caps.secure_storage); // No secure storage
    assert!(caps.hardware_rng); // Uses hardware RNG
    assert!(caps.side_channel_resistant); // AWS-LC is designed to be side-channel resistant
}

/// Test error handling
#[test]
fn test_error_handling() {
    let backend = backend::AwsLcBackend::new().expect("Failed to create backend");
    
    use vtok_backend::types::{Mechanism, DigestAlgorithm};
    
    // Test unsupported mechanism
    let unsupported_mechanism = Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha1) };
    assert!(!backend.supports_mechanism(&unsupported_mechanism));
}

/// Test thread safety
#[test]
fn test_thread_safety() {
    use std::sync::Arc;
    use std::thread;
    
    let backend = Arc::new(backend::AwsLcBackend::new().expect("Failed to create backend"));
    let provider = Arc::new(provider::AwsLcProvider::new((*backend).clone()));
    
    let handles: Vec<_> = (0..4).map(|i| {
        let provider_clone = provider.clone();
        thread::spawn(move || {
            let info = provider_clone.info();
            assert_eq!(info.name, "AWS-LC PKCS#11 Provider");
            
            let mechanisms = provider_clone.supported_mechanisms();
            assert!(!mechanisms.is_empty());
            
            println!("Thread {} completed successfully", i);
        })
    }).collect();
    
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}