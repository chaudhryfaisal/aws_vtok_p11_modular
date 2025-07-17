//! Integration tests for the mock PKCS#11 provider.

use std::collections::HashMap;
use std::time::Duration;

use pkcs11_mock::provider::MockProvider;
use pkcs11_mock::data::MockConfig;
use pkcs11_mock::utils::{TestScenarios, MockDataFactory, testing};
use vtok_backend::traits::CryptoBackend;
use vtok_backend::types::{KeyAlgorithm, DigestAlgorithm, Mechanism};

#[tokio::test]
async fn test_provider_creation() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let info = provider.info();
    
    assert_eq!(info.name, "Mock PKCS#11 Provider");
    assert_eq!(info.version, "1.0.0");
    assert!(provider.is_thread_safe());
}

#[tokio::test]
async fn test_backend_mechanisms() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    let mechanisms = backend.supported_mechanisms();
    assert!(!mechanisms.is_empty());
    
    // Test specific mechanisms
    assert!(backend.supports_mechanism(&Mechanism::Digest(DigestAlgorithm::Sha256)));
    assert!(backend.supports_mechanism(&Mechanism::RsaPkcs1 { 
        digest: Some(DigestAlgorithm::Sha256) 
    }));
    assert!(backend.supports_mechanism(&Mechanism::Ecdsa { 
        digest: Some(DigestAlgorithm::Sha256) 
    }));
}

#[tokio::test]
async fn test_key_algorithms() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    let algorithms = backend.supported_key_algorithms();
    assert!(!algorithms.is_empty());
    
    // Test specific algorithms
    assert!(algorithms.contains(&KeyAlgorithm::Rsa2048));
    assert!(algorithms.contains(&KeyAlgorithm::EcdsaP256));
    assert!(algorithms.contains(&KeyAlgorithm::Aes256));
}

#[tokio::test]
async fn test_key_generation() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    // Test RSA key pair generation
    let rsa_keypair = backend.generate_keypair(KeyAlgorithm::Rsa2048, None)
        .await
        .expect("Failed to generate RSA key pair");
    
    assert_eq!(rsa_keypair.algorithm(), KeyAlgorithm::Rsa2048);
    assert_eq!(rsa_keypair.key_size(), 2048);
    assert!(rsa_keypair.private_key().can_sign());
    assert!(rsa_keypair.public_key().can_verify());
    
    // Test ECDSA key pair generation
    let ecdsa_keypair = backend.generate_keypair(KeyAlgorithm::EcdsaP256, None)
        .await
        .expect("Failed to generate ECDSA key pair");
    
    assert_eq!(ecdsa_keypair.algorithm(), KeyAlgorithm::EcdsaP256);
    assert_eq!(ecdsa_keypair.key_size(), 256);
    assert!(ecdsa_keypair.private_key().can_sign());
    assert!(ecdsa_keypair.public_key().can_verify());
    
    // Test symmetric key generation
    let symmetric_key = backend.generate_key(KeyAlgorithm::Aes256, None)
        .await
        .expect("Failed to generate symmetric key");
    
    assert_eq!(symmetric_key.algorithm(), KeyAlgorithm::Aes256);
    assert_eq!(symmetric_key.key_size(), 256);
    assert!(symmetric_key.can_encrypt());
    assert!(symmetric_key.can_decrypt());
}

#[tokio::test]
async fn test_digest_operations() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    let mut digest_ctx = backend.create_digest_context(DigestAlgorithm::Sha256, None)
        .await
        .expect("Failed to create digest context");
    
    let test_data = b"Hello, World!";
    digest_ctx.update(test_data).expect("Failed to update digest");
    
    let hash = digest_ctx.finalize().expect("Failed to finalize digest");
    assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
    
    // Test deterministic behavior
    let mut digest_ctx2 = backend.create_digest_context(DigestAlgorithm::Sha256, None)
        .await
        .expect("Failed to create second digest context");
    
    digest_ctx2.update(test_data).expect("Failed to update second digest");
    let hash2 = digest_ctx2.finalize().expect("Failed to finalize second digest");
    
    assert_eq!(hash, hash2, "Deterministic digest should produce same result");
}

#[tokio::test]
async fn test_sign_verify_operations() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    // Generate a key pair for signing
    let keypair = backend.generate_keypair(KeyAlgorithm::Rsa2048, None)
        .await
        .expect("Failed to generate key pair");
    
    let mechanism = Mechanism::RsaPkcs1 { digest: Some(DigestAlgorithm::Sha256) };
    let test_data = b"Sign this message";
    
    // Create sign context and sign data
    let sign_ctx = backend.create_sign_context(mechanism.clone(), keypair.private_key(), None)
        .await
        .expect("Failed to create sign context");
    
    let signature = sign_ctx.sign_oneshot(test_data)
        .expect("Failed to sign data");
    
    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 256); // RSA-2048 signature size
    
    // Create verify context and verify signature
    let verify_ctx = backend.create_verify_context(mechanism, keypair.public_key(), None)
        .await
        .expect("Failed to create verify context");
    
    let is_valid = verify_ctx.verify_oneshot(test_data, &signature)
        .expect("Failed to verify signature");
    
    assert!(is_valid, "Signature should be valid");
    
    // Test with wrong data
    let wrong_data = b"Wrong message";
    let is_invalid = verify_ctx.verify_oneshot(wrong_data, &signature)
        .expect("Failed to verify wrong signature");
    
    assert!(!is_invalid, "Signature should be invalid for wrong data");
}

#[tokio::test]
async fn test_encrypt_decrypt_operations() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    // Generate a symmetric key for encryption
    let key = backend.generate_key(KeyAlgorithm::Aes256, None)
        .await
        .expect("Failed to generate symmetric key");
    
    let mechanism = Mechanism::Digest(DigestAlgorithm::Sha256); // Simplified for mock
    let plaintext = b"Encrypt this message";
    
    // Create encrypt context and encrypt data
    let encrypt_ctx = backend.create_encrypt_context(mechanism.clone(), &key, None)
        .await
        .expect("Failed to create encrypt context");
    
    let ciphertext = encrypt_ctx.encrypt_oneshot(plaintext)
        .expect("Failed to encrypt data");
    
    assert!(!ciphertext.is_empty());
    assert_ne!(plaintext.to_vec(), ciphertext, "Ciphertext should differ from plaintext");
    
    // Create decrypt context and decrypt data
    let decrypt_ctx = backend.create_decrypt_context(mechanism, &key, None)
        .await
        .expect("Failed to create decrypt context");
    
    let decrypted = decrypt_ctx.decrypt_oneshot(&ciphertext)
        .expect("Failed to decrypt data");
    
    assert_eq!(plaintext.to_vec(), decrypted, "Decrypted data should match original");
}

#[tokio::test]
async fn test_random_generation() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    let random1 = backend.generate_random(32)
        .await
        .expect("Failed to generate random data");
    
    let random2 = backend.generate_random(32)
        .await
        .expect("Failed to generate second random data");
    
    assert_eq!(random1.len(), 32);
    assert_eq!(random2.len(), 32);
    
    // In deterministic mode, random data should be the same
    assert_eq!(random1, random2, "Deterministic random should be identical");
}

#[tokio::test]
async fn test_error_injection() {
    let provider = MockProvider::with_error_injection(vec![
        "generate_keypair".to_string(),
    ]).expect("Failed to create provider with error injection");
    
    let backend = provider.backend();
    
    // This should fail due to error injection
    let result = backend.generate_keypair(KeyAlgorithm::Rsa2048, None).await;
    assert!(result.is_err(), "Error injection should cause failure");
}

#[tokio::test]
async fn test_performance_simulation() {
    let mut delays = HashMap::new();
    delays.insert("generate_keypair".to_string(), Duration::from_millis(100));
    
    let provider = MockProvider::with_performance_simulation(delays)
        .expect("Failed to create provider with performance simulation");
    
    let backend = provider.backend();
    
    let start = std::time::Instant::now();
    let _keypair = backend.generate_keypair(KeyAlgorithm::Rsa2048, None)
        .await
        .expect("Failed to generate key pair");
    let duration = start.elapsed();
    
    // Should take at least 100ms due to simulated delay
    assert!(duration >= Duration::from_millis(90), "Performance simulation should add delay");
}

#[tokio::test]
async fn test_test_scenarios() {
    // Test basic deterministic scenario
    let config = TestScenarios::basic_deterministic();
    assert!(config.deterministic);
    assert!(config.error_injection.is_none());
    
    // Test error injection scenario
    let config = TestScenarios::error_injection();
    assert!(config.deterministic);
    assert!(config.error_injection.is_some());
    
    // Test performance testing scenario
    let config = TestScenarios::performance_testing();
    assert!(config.deterministic);
    assert!(config.performance_simulation.is_some());
}

#[tokio::test]
async fn test_mock_data_factory() {
    let factory = MockDataFactory::deterministic();
    
    // Test RSA test data generation
    let rsa_data = factory.rsa_test_data(2048);
    assert_eq!(rsa_data.key_size, 2048);
    assert!(!rsa_data.private_key.is_empty());
    assert!(!rsa_data.public_key.is_empty());
    assert!(!rsa_data.signature.is_empty());
    
    // Test ECDSA test data generation
    let ecdsa_data = factory.ecdsa_test_data("P-256");
    assert_eq!(ecdsa_data.curve, "P-256");
    assert!(!ecdsa_data.private_key.is_empty());
    assert!(!ecdsa_data.public_key.is_empty());
    assert!(!ecdsa_data.signature.is_empty());
    
    // Test symmetric test data generation
    let symmetric_data = factory.symmetric_test_data("AES-256");
    assert_eq!(symmetric_data.algorithm, "AES-256");
    assert_eq!(symmetric_data.key.len(), 32);
    assert!(!symmetric_data.plaintext.is_empty());
    assert!(!symmetric_data.ciphertext.is_empty());
    
    // Test certificate test data generation
    let cert_data = factory.certificate_test_data("CN=Test");
    assert_eq!(cert_data.subject, "CN=Test");
    assert!(!cert_data.der_data.is_empty());
    assert!(!cert_data.public_key.is_empty());
}

#[tokio::test]
async fn test_key_import_export() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    // Generate a key to export
    let original_key = backend.generate_key(KeyAlgorithm::Aes256, None)
        .await
        .expect("Failed to generate key");
    
    // Export the key
    let key_data = original_key.export_key()
        .expect("Failed to export key");
    
    assert_eq!(key_data.len(), 32); // AES-256 key size
    
    // Import the key back
    let imported_key = backend.import_key(
        vtok_backend::types::KeyType::Secret,
        KeyAlgorithm::Aes256,
        &key_data,
        None
    ).await.expect("Failed to import key");
    
    assert_eq!(imported_key.algorithm(), KeyAlgorithm::Aes256);
    assert_eq!(imported_key.key_size(), 256);
    
    // Verify the imported key data matches
    let imported_data = imported_key.export_key()
        .expect("Failed to export imported key");
    
    assert_eq!(key_data, imported_data, "Imported key should match original");
}

#[tokio::test]
async fn test_streaming_operations() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    // Test streaming digest
    let mut digest_ctx = backend.create_digest_context(DigestAlgorithm::Sha256, None)
        .await
        .expect("Failed to create digest context");
    
    let data1 = b"Hello, ";
    let data2 = b"World!";
    
    digest_ctx.update(data1).expect("Failed to update digest with data1");
    digest_ctx.update(data2).expect("Failed to update digest with data2");
    
    let hash = digest_ctx.finalize().expect("Failed to finalize digest");
    
    // Compare with one-shot digest
    let mut digest_ctx2 = backend.create_digest_context(DigestAlgorithm::Sha256, None)
        .await
        .expect("Failed to create second digest context");
    
    let combined_data = b"Hello, World!";
    digest_ctx2.update(combined_data).expect("Failed to update digest with combined data");
    let hash2 = digest_ctx2.finalize().expect("Failed to finalize second digest");
    
    assert_eq!(hash, hash2, "Streaming and one-shot digest should produce same result");
}

#[tokio::test]
async fn test_configuration_persistence() {
    let config = MockConfig::deterministic();
    let temp_file = "/tmp/test_config.json";
    
    // Save configuration
    config.to_file(temp_file).expect("Failed to save config");
    
    // Load configuration
    let loaded_config = MockConfig::from_file(temp_file)
        .expect("Failed to load config");
    
    assert_eq!(config.deterministic, loaded_config.deterministic);
    
    // Clean up
    std::fs::remove_file(temp_file).ok();
}

#[tokio::test]
async fn test_provider_capabilities() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let capabilities = provider.capabilities();
    
    assert!(!capabilities.hardware_keys);
    assert!(!capabilities.secure_storage);
    assert!(!capabilities.hardware_rng);
    assert!(!capabilities.side_channel_resistant);
    assert!(!capabilities.fips_compliant);
    assert!(capabilities.deterministic_mode);
    assert!(capabilities.error_injection);
    assert!(capabilities.performance_simulation);
}

#[tokio::test]
async fn test_concurrent_operations() {
    let provider = MockProvider::deterministic().expect("Failed to create provider");
    let backend = provider.backend();
    
    // Test concurrent key generation
    let mut handles = vec![];
    
    for _ in 0..10 {
        let backend_clone = backend.clone();
        let handle = tokio::spawn(async move {
            backend_clone.generate_keypair(KeyAlgorithm::Rsa2048, None).await
        });
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    for handle in handles {
        let result = handle.await.expect("Task panicked");
        assert!(result.is_ok(), "Concurrent key generation should succeed");
    }
}

#[test]
fn test_utility_functions() {
    // Test deterministic data generation
    let data1 = testing::generate_test_data(100, 42);
    let data2 = testing::generate_test_data(100, 42);
    
    assert_eq!(data1, data2, "Deterministic data should be identical");
    assert_eq!(data1.len(), 100);
    
    // Test byte comparison utility
    let bytes1 = vec![1, 2, 3, 4];
    let bytes2 = vec![1, 2, 3, 4];
    
    testing::assert_bytes_equal(&bytes1, &bytes2, "Test bytes should be equal");
}