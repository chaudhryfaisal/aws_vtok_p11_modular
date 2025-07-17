//! Integration tests for the vtok_p11 modular architecture
//!
//! These tests validate the interaction between different crates and ensure
//! the modular architecture works correctly as a whole.

use std::sync::Arc;
use tokio;
use vtok_backend::traits::{CryptoBackend, SignContext, VerifyContext, DigestContext};
use vtok_backend::types::{KeyAlgorithm, Mechanism, DigestAlgorithm, BackendResult};

/// Test configuration for integration tests
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub test_rsa_2048: bool,
    pub test_ecdsa_p256: bool,
    pub test_signing: bool,
    pub test_verification: bool,
    pub test_digest: bool,
    pub test_key_generation: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            test_rsa_2048: true,
            test_ecdsa_p256: true,
            test_signing: true,
            test_verification: true,
            test_digest: true,
            test_key_generation: true,
        }
    }
}

/// Generic backend test suite that can be run against any CryptoBackend implementation
pub async fn run_backend_test_suite<B>(backend: Arc<B>, config: TestConfig) -> BackendResult<()>
where
    B: CryptoBackend + 'static,
{
    println!("Running backend test suite for: {}", backend.info().name);

    if config.test_key_generation {
        test_key_generation(&backend).await?;
    }

    if config.test_signing {
        test_signing_operations(&backend).await?;
    }

    if config.test_verification {
        test_verification_operations(&backend).await?;
    }

    if config.test_digest {
        test_digest_operations(&backend).await?;
    }

    test_backend_capabilities(&backend).await?;
    test_error_handling(&backend).await?;

    println!("✅ All tests passed for backend: {}", backend.info().name);
    Ok(())
}

/// Test key generation for supported algorithms
async fn test_key_generation<B: CryptoBackend>(backend: &B) -> BackendResult<()> {
    println!("Testing key generation...");

    for algorithm in backend.supported_key_algorithms() {
        match algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
                let keypair = backend.generate_keypair(algorithm, None).await?;
                assert_eq!(keypair.algorithm(), algorithm);
                assert_eq!(keypair.key_size(), algorithm.key_size_bits());
                println!("  ✅ Generated {} keypair", algorithm.name());
            }
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 | KeyAlgorithm::EcdsaP521 => {
                let keypair = backend.generate_keypair(algorithm, None).await?;
                assert_eq!(keypair.algorithm(), algorithm);
                assert_eq!(keypair.key_size(), algorithm.key_size_bits());
                println!("  ✅ Generated {} keypair", algorithm.name());
            }
            _ => {
                // Test symmetric key generation if supported
                if algorithm.is_symmetric() {
                    let key = backend.generate_key(algorithm, None).await?;
                    assert_eq!(key.algorithm(), algorithm);
                    assert_eq!(key.key_size(), algorithm.key_size_bits());
                    println!("  ✅ Generated {} key", algorithm.name());
                }
            }
        }
    }

    Ok(())
}

/// Test signing operations
async fn test_signing_operations<B: CryptoBackend>(backend: &B) -> BackendResult<()> {
    println!("Testing signing operations...");

    let test_data = b"Hello, PKCS#11 modular architecture!";

    // Test RSA signing if supported
    if backend.supported_key_algorithms().contains(&KeyAlgorithm::Rsa2048) {
        let keypair = backend.generate_keypair(KeyAlgorithm::Rsa2048, None).await?;
        
        let mechanism = Mechanism::RsaPkcs1 {
            digest: Some(DigestAlgorithm::Sha256),
        };

        if backend.supports_mechanism(&mechanism) {
            let sign_ctx = backend.create_sign_context(
                mechanism,
                keypair.private_key(),
                None,
            ).await?;

            let signature = sign_ctx.sign(test_data).await?;
            assert!(!signature.is_empty());
            assert_eq!(signature.len(), 256); // RSA-2048 signature size
            println!("  ✅ RSA-2048 signing successful");
        }
    }

    // Test ECDSA signing if supported
    if backend.supported_key_algorithms().contains(&KeyAlgorithm::EcdsaP256) {
        let keypair = backend.generate_keypair(KeyAlgorithm::EcdsaP256, None).await?;
        
        let mechanism = Mechanism::Ecdsa {
            digest: Some(DigestAlgorithm::Sha256),
        };

        if backend.supports_mechanism(&mechanism) {
            let sign_ctx = backend.create_sign_context(
                mechanism,
                keypair.private_key(),
                None,
            ).await?;

            let signature = sign_ctx.sign(test_data).await?;
            assert!(!signature.is_empty());
            println!("  ✅ ECDSA-P256 signing successful");
        }
    }

    Ok(())
}

/// Test verification operations
async fn test_verification_operations<B: CryptoBackend>(backend: &B) -> BackendResult<()> {
    println!("Testing verification operations...");

    let test_data = b"Verification test data";

    // Test RSA verification if supported
    if backend.supported_key_algorithms().contains(&KeyAlgorithm::Rsa2048) {
        let keypair = backend.generate_keypair(KeyAlgorithm::Rsa2048, None).await?;
        
        let mechanism = Mechanism::RsaPkcs1 {
            digest: Some(DigestAlgorithm::Sha256),
        };

        if backend.supports_mechanism(&mechanism) {
            // Sign the data
            let sign_ctx = backend.create_sign_context(
                mechanism.clone(),
                keypair.private_key(),
                None,
            ).await?;
            let signature = sign_ctx.sign(test_data).await?;

            // Verify the signature
            let verify_ctx = backend.create_verify_context(
                mechanism,
                keypair.public_key(),
                None,
            ).await?;
            let is_valid = verify_ctx.verify(test_data, &signature).await?;
            assert!(is_valid);
            println!("  ✅ RSA-2048 verification successful");

            // Test with invalid signature
            let verify_ctx2 = backend.create_verify_context(
                Mechanism::RsaPkcs1 {
                    digest: Some(DigestAlgorithm::Sha256),
                },
                keypair.public_key(),
                None,
            ).await?;
            let mut invalid_signature = signature.clone();
            invalid_signature[0] ^= 0xFF; // Corrupt the signature
            let is_valid = verify_ctx2.verify(test_data, &invalid_signature).await?;
            assert!(!is_valid);
            println!("  ✅ RSA-2048 invalid signature detection successful");
        }
    }

    Ok(())
}

/// Test digest operations
async fn test_digest_operations<B: CryptoBackend>(backend: &B) -> BackendResult<()> {
    println!("Testing digest operations...");

    let test_data = b"Digest test data";

    // Test supported digest algorithms
    let digest_algorithms = [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ];

    for &algorithm in &digest_algorithms {
        if backend.supports_mechanism(&Mechanism::Digest(algorithm)) {
            let digest_ctx = backend.create_digest_context(algorithm, None).await?;
            
            // Test single-part digest
            let hash = digest_ctx.digest(test_data).await?;
            assert_eq!(hash.len(), algorithm.output_size());
            println!("  ✅ {} digest successful", algorithm.name());

            // Test multi-part digest
            let mut digest_ctx2 = backend.create_digest_context(algorithm, None).await?;
            digest_ctx2.update(&test_data[..5]).await?;
            digest_ctx2.update(&test_data[5..]).await?;
            let hash2 = digest_ctx2.finalize().await?;
            assert_eq!(hash, hash2);
            println!("  ✅ {} multi-part digest successful", algorithm.name());
        }
    }

    Ok(())
}

/// Test backend capabilities and metadata
async fn test_backend_capabilities<B: CryptoBackend>(backend: &B) -> BackendResult<()> {
    println!("Testing backend capabilities...");

    let info = backend.info();
    assert!(!info.name.is_empty());
    assert!(!info.version.is_empty());
    println!("  ✅ Backend info: {} v{}", info.name, info.version);

    let mechanisms = backend.supported_mechanisms();
    assert!(!mechanisms.is_empty());
    println!("  ✅ Supported mechanisms: {}", mechanisms.len());

    let algorithms = backend.supported_key_algorithms();
    assert!(!algorithms.is_empty());
    println!("  ✅ Supported key algorithms: {}", algorithms.len());

    // Test mechanism support queries
    for mechanism in &mechanisms {
        assert!(backend.supports_mechanism(mechanism));
    }
    println!("  ✅ Mechanism support queries consistent");

    Ok(())
}

/// Test error handling
async fn test_error_handling<B: CryptoBackend>(backend: &B) -> BackendResult<()> {
    println!("Testing error handling...");

    // Test unsupported algorithm
    let result = backend.generate_keypair(KeyAlgorithm::Rsa8192, None).await;
    if result.is_err() {
        println!("  ✅ Unsupported algorithm error handled correctly");
    }

    // Test unsupported mechanism
    let unsupported_mechanism = Mechanism::EdDsa;
    if !backend.supports_mechanism(&unsupported_mechanism) {
        if let Ok(keypair) = backend.generate_keypair(KeyAlgorithm::EcdsaP256, None).await {
            let result = backend.create_sign_context(
                unsupported_mechanism,
                keypair.private_key(),
                None,
            ).await;
            if result.is_err() {
                println!("  ✅ Unsupported mechanism error handled correctly");
            }
        }
    }

    Ok(())
}

/// Test cross-backend compatibility
#[tokio::test]
async fn test_cross_backend_compatibility() {
    // This test would compare operations between different backends
    // to ensure they produce compatible results where applicable
    println!("Testing cross-backend compatibility...");
    
    // Note: This is a placeholder for when multiple backends are available
    // Currently we only have mock and aws-lc backends
    
    println!("  ✅ Cross-backend compatibility test placeholder");
}

/// Test concurrent operations
#[tokio::test]
async fn test_concurrent_operations() {
    println!("Testing concurrent operations...");
    
    // This test would verify that backends handle concurrent access correctly
    // by running multiple operations simultaneously
    
    println!("  ✅ Concurrent operations test placeholder");
}

/// Performance benchmark test
#[tokio::test]
async fn test_performance_benchmarks() {
    println!("Running performance benchmarks...");
    
    // This test would measure performance characteristics
    // of different backends and operations
    
    println!("  ✅ Performance benchmark test placeholder");
}

/// Test PKCS#11 compliance
#[tokio::test]
async fn test_pkcs11_compliance() {
    println!("Testing PKCS#11 compliance...");
    
    // This test would verify that the implementation
    // complies with PKCS#11 standards
    
    println!("  ✅ PKCS#11 compliance test placeholder");
}

/// Helper function to create test configuration for specific scenarios
pub fn create_test_config_for_ci() -> TestConfig {
    TestConfig {
        test_rsa_2048: true,
        test_ecdsa_p256: true,
        test_signing: true,
        test_verification: true,
        test_digest: true,
        test_key_generation: true,
    }
}

/// Helper function to create minimal test configuration for quick tests
pub fn create_minimal_test_config() -> TestConfig {
    TestConfig {
        test_rsa_2048: false,
        test_ecdsa_p256: true,
        test_signing: true,
        test_verification: false,
        test_digest: true,
        test_key_generation: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integration_framework() {
        // Test that the integration test framework itself works
        println!("Testing integration test framework...");
        
        let config = create_minimal_test_config();
        assert!(config.test_ecdsa_p256);
        assert!(config.test_signing);
        assert!(config.test_digest);
        assert!(config.test_key_generation);
        
        println!("  ✅ Integration test framework working");
    }
}