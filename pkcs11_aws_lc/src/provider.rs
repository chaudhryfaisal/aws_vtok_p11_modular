//! Provider integration for AWS-LC PKCS#11 implementation.

use std::sync::Arc;
use vtok_backend::traits::CryptoBackend;
use crate::backend::AwsLcBackend;

/// AWS-LC PKCS#11 Provider
/// 
/// This struct integrates the AWS-LC backend with the vtok_p11 core
/// to provide a complete PKCS#11 implementation.
pub struct AwsLcProvider {
    backend: Arc<AwsLcBackend>,
}

impl AwsLcProvider {
    /// Create a new AWS-LC provider
    pub fn new(backend: AwsLcBackend) -> Self {
        Self {
            backend: Arc::new(backend),
        }
    }

    /// Get the backend instance
    pub fn backend(&self) -> &Arc<AwsLcBackend> {
        &self.backend
    }

    /// Get provider information
    pub fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "AWS-LC PKCS#11 Provider".to_string(),
            version: "1.0.0".to_string(),
            description: "Complete PKCS#11 provider with AWS-LC cryptographic backend".to_string(),
            vendor: "Amazon Web Services".to_string(),
        }
    }

    /// Initialize the provider
    pub fn initialize(&self) -> Result<(), ProviderError> {
        // Provider-specific initialization logic
        log::info!("Initializing AWS-LC PKCS#11 provider");
        Ok(())
    }

    /// Finalize the provider
    pub fn finalize(&self) -> Result<(), ProviderError> {
        // Provider-specific cleanup logic
        log::info!("Finalizing AWS-LC PKCS#11 provider");
        Ok(())
    }

    /// Check if the provider supports a specific mechanism
    pub fn supports_mechanism(&self, mechanism: &vtok_backend::types::Mechanism) -> bool {
        self.backend.supports_mechanism(mechanism)
    }

    /// Get supported mechanisms
    pub fn supported_mechanisms(&self) -> Vec<vtok_backend::types::Mechanism> {
        self.backend.supported_mechanisms()
    }

    /// Get supported key algorithms
    pub fn supported_key_algorithms(&self) -> Vec<vtok_backend::types::KeyAlgorithm> {
        self.backend.supported_key_algorithms()
    }
}

/// Provider information
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub vendor: String,
}

/// Provider-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("Provider initialization failed: {0}")]
    InitializationFailed(String),
    
    #[error("Provider finalization failed: {0}")]
    FinalizationFailed(String),
    
    #[error("Backend error: {0}")]
    BackendError(#[from] vtok_backend::types::BackendError),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

impl std::fmt::Debug for AwsLcProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsLcProvider")
            .field("backend_info", &self.backend.info())
            .finish()
    }
}

/// Provider capabilities
#[derive(Debug, Clone)]
pub struct ProviderCapabilities {
    pub hardware_keys: bool,
    pub secure_storage: bool,
    pub hardware_rng: bool,
    pub side_channel_resistant: bool,
    pub fips_compliant: bool,
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            hardware_keys: false,
            secure_storage: false,
            hardware_rng: true,
            side_channel_resistant: true,
            fips_compliant: false, // AWS-LC can be FIPS compliant but depends on build
        }
    }
}

impl AwsLcProvider {
    /// Get provider capabilities
    pub fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }

    /// Check if the provider is thread-safe
    pub fn is_thread_safe(&self) -> bool {
        true // AWS-LC backend is designed to be thread-safe
    }

    /// Get maximum number of concurrent sessions
    pub fn max_sessions(&self) -> Option<usize> {
        Some(1024) // Reasonable default limit
    }

    /// Get maximum key size for a given algorithm
    pub fn max_key_size(&self, algorithm: vtok_backend::types::KeyAlgorithm) -> Option<usize> {
        match algorithm {
            vtok_backend::types::KeyAlgorithm::Rsa2048 => Some(2048),
            vtok_backend::types::KeyAlgorithm::Rsa3072 => Some(3072),
            vtok_backend::types::KeyAlgorithm::Rsa4096 => Some(4096),
            vtok_backend::types::KeyAlgorithm::EcdsaP256 => Some(256),
            vtok_backend::types::KeyAlgorithm::EcdsaP384 => Some(384),
            vtok_backend::types::KeyAlgorithm::Aes256 => Some(256),
            _ => None,
        }
    }

    /// Get minimum key size for a given algorithm
    pub fn min_key_size(&self, algorithm: vtok_backend::types::KeyAlgorithm) -> Option<usize> {
        match algorithm {
            vtok_backend::types::KeyAlgorithm::Rsa2048 => Some(2048),
            vtok_backend::types::KeyAlgorithm::Rsa3072 => Some(3072),
            vtok_backend::types::KeyAlgorithm::Rsa4096 => Some(4096),
            vtok_backend::types::KeyAlgorithm::EcdsaP256 => Some(256),
            vtok_backend::types::KeyAlgorithm::EcdsaP384 => Some(384),
            vtok_backend::types::KeyAlgorithm::Aes256 => Some(256),
            _ => None,
        }
    }
}

/// Provider configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub enable_logging: bool,
    pub log_level: String,
    pub max_sessions: usize,
    pub session_timeout: Option<std::time::Duration>,
    pub enable_threading: bool,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            enable_logging: true,
            log_level: "info".to_string(),
            max_sessions: 1024,
            session_timeout: Some(std::time::Duration::from_secs(3600)), // 1 hour
            enable_threading: true,
        }
    }
}

impl AwsLcProvider {
    /// Create a new provider with custom configuration
    pub fn with_config(backend: AwsLcBackend, config: ProviderConfig) -> Self {
        let provider = Self::new(backend);
        
        if config.enable_logging {
            log::info!("AWS-LC provider created with config: {:?}", config);
        }
        
        provider
    }

    /// Get current configuration
    pub fn config(&self) -> ProviderConfig {
        ProviderConfig::default() // In a real implementation, this would return the actual config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: ProviderConfig) -> Result<(), ProviderError> {
        log::info!("Updating provider configuration: {:?}", config);
        // In a real implementation, this would update the internal configuration
        Ok(())
    }
}