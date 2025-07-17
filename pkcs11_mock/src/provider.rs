//! Provider integration for Mock PKCS#11 implementation.

use std::sync::Arc;
use vtok_backend::traits::CryptoBackend;
use crate::backend::MockBackend;
use crate::data::MockConfig;

/// Mock PKCS#11 Provider
/// 
/// This struct integrates the mock backend with the vtok_p11 core
/// to provide a complete PKCS#11 implementation for testing.
pub struct MockProvider {
    backend: Arc<MockBackend>,
}

impl MockProvider {
    /// Create a new mock provider
    pub fn new(backend: MockBackend) -> Self {
        Self {
            backend: Arc::new(backend),
        }
    }

    /// Create a new mock provider with custom configuration
    pub fn with_config(config: MockConfig) -> Result<Self, ProviderError> {
        let backend = MockBackend::with_config(config)
            .map_err(|e| ProviderError::BackendError(e))?;
        Ok(Self::new(backend))
    }

    /// Get the backend instance
    pub fn backend(&self) -> &Arc<MockBackend> {
        &self.backend
    }

    /// Get provider information
    pub fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "Mock PKCS#11 Provider".to_string(),
            version: "1.0.0".to_string(),
            description: "Complete PKCS#11 provider with mock cryptographic backend for testing".to_string(),
            vendor: "Mock Crypto Inc.".to_string(),
        }
    }

    /// Initialize the provider
    pub fn initialize(&self) -> Result<(), ProviderError> {
        // Provider-specific initialization logic
        log::info!("Initializing Mock PKCS#11 provider");
        Ok(())
    }

    /// Finalize the provider
    pub fn finalize(&self) -> Result<(), ProviderError> {
        // Provider-specific cleanup logic
        log::info!("Finalizing Mock PKCS#11 provider");
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

    /// Update the mock configuration
    pub fn update_config(&self, config: MockConfig) -> Result<(), ProviderError> {
        // In a real implementation, this would update the backend configuration
        // For now, we'll just log the update
        log::info!("Mock provider configuration update requested");
        Ok(())
    }

    /// Enable error injection for testing
    pub fn enable_error_injection(&self, operations: Vec<String>) -> Result<(), ProviderError> {
        log::info!("Enabling error injection for operations: {:?}", operations);
        // In a real implementation, this would update the backend's error injection config
        Ok(())
    }

    /// Disable error injection
    pub fn disable_error_injection(&self) -> Result<(), ProviderError> {
        log::info!("Disabling error injection");
        // In a real implementation, this would disable error injection in the backend
        Ok(())
    }

    /// Set deterministic mode
    pub fn set_deterministic_mode(&self, enabled: bool) -> Result<(), ProviderError> {
        log::info!("Setting deterministic mode: {}", enabled);
        // In a real implementation, this would update the backend's deterministic setting
        Ok(())
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

    #[error("Mock error: {0}")]
    MockError(String),
}

impl std::fmt::Debug for MockProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockProvider")
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
    pub deterministic_mode: bool,
    pub error_injection: bool,
    pub performance_simulation: bool,
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            hardware_keys: false,
            secure_storage: false,
            hardware_rng: false,
            side_channel_resistant: false,
            fips_compliant: false,
            deterministic_mode: true,
            error_injection: true,
            performance_simulation: true,
        }
    }
}

impl MockProvider {
    /// Get provider capabilities
    pub fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }

    /// Check if the provider is thread-safe
    pub fn is_thread_safe(&self) -> bool {
        true // Mock backend is designed to be thread-safe
    }

    /// Get maximum number of concurrent sessions
    pub fn max_sessions(&self) -> Option<usize> {
        Some(1024) // Reasonable default limit for testing
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

/// Provider configuration for testing scenarios
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub enable_logging: bool,
    pub log_level: String,
    pub max_sessions: usize,
    pub session_timeout: Option<std::time::Duration>,
    pub enable_threading: bool,
    pub mock_config: MockConfig,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            enable_logging: true,
            log_level: "info".to_string(),
            max_sessions: 1024,
            session_timeout: Some(std::time::Duration::from_secs(3600)), // 1 hour
            enable_threading: true,
            mock_config: MockConfig::default(),
        }
    }
}

impl MockProvider {
    /// Create a new provider with custom configuration
    pub fn with_provider_config(config: ProviderConfig) -> Result<Self, ProviderError> {
        let backend = MockBackend::with_config(config.mock_config)
            .map_err(|e| ProviderError::BackendError(e))?;
        let provider = Self::new(backend);
        
        if config.enable_logging {
            log::info!("Mock provider created with config: {:?}", config);
        }
        
        Ok(provider)
    }

    /// Get current configuration
    pub fn config(&self) -> ProviderConfig {
        ProviderConfig {
            enable_logging: true,
            log_level: "info".to_string(),
            max_sessions: 1024,
            session_timeout: Some(std::time::Duration::from_secs(3600)),
            enable_threading: true,
            mock_config: self.backend.config().clone(),
        }
    }

    /// Create a provider for deterministic testing
    pub fn deterministic() -> Result<Self, ProviderError> {
        let config = MockConfig::deterministic();
        Self::with_config(config)
    }

    /// Create a provider with error injection enabled
    pub fn with_error_injection(operations: Vec<String>) -> Result<Self, ProviderError> {
        let config = MockConfig::with_error_injection(operations);
        Self::with_config(config)
    }

    /// Create a provider with performance simulation
    pub fn with_performance_simulation(
        delays: std::collections::HashMap<String, std::time::Duration>
    ) -> Result<Self, ProviderError> {
        let config = MockConfig::with_performance_simulation(delays);
        Self::with_config(config)
    }

    /// Load provider configuration from file
    pub fn from_config_file(path: &str) -> Result<Self, ProviderError> {
        let config = MockConfig::from_file(path)
            .map_err(|e| ProviderError::ConfigurationError(e.to_string()))?;
        Self::with_config(config)
    }

    /// Save provider configuration to file
    pub fn save_config_to_file(&self, path: &str) -> Result<(), ProviderError> {
        self.backend.config().to_file(path)
            .map_err(|e| ProviderError::ConfigurationError(e.to_string()))
    }
}