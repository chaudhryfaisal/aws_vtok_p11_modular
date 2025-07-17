//! Mock context implementations for crypto operations.

use vtok_backend::types::{BackendResult, BackendError};
use crate::data::MockConfig;

/// Base context for mock operations
#[derive(Debug, Clone)]
pub struct MockContext {
    config: MockConfig,
    operation_count: usize,
}

impl MockContext {
    /// Create a new mock context
    pub fn new(config: &MockConfig) -> Self {
        Self {
            config: config.clone(),
            operation_count: 0,
        }
    }

    /// Increment operation count
    pub fn increment_operations(&mut self) {
        self.operation_count += 1;
    }

    /// Get operation count
    pub fn operation_count(&self) -> usize {
        self.operation_count
    }

    /// Check if error injection should occur
    pub fn should_inject_error(&self, operation: &str) -> Option<BackendError> {
        if let Some(ref error_config) = self.config.error_injection {
            if error_config.enabled && error_config.operations.contains(&operation.to_string()) {
                return Some(BackendError::MockError(format!("Injected error for {}", operation)));
            }
        }
        None
    }

    /// Simulate performance delay if configured
    pub async fn simulate_delay(&self, operation: &str) {
        if let Some(ref perf_config) = self.config.performance_simulation {
            if perf_config.enabled {
                if let Some(delay) = perf_config.operation_delays.get(operation) {
                    tokio::time::sleep(*delay).await;
                }
            }
        }
    }

    /// Generate deterministic data if configured
    pub fn generate_deterministic_data(&self, length: usize, seed: u8) -> Vec<u8> {
        if self.config.deterministic {
            let mut data = Vec::with_capacity(length);
            for i in 0..length {
                data.push(((seed as usize + i) % 256) as u8);
            }
            data
        } else {
            use rand::RngCore;
            let mut data = vec![0u8; length];
            rand::thread_rng().fill_bytes(&mut data);
            data
        }
    }
}