//! Common context utilities for AWS-LC backend.

use vtok_backend::types::{ContextState, OperationProgress};

/// Common context state management
#[derive(Debug, Clone)]
pub struct ContextStateManager {
    state: ContextState,
    bytes_processed: u64,
}

impl ContextStateManager {
    pub fn new() -> Self {
        Self {
            state: ContextState::Initialized,
            bytes_processed: 0,
        }
    }

    pub fn state(&self) -> ContextState {
        self.state
    }

    pub fn set_state(&mut self, state: ContextState) {
        self.state = state;
    }

    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    pub fn add_bytes_processed(&mut self, bytes: usize) {
        self.bytes_processed += bytes as u64;
    }

    pub fn progress(&self) -> OperationProgress {
        OperationProgress::new(self.bytes_processed)
    }

    pub fn can_update(&self) -> bool {
        self.state.can_update()
    }

    pub fn can_finalize(&self) -> bool {
        self.state.can_finalize()
    }

    pub fn is_finalized(&self) -> bool {
        self.state.is_finalized()
    }
}

impl Default for ContextStateManager {
    fn default() -> Self {
        Self::new()
    }
}