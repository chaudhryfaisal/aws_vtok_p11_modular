# Migration Guide: From Monolithic to Modular Architecture

## Overview

This guide provides step-by-step instructions for migrating from the original monolithic vtok_p11 implementation to the new modular architecture. The modular design separates concerns, improves maintainability, and enables pluggable cryptographic backends.

## Migration Benefits

### Before: Monolithic Architecture
- Single large crate with tightly coupled components
- Direct dependency on specific cryptographic libraries
- Difficult to test individual components
- Hard to add new cryptographic backends
- Complex build configuration

### After: Modular Architecture
- Clear separation of concerns across multiple crates
- Pluggable backend system with trait-based abstractions
- Independent testing of components
- Easy addition of new cryptographic backends
- Simplified build and dependency management

## Migration Steps

### Step 1: Understanding the New Structure

The monolithic crate has been split into five focused crates:

```
Old Structure:
vtok_p11/ (monolithic)
├── src/
│   ├── lib.rs
│   ├── crypto/
│   ├── pkcs11/
│   └── backend/

New Structure:
├── vtok_backend/     # Backend abstraction traits
├── vtok_common/      # Shared utilities
├── vtok_p11/         # Core PKCS#11 implementation
├── pkcs11_aws_lc/    # AWS-LC backend provider
└── pkcs11_mock/      # Mock backend provider
```

### Step 2: Dependency Updates

#### Old Cargo.toml Dependencies
```toml
[dependencies]
aws-lc-rs = "1.8"
libc = "0.2"
serde = "1.0"
# ... all dependencies in one place
```

#### New Workspace Dependencies
```toml
# Root Cargo.toml
[workspace]
members = ["vtok_backend", "vtok_common", "vtok_p11", "pkcs11_aws_lc", "pkcs11_mock"]

[workspace.dependencies]
vtok_backend = { path = "vtok_backend" }
vtok_common = { path = "vtok_common" }
# ... shared dependencies
```

### Step 3: Code Migration Patterns

#### Backend Interface Migration

**Old Pattern: Direct Implementation**
```rust
// Old: Direct AWS-LC usage in PKCS#11 code
use aws_lc_rs::signature;

pub fn sign_data(key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    // Direct AWS-LC calls mixed with PKCS#11 logic
    let signature = signature::sign(&key.aws_lc_key, data)?;
    Ok(signature.as_ref().to_vec())
}
```

**New Pattern: Trait-Based Abstraction**
```rust
// New: Backend trait implementation
use vtok_backend::traits::SignatureOperations;

impl SignatureOperations for AwsLcBackend {
    fn sign(&mut self, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // AWS-LC specific implementation isolated in backend
        let signature = signature::sign(&key.aws_lc_key, data)?;
        Ok(signature.as_ref().to_vec())
    }
}

// PKCS#11 layer uses trait
pub fn c_sign(session: SessionHandle, data: &[u8]) -> CK_RV {
    let backend = get_backend(session);
    match backend.sign(&key_handle, data) {
        Ok(signature) => store_signature(signature),
        Err(e) => convert_error(e),
    }
}
```

#### Error Handling Migration

**Old Pattern: Mixed Error Types**
```rust
// Old: Different error types throughout codebase
pub enum VtokError {
    AwsLcError(aws_lc_rs::error::Unspecified),
    IoError(std::io::Error),
    ParseError(String),
}
```

**New Pattern: Layered Error Handling**
```rust
// Backend-specific errors
#[derive(thiserror::Error, Debug)]
pub enum AwsLcError {
    #[error("AWS-LC operation failed: {0}")]
    CryptoError(#[from] aws_lc_rs::error::Unspecified),
    #[error("Invalid key format")]
    InvalidKey,
}

// Common backend error trait
pub trait BackendError: std::error::Error + Send + Sync + 'static {}

// PKCS#11 layer converts backend errors to PKCS#11 return codes
fn convert_backend_error<E: BackendError>(error: E) -> CK_RV {
    // Standardized error conversion
}
```

### Step 4: Application Migration

#### For PKCS#11 Applications

**No Changes Required**: Applications using the standard PKCS#11 C API continue to work without modification.

```c
// Application code remains unchanged
CK_RV rv = C_Initialize(NULL);
CK_SESSION_HANDLE session;
rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &session);
// ... existing PKCS#11 code works as before
```

#### For Rust Applications

**Old Pattern: Direct Library Usage**
```rust
// Old: Direct dependency on monolithic crate
use vtok_p11::{initialize, create_session, sign_data};

fn main() {
    initialize();
    let session = create_session();
    let signature = sign_data(&session, &key, &data);
}
```

**New Pattern: Provider Selection**
```rust
// New: Choose specific provider
use pkcs11_aws_lc as provider;
// or
use pkcs11_mock as provider;

fn main() {
    provider::initialize();
    let session = provider::create_session();
    let signature = provider::sign_data(&session, &key, &data);
}
```

### Step 5: Testing Migration

#### Old Testing Approach
```rust
// Old: Tests mixed with implementation
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sign() {
        // Test requires real AWS-LC operations
        let key = generate_real_key();
        let signature = sign_data(&key, b"test");
        assert!(verify_signature(&key, b"test", &signature));
    }
}
```

#### New Testing Approach
```rust
// New: Isolated testing with mock backend
#[cfg(test)]
mod tests {
    use vtok_backend::traits::*;
    use pkcs11_mock::MockBackend;
    
    #[test]
    fn test_sign() {
        let mut backend = MockBackend::new();
        let key = backend.generate_test_key();
        let signature = backend.sign(&key, b"test").unwrap();
        assert!(backend.verify(&key, b"test", &signature).unwrap());
    }
    
    #[test]
    fn test_error_conditions() {
        let mut backend = MockBackend::with_error_injection();
        backend.inject_error(ErrorType::InvalidKey);
        let result = backend.sign(&invalid_key, b"test");
        assert!(result.is_err());
    }
}
```

### Step 6: Build System Migration

#### Old Build Configuration
```toml
# Single Cargo.toml with all features
[features]
default = ["aws-lc"]
aws-lc = ["aws-lc-rs"]
mock = ["mock-crypto"]
```

#### New Build Configuration
```toml
# Workspace-level configuration
[workspace]
members = ["vtok_backend", "vtok_common", "vtok_p11", "pkcs11_aws_lc", "pkcs11_mock"]

# Build specific providers
cargo build -p pkcs11_aws_lc    # AWS-LC provider
cargo build -p pkcs11_mock      # Mock provider
cargo build --workspace         # All components
```

### Step 7: Deployment Migration

#### Old Deployment
```bash
# Single library file
libvtok_p11.so
```

#### New Deployment Options

**Option 1: Specific Provider**
```bash
# Deploy only needed provider
libpkcs11_aws_lc.so     # Production with AWS-LC
libpkcs11_mock.so       # Testing/development
```

**Option 2: Multiple Providers**
```bash
# Deploy multiple providers for flexibility
libpkcs11_aws_lc.so
libpkcs11_mock.so
# Application chooses at runtime
```

### Step 8: Configuration Migration

#### Old Configuration
```json
{
  "crypto_backend": "aws-lc",
  "key_storage": "/path/to/keys",
  "log_level": "info"
}
```

#### New Configuration
```json
{
  "provider": "pkcs11_aws_lc",
  "backend_config": {
    "key_storage": "/path/to/keys",
    "performance_mode": "optimized"
  },
  "log_level": "info"
}
```

## Migration Checklist

### Pre-Migration Assessment
- [ ] Identify current vtok_p11 usage patterns
- [ ] Document existing configuration
- [ ] List all dependent applications
- [ ] Plan testing strategy

### Code Migration
- [ ] Update build dependencies to workspace structure
- [ ] Migrate direct crypto calls to backend traits
- [ ] Update error handling patterns
- [ ] Refactor tests to use mock backend

### Testing
- [ ] Verify PKCS#11 API compatibility
- [ ] Test with both AWS-LC and mock backends
- [ ] Validate performance characteristics
- [ ] Run integration tests

### Deployment
- [ ] Choose appropriate provider(s)
- [ ] Update deployment scripts
- [ ] Migrate configuration files
- [ ] Plan rollback strategy

### Validation
- [ ] Verify all applications work correctly
- [ ] Confirm performance meets requirements
- [ ] Validate security properties
- [ ] Document any behavioral changes

## Common Migration Issues

### Issue 1: Direct Crypto Library Usage
**Problem**: Code directly imports and uses AWS-LC functions.
**Solution**: Refactor to use backend traits and move crypto-specific code to backend implementations.

### Issue 2: Tightly Coupled Tests
**Problem**: Tests require real cryptographic operations.
**Solution**: Use mock backend for unit tests, real backend for integration tests.

### Issue 3: Configuration Complexity
**Problem**: Complex feature flags and conditional compilation.
**Solution**: Use separate provider crates with clear boundaries.

### Issue 4: Performance Regression
**Problem**: Trait dispatch overhead affects performance.
**Solution**: Use static dispatch where possible, profile critical paths.

## Best Practices

### 1. Gradual Migration
- Migrate one component at a time
- Maintain backward compatibility during transition
- Use feature flags to enable new architecture gradually

### 2. Testing Strategy
- Use mock backend for fast unit tests
- Use real backend for integration and compliance tests
- Implement comprehensive error injection testing

### 3. Performance Monitoring
- Benchmark before and after migration
- Profile critical paths with trait dispatch
- Optimize hot paths if necessary

### 4. Documentation
- Document all API changes
- Provide migration examples
- Update deployment guides

## Rollback Plan

If migration issues arise:

1. **Immediate Rollback**: Keep old monolithic version available
2. **Partial Rollback**: Use feature flags to disable new architecture
3. **Component Rollback**: Revert specific components while keeping others
4. **Configuration Rollback**: Switch back to old configuration format

## Support and Resources

- **Architecture Documentation**: [`docs/architecture.md`](architecture.md)
- **Backend Implementation Guide**: [`docs/backend_implementation.md`](backend_implementation.md)
- **API Reference**: [`docs/api_reference.md`](api_reference.md)
- **Integration Tests**: [`tests/`](../tests/)
- **Example Applications**: [`examples/`](../examples/)

The modular architecture provides a solid foundation for future development while maintaining compatibility with existing PKCS#11 applications. This migration enables better testing, easier maintenance, and the flexibility to support multiple cryptographic backends.