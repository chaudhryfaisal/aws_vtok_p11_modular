# Vtok PKCS#11 Provider Refactoring Plan

This document outlines the tasks required to refactor the `vtok_p11` provider into a modular, crypto-agnostic architecture.

## Phase 1: Architecture & Planning

- [ ] **Define `vtok_backend` Interface:**
    - [ ] Analyze `src/vtok_p11/src/crypto` to identify all cryptographic primitives.
    - [ ] Define a `VtokBackend` trait in a new `vtok_backend` crate (or within the refactored `vtok_p11` crate). This trait will abstract all crypto operations (key generation, encryption, decryption, signing, verification, digests, etc.).
    - [ ] Define data structures for keys, certificates, and other cryptographic objects to be passed across the backend boundary.
- [ ] **Plan Crate Structure:**
    - [ ] Finalize the new crate structure (`vtok_p11`, `pkcs11_aws_lc`, `pkcs11_mock`).
    - [ ] Update the root `Cargo.toml` to reflect the new workspace structure.
- [ ] **Create `todo.md`:**
    - [x] Create this `todo.md` file to track all tasks and their dependencies.

## Phase 2: Core Library Refactoring (`vtok_p11`)

- [ ] **Isolate Crypto-Agnostic Logic:**
    - [ ] Refactor the existing `vtok_p11` crate to be crypto-agnostic.
    - [ ] Remove all direct `aws-lc` (or other crypto library) dependencies from `vtok_p11`.
    - [ ] All cryptographic operations in `vtok_p11` must be delegated to the `VtokBackend` trait.
- [ ] **Refactor `vtok_p11::api`:**
    - [ ] Update functions in `src/vtok_p11/src/api` to use the `VtokBackend` trait.
- [ ] **Refactor `vtok_p11::backend`:**
    - [ ] Update `src/vtok_p11/src/backend` to work with the generic `VtokBackend`.
    - [ ] The object database (`src/vtok_p11/src/backend/db`) will need to store backend-specific key handles or identifiers.

## Phase 3: `aws-lc` Backend Implementation (`pkcs11_aws_lc`)

- [ ] **Create `pkcs11_aws_lc` Crate:**
    - [ ] Create a new crate `pkcs11_aws_lc`.
    - [ ] This crate will depend on `vtok_p11` and `aws-lc`.
- [ ] **Implement `VtokBackend` for `aws-lc`:**
    - [ ] Create a struct, e.g., `AwsLcBackend`, that implements the `VtokBackend` trait.
    - [ ] Implement all trait methods using `aws-lc` for cryptographic operations.
- [ ] **Create PKCS#11 Module Entry Points:**
    - [ ] The `pkcs11_aws_lc` crate will be a `cdylib`.
    - [ ] It will expose the standard PKCS#11 C ABI functions (`C_GetFunctionList`, etc.).
    - [ ] These functions will instantiate the `vtok_p11` core with the `AwsLcBackend`.

## Phase 4: Mock Backend Implementation (`pkcs11_mock`)

- [ ] **Create `pkcs11_mock` Crate:**
    - [ ] Create a new crate `pkcs11_mock`.
    - [ ] This crate will depend on `vtok_p11`.
- [ ] **Implement Mock `VtokBackend`:**
    - [ ] Create a struct, e.g., `MockBackend`, that implements the `VtokBackend` trait.
    - [ ] Implement the trait methods with mock logic (e.g., in-memory key store, predictable outputs). This is for testing the `vtok_p11` core without a real crypto backend.
- [ ] **Create PKCS#11 Module for Testing:**
    - [ ] The `pkcs11_mock` crate will also be a `cdylib`.
    - [ ] It will expose the PKCS#11 C ABI, instantiating the `vtok_p11` core with the `MockBackend`.

## Phase 5: Integration & Testing

- [ ] **Integration Tests:**
    - [ ] Create a new integration test suite that can run against any PKCS#11 module that follows the new architecture.
    - [ ] Run tests against `pkcs11_aws_lc`.
    - [ ] Run tests against `pkcs11_mock`.
- [ ] **Build System:**
    - [ ] Update `Makefile` to build both `pkcs11_aws_lc.so` and `pkcs11_mock.so`.
- [ ] **Documentation:**
    - [ ] Update `README.md` to explain the new architecture, how to build the different backends, and how to use them.
    - [ ] Add developer documentation for the `VtokBackend` trait for creating new backends.
- [ ] **Cleanup:**
    - [ ] Remove any old, unused code from the original `vtok_p11` implementation.
    - [ ] Ensure `cargo clippy` and `cargo fmt` pass on all crates.