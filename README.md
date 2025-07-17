# Prompt Kilo Code
```text
@src/vtok_p11 project is complete implementation of pkcs11 provider , it currently used aws-lc crypto library to implement backend provider and all with in same code base

 I would like to
- create a an abstraction in vtok_backend so backend can be implement with any crypto library such as openssl, boringssl, wolfcrypt
- refactor vtok_p11 in such a way so it can become as dependency of other crates which can plug in any backend
- move all  aws_ls crypto logic to separate crate called pkcs11_aws_ls  as one of the implementation of vtok_backend and should depend on vtok_p11 to re use all the pkcs11 specific implementation
- create a completed pkcs11_mock create which also depends on vtok_backend and vtok_p11 to provide complete mock implementation of pkcs11 provider 
- pkcs11_aws_ls and pkcs11_mock are completed pkcs11 modules which can be used with any pkcs11 tool to query info 
```

# Enhanced
```text
I need to refactor my existing @src/vtok_p11 PKCS#11 provider implementation to create a modular, extensible architecture

 Currently, the project is a monolithic implementation using aws-lc crypto library

 I want to transform it into a layered system with clear separation of concerns:

Create a vtok_backend abstraction layer that defines a generic interface for cryptographic operations, allowing any crypto library (OpenSSL, BoringSSL, WolfCrypt, etc

) to be plugged in as the underlying implementation without affecting the PKCS#11 logic



Refactor vtok_p11 into a reusable core library crate that contains all PKCS#11-specific protocol handling, object management, and session management logic, but remains crypto-backend agnostic

 This crate should be designed as a dependency that other implementations can build upon



Extract all current aws-lc crypto functionality into a new pkcs11_aws_lc crate that implements the vtok_backend interface and depends on vtok_p11 for PKCS#11 operations

 This crate should provide a complete, production-ready PKCS#11 provider using aws-lc as the cryptographic backend



Develop a pkcs11_mock crate that also implements vtok_backend and depends on vtok_p11, providing a comprehensive mock implementation suitable for testing, development, and scenarios where actual cryptographic operations are not required



Both pkcs11_aws_lc and pkcs11_mock should be complete, standalone PKCS#11 modules that can be used directly with any PKCS#11-compatible tools and applications for querying provider information, managing keys, and performing cryptographic operations


```

```
I need to refactor my existing @src/vtok_p11 PKCS#11 provider implementation to create a modular, extensible architecture that transforms the current monolithic aws-lc-based implementation into a layered system with clear separation of concerns

Design and implement a vtok_backend abstraction layer that defines a comprehensive generic interface for all cryptographic operations, enabling any crypto library (OpenSSL, BoringSSL, WolfCrypt, aws-lc, or others) to be seamlessly integrated as the underlying implementation without requiring any modifications to the PKCS#11 protocol logic

Refactor the existing vtok_p11 codebase into a reusable, crypto-backend-agnostic core library crate that encapsulates all PKCS#11-specific functionality including protocol handling, object lifecycle management, session management, token operations, and attribute processing, designed as a foundational dependency for multiple concrete implementations

Extract and migrate all current aws-lc cryptographic functionality into a new pkcs11_aws_lc crate that implements the vtok_backend interface and depends on vtok_p11, providing a complete, production-ready PKCS#11 provider with full aws-lc integration for real-world cryptographic operations

Develop a comprehensive pkcs11_mock crate that implements the vtok_backend interface and depends on vtok_p11, offering a fully functional mock implementation with simulated cryptographic operations suitable for testing, development environments, CI/CD pipelines, and scenarios where actual cryptographic security is not required but PKCS#11 compatibility is needed

Ensure both pkcs11_aws_lc and pkcs11_mock function as complete, standalone PKCS#11 modules that can be directly integrated with any PKCS#11-compatible applications, tools, and libraries for comprehensive provider information queries, key management operations, certificate handling, and all standard cryptographic functions

Design the vtok_backend interface to support extensibility for future cryptographic backends while maintaining API stability, implement proper error handling and type safety throughout all layers, ensure thread safety and concurrent access patterns, and maintain backward compatibility where possible

Create a comprehensive project plan with detailed task breakdown, implementation phases, testing strategies, and documentation requirements, then generate and maintain a detailed todo.md file that tracks all tasks with checkboxes, priority levels, dependencies, and completion status, ensuring the todo.md remains current and accurate as tasks are completed so development can be resumed efficiently at any point


```