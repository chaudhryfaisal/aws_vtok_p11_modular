//! Provider information utility
//!
//! This binary provides information about the AWS-LC PKCS#11 provider,
//! including supported mechanisms, key algorithms, and capabilities.

use std::process;
use clap::{Arg, Command};
use pkcs11_aws_lc::backend::AwsLcBackend;
use pkcs11_aws_lc::provider::AwsLcProvider;
use vtok_backend::traits::CryptoBackend;

fn main() {
    env_logger::init();

    let matches = Command::new("pkcs11-aws-lc-info")
        .version("1.0.0")
        .author("Amazon Web Services")
        .about("AWS-LC PKCS#11 Provider Information Utility")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Enable verbose output"),
        )
        .arg(
            Arg::new("mechanisms")
                .short('m')
                .long("mechanisms")
                .action(clap::ArgAction::SetTrue)
                .help("List supported mechanisms"),
        )
        .arg(
            Arg::new("algorithms")
                .short('a')
                .long("algorithms")
                .action(clap::ArgAction::SetTrue)
                .help("List supported key algorithms"),
        )
        .arg(
            Arg::new("capabilities")
                .short('c')
                .long("capabilities")
                .action(clap::ArgAction::SetTrue)
                .help("Show provider capabilities"),
        )
        .arg(
            Arg::new("all")
                .long("all")
                .action(clap::ArgAction::SetTrue)
                .help("Show all information"),
        )
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let show_mechanisms = matches.get_flag("mechanisms") || matches.get_flag("all");
    let show_algorithms = matches.get_flag("algorithms") || matches.get_flag("all");
    let show_capabilities = matches.get_flag("capabilities") || matches.get_flag("all");

    // Create the backend and provider
    let backend = match AwsLcBackend::new() {
        Ok(backend) => backend,
        Err(e) => {
            eprintln!("Failed to create AWS-LC backend: {:?}", e);
            process::exit(1);
        }
    };

    let provider = AwsLcProvider::new(backend);

    // Show basic provider information
    println!("AWS-LC PKCS#11 Provider Information");
    println!("====================================");
    
    let info = provider.info();
    println!("Name: {}", info.name);
    println!("Version: {}", info.version);
    println!("Description: {}", info.description);
    println!("Vendor: {}", info.vendor);
    println!();

    // Show backend information
    let backend_info = provider.backend().info();
    println!("Backend Information:");
    println!("  Name: {}", backend_info.name());
    println!("  Version: {}", backend_info.version());
    println!("  Description: {}", backend_info.description());
    println!();

    // Show capabilities if requested
    if show_capabilities {
        println!("Provider Capabilities:");
        let caps = provider.capabilities();
        println!("  Hardware Keys: {}", caps.hardware_keys);
        println!("  Secure Storage: {}", caps.secure_storage);
        println!("  Hardware RNG: {}", caps.hardware_rng);
        println!("  Side-Channel Resistant: {}", caps.side_channel_resistant);
        println!("  FIPS Compliant: {}", caps.fips_compliant);
        println!("  Thread Safe: {}", provider.is_thread_safe());
        if let Some(max_sessions) = provider.max_sessions() {
            println!("  Max Sessions: {}", max_sessions);
        }
        println!();
    }

    // Show supported mechanisms if requested
    if show_mechanisms {
        println!("Supported Mechanisms:");
        let mechanisms = provider.supported_mechanisms();
        for (i, mechanism) in mechanisms.iter().enumerate() {
            if verbose {
                println!("  {}: {:?}", i + 1, mechanism);
            } else {
                println!("  {}: {}", i + 1, format_mechanism(mechanism));
            }
        }
        println!("  Total: {} mechanisms", mechanisms.len());
        println!();
    }

    // Show supported key algorithms if requested
    if show_algorithms {
        println!("Supported Key Algorithms:");
        let algorithms = provider.supported_key_algorithms();
        for (i, algorithm) in algorithms.iter().enumerate() {
            let key_info = if verbose {
                format!("{:?}", algorithm)
            } else {
                format_key_algorithm(algorithm)
            };
            
            if let Some(min_size) = provider.min_key_size(*algorithm) {
                if let Some(max_size) = provider.max_key_size(*algorithm) {
                    if min_size == max_size {
                        println!("  {}: {} ({} bits)", i + 1, key_info, min_size);
                    } else {
                        println!("  {}: {} ({}-{} bits)", i + 1, key_info, min_size, max_size);
                    }
                } else {
                    println!("  {}: {} (min {} bits)", i + 1, key_info, min_size);
                }
            } else {
                println!("  {}: {}", i + 1, key_info);
            }
        }
        println!("  Total: {} algorithms", algorithms.len());
        println!();
    }

    // Show configuration if verbose
    if verbose {
        println!("Provider Configuration:");
        let config = provider.config();
        println!("  Logging Enabled: {}", config.enable_logging);
        println!("  Log Level: {}", config.log_level);
        println!("  Max Sessions: {}", config.max_sessions);
        if let Some(timeout) = config.session_timeout {
            println!("  Session Timeout: {:?}", timeout);
        }
        println!("  Threading Enabled: {}", config.enable_threading);
        println!();
    }

    println!("Provider initialized successfully!");
}

/// Format a mechanism for display
fn format_mechanism(mechanism: &vtok_backend::types::Mechanism) -> String {
    match mechanism {
        vtok_backend::types::Mechanism::Digest(alg) => format!("Digest ({})", format_digest_algorithm(alg)),
        vtok_backend::types::Mechanism::RsaPkcs1 { digest } => {
            if let Some(digest) = digest {
                format!("RSA PKCS#1 with {}", format_digest_algorithm(digest))
            } else {
                "RSA PKCS#1".to_string()
            }
        }
        vtok_backend::types::Mechanism::RsaPkcs1Pss { digest, mgf, salt_len } => {
            format!("RSA PSS (digest: {}, mgf: {}, salt: {})", 
                   format_digest_algorithm(digest),
                   format_digest_algorithm(mgf),
                   salt_len)
        }
        vtok_backend::types::Mechanism::Ecdsa { digest } => {
            if let Some(digest) = digest {
                format!("ECDSA with {}", format_digest_algorithm(digest))
            } else {
                "ECDSA".to_string()
            }
        }
        _ => format!("{:?}", mechanism),
    }
}

/// Format a digest algorithm for display
fn format_digest_algorithm(alg: &vtok_backend::types::DigestAlgorithm) -> String {
    match alg {
        vtok_backend::types::DigestAlgorithm::Sha1 => "SHA-1".to_string(),
        vtok_backend::types::DigestAlgorithm::Sha224 => "SHA-224".to_string(),
        vtok_backend::types::DigestAlgorithm::Sha256 => "SHA-256".to_string(),
        vtok_backend::types::DigestAlgorithm::Sha384 => "SHA-384".to_string(),
        vtok_backend::types::DigestAlgorithm::Sha512 => "SHA-512".to_string(),
        vtok_backend::types::DigestAlgorithm::Sha512_256 => "SHA-512/256".to_string(),
        _ => format!("{:?}", alg),
    }
}

/// Format a key algorithm for display
fn format_key_algorithm(alg: &vtok_backend::types::KeyAlgorithm) -> String {
    match alg {
        vtok_backend::types::KeyAlgorithm::Rsa2048 => "RSA-2048".to_string(),
        vtok_backend::types::KeyAlgorithm::Rsa3072 => "RSA-3072".to_string(),
        vtok_backend::types::KeyAlgorithm::Rsa4096 => "RSA-4096".to_string(),
        vtok_backend::types::KeyAlgorithm::EcdsaP256 => "ECDSA P-256".to_string(),
        vtok_backend::types::KeyAlgorithm::EcdsaP384 => "ECDSA P-384".to_string(),
        vtok_backend::types::KeyAlgorithm::Aes256 => "AES-256".to_string(),
        _ => format!("{:?}", alg),
    }
}