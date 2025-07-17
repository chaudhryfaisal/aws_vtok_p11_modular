// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;

fn main() {
    // Link to the crypto library for AWS-LC
    println!("cargo:rustc-link-lib=dylib=crypto");
    
    // Handle feature-based linking
    if cfg!(feature = "static-linking") {
        println!("cargo:rustc-link-lib=static=aws-lc-crypto");
        println!("cargo:rustc-link-lib=static=aws-lc-ssl");
    } else if cfg!(feature = "dynamic-linking") {
        println!("cargo:rustc-link-lib=dylib=aws-lc-crypto");
        println!("cargo:rustc-link-lib=dylib=aws-lc-ssl");
    }
    
    // Platform-specific linking
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=dylib=dl");
            println!("cargo:rustc-link-lib=dylib=pthread");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
        }
        "windows" => {
            println!("cargo:rustc-link-lib=dylib=ws2_32");
            println!("cargo:rustc-link-lib=dylib=advapi32");
            println!("cargo:rustc-link-lib=dylib=crypt32");
            println!("cargo:rustc-link-lib=dylib=user32");
        }
        _ => {}
    }
    
    // Rerun if environment variables change
    println!("cargo:rerun-if-env-changed=AWS_LC_STATIC");
    println!("cargo:rerun-if-env-changed=AWS_LC_DYNAMIC");
    
    // Rerun if build script changes
    println!("cargo:rerun-if-changed=build.rs");
}