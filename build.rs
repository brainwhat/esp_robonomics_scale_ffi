extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Get the directory of the Cargo.toml manifest
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var is not set");

    // Get the package name from Cargo.toml
    let package_name = env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME env var is not set");

    // Define the output path for the generated C header file
    // It will be placed in an 'include' subdirectory within the Rust crate root
    let header_file_name = format!("{}.h", package_name); // e.g., rust_scale_codec_wrapper.h
    let output_file_h = PathBuf::from(&crate_dir)
        .join("include")
        .join(&header_file_name);

    // Ensure the 'include' directory exists
    if let Some(parent_dir) = output_file_h.parent() {
        if !parent_dir.exists() {
            std::fs::create_dir_all(parent_dir).expect("Failed to create include directory");
        }
    }

    // Configure cbindgen
    let config = cbindgen::Config {
        language: cbindgen::Language::C, // Generate C-style headers
        include_guard: Some(format!(
            "{}_H",
            package_name.to_uppercase().replace("-", "_")
        )), // e.g., RUST_SCALE_CODEC_WRAPPER_H
        // header: Some("/* Generated by cbindgen */".to_string()), // Optional header comment
        // namespace: Some("my_namespace"), // If you want to namespace your C functions
        // style: cbindgen::Style::Both, // To generate both types and functions if needed
        ..Default::default()
    };

    // Generate the C bindings
    cbindgen::generate_with_config(&crate_dir, config)
        .expect("Unable to generate C bindings")
        .write_to_file(&output_file_h);

    println!("cargo:rerun-if-changed=src/lib.rs"); // Re-run build.rs if lib.rs changes
    println!("cargo:rerun-if-changed=build.rs"); // Re-run build.rs if build.rs changes
    println!("Generated C header at: {}", output_file_h.display());
}
