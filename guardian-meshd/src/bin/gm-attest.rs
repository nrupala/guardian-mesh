// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use guardian_meshd::attestation::{ProvenanceStatement, AttestationPackage, verify_package};
use guardian_meshd::sealed_envelope::load_or_generate_signing_key;
use sha2::{Sha256, Digest};
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        usage();
        std::process::exit(2);
    }
    
    let subcommand = &args[1];
    
    match subcommand.as_str() {
        "build" => build_statement(&args[2..]),
        "sign" => sign_statement(&args[2..]),
        "verify" => verify_attestation(&args[2..]),
        _ => {
            eprintln!("Unknown subcommand: {}", subcommand);
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    eprintln!("gm-attest: Guardian Mesh attestation tool");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  gm-attest build --binary <path> --source-dir <path> --build-type <uri>");
    eprintln!("                  --invocation-id <id> --target <triple> --toolchain <string>");
    eprintln!("                  --version <version> --out <file>");
    eprintln!();
    eprintln!("  gm-attest sign --statement <file> --key-file <path> --out <file>");
    eprintln!();
    eprintln!("  gm-attest verify --package <file> --binary <path>");
}

fn build_statement(args: &[String]) {
    let mut binary_path = None;
    let mut source_dir = None;
    let mut build_type = None;
    let mut invocation_id = None;
    let mut target = None;
    let mut toolchain = None;
    let mut version = None;
    let mut out = None;
    
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--binary" => {
                i += 1;
                if i >= args.len() { usage_error("--binary requires a value"); }
                binary_path = Some(&args[i]);
            }
            "--source-dir" => {
                i += 1;
                if i >= args.len() { usage_error("--source-dir requires a value"); }
                source_dir = Some(&args[i]);
            }
            "--build-type" => {
                i += 1;
                if i >= args.len() { usage_error("--build-type requires a value"); }
                build_type = Some(&args[i]);
            }
            "--invocation-id" => {
                i += 1;
                if i >= args.len() { usage_error("--invocation-id requires a value"); }
                invocation_id = Some(&args[i]);
            }
            "--target" => {
                i += 1;
                if i >= args.len() { usage_error("--target requires a value"); }
                target = Some(&args[i]);
            }
            "--toolchain" => {
                i += 1;
                if i >= args.len() { usage_error("--toolchain requires a value"); }
                toolchain = Some(&args[i]);
            }
            "--version" => {
                i += 1;
                if i >= args.len() { usage_error("--version requires a value"); }
                version = Some(&args[i]);
            }
            "--out" => {
                i += 1;
                if i >= args.len() { usage_error("--out requires a value"); }
                out = Some(&args[i]);
            }
            _ => usage_error(&format!("unknown argument: {}", args[i])),
        }
        i += 1;
    }
    
    let binary_path = binary_path.unwrap_or_else(|| usage_error("--binary is required"));
    let source_dir = source_dir.unwrap_or_else(|| usage_error("--source-dir is required"));
    let build_type = build_type.unwrap_or_else(|| usage_error("--build-type is required"));
    let invocation_id = invocation_id.unwrap_or_else(|| usage_error("--invocation-id is required"));
    let target = target.unwrap_or_else(|| usage_error("--target is required"));
    let toolchain = toolchain.unwrap_or_else(|| usage_error("--toolchain is required"));
    let version = version.unwrap_or_else(|| usage_error("--version is required"));
    let out = out.unwrap_or_else(|| usage_error("--out is required"));
    
    // Read binary and compute SHA-256
    let binary_bytes = std::fs::read(binary_path)
        .unwrap_or_else(|e| fatal(&format!("failed to read binary {}: {}", binary_path, e)));
    let subject_sha256 = hex::encode(Sha256::digest(&binary_bytes));
    
    // Read Cargo.lock and compute SHA-256
    let cargo_lock_path = std::path::Path::new(source_dir).join("Cargo.lock");
    let cargo_lock_bytes = std::fs::read(&cargo_lock_path)
        .unwrap_or_else(|e| fatal(&format!("failed to read Cargo.lock at {}: {}", cargo_lock_path.display(), e)));
    let cargo_lock_sha256 = hex::encode(Sha256::digest(&cargo_lock_bytes));
    
    // Get git commit from source-dir
    let git_commit = Command::new("git")
        .args(&["-C", source_dir, "rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    
    // Get SOURCE_DATE_EPOCH from env or use 0
    let source_date_epoch: u64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    // Build command: construct a representative reproducible command
    let build_command = format!(
        "SOURCE_DATE_EPOCH={} GUARDIAN_MESH_GIT_COMMIT={} cargo build --release --locked --target {}",
        source_date_epoch, git_commit, target
    );
    
    let statement = ProvenanceStatement {
        statement_type: "https://in-toto.io/Statement/v1".to_string(),
        subject_name: "guardian-meshd".to_string(),
        subject_sha256,
        predicate_type: "https://slsa.dev/provenance/v1".to_string(),
        build_type: build_type.to_string(),
        builder_id: "guardian-mesh release pipeline".to_string(),
        invocation_id: invocation_id.to_string(),
        git_commit,
        version: version.to_string(),
        target_triple: target.to_string(),
        toolchain: toolchain.to_string(),
        source_date_epoch,
        cargo_lock_sha256,
        build_command,
    };
    
    let canonical = statement.canonical_json();
    std::fs::write(out, &canonical)
        .unwrap_or_else(|e| fatal(&format!("failed to write statement to {}: {}", out, e)));
    
    println!("Statement written to {}", out);
}

fn sign_statement(args: &[String]) {
    let mut statement_path = None;
    let mut key_file = None;
    let mut out = None;
    
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--statement" => {
                i += 1;
                if i >= args.len() { usage_error("--statement requires a value"); }
                statement_path = Some(&args[i]);
            }
            "--key-file" => {
                i += 1;
                if i >= args.len() { usage_error("--key-file requires a value"); }
                key_file = Some(&args[i]);
            }
            "--out" => {
                i += 1;
                if i >= args.len() { usage_error("--out requires a value"); }
                out = Some(&args[i]);
            }
            _ => usage_error(&format!("unknown argument: {}", args[i])),
        }
        i += 1;
    }
    
    let statement_path = statement_path.unwrap_or_else(|| usage_error("--statement is required"));
    let key_file = key_file.unwrap_or_else(|| usage_error("--key-file is required"));
    let out = out.unwrap_or_else(|| usage_error("--out is required"));
    
    // Read statement JSON
    let statement_json = std::fs::read(statement_path)
        .unwrap_or_else(|e| fatal(&format!("failed to read statement {}: {}", statement_path, e)));
    let statement: ProvenanceStatement = serde_json::from_slice(&statement_json)
        .unwrap_or_else(|e| fatal(&format!("failed to parse statement JSON: {}", e)));
    
    // Load signing key (key_file is the directory containing daemon_signing_key.bin)
    let keys_dir = std::path::Path::new(key_file).parent()
        .unwrap_or_else(|| fatal(&format!("--key-file must point to a file inside a directory")));
    let (signing_key, _vk) = load_or_generate_signing_key(keys_dir)
        .unwrap_or_else(|e| fatal(&format!("failed to load signing key: {}", e)));
    
    // Build the attestation package
    let package = AttestationPackage::build(statement, &signing_key);
    
    // Serialize and write
    let package_json = serde_json::to_vec_pretty(&package)
        .unwrap_or_else(|e| fatal(&format!("failed to serialize package: {}", e)));
    std::fs::write(out, &package_json)
        .unwrap_or_else(|e| fatal(&format!("failed to write package to {}: {}", out, e)));
    
    println!("Attestation package written to {}", out);
    println!("Fingerprint: {}", package.fingerprint);
    println!("Signer fingerprint: {}", package.signer_fingerprint);
}

fn verify_attestation(args: &[String]) {
    let mut package_path = None;
    let mut binary_path = None;
    
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--package" => {
                i += 1;
                if i >= args.len() { usage_error("--package requires a value"); }
                package_path = Some(&args[i]);
            }
            "--binary" => {
                i += 1;
                if i >= args.len() { usage_error("--binary requires a value"); }
                binary_path = Some(&args[i]);
            }
            _ => usage_error(&format!("unknown argument: {}", args[i])),
        }
        i += 1;
    }
    
    let package_path = package_path.unwrap_or_else(|| usage_error("--package is required"));
    let binary_path = binary_path.unwrap_or_else(|| usage_error("--binary is required"));
    
    // Read package JSON
    let package_json = std::fs::read(package_path)
        .unwrap_or_else(|e| fatal(&format!("failed to read package {}: {}", package_path, e)));
    let package: AttestationPackage = serde_json::from_slice(&package_json)
        .unwrap_or_else(|e| fatal(&format!("failed to parse package JSON: {}", e)));
    
    // Read binary
    let binary_bytes = std::fs::read(binary_path)
        .unwrap_or_else(|e| fatal(&format!("failed to read binary {}: {}", binary_path, e)));
    
    // Verify
    match verify_package(&package, &binary_bytes) {
        Ok(()) => {
            println!("ATTESTATION VALID");
            println!("Fingerprint: {}", package.fingerprint);
            std::process::exit(0);
        }
        Err(reason) => {
            println!("ATTESTATION INVALID: {}", reason);
            std::process::exit(1);
        }
    }
}

fn usage_error(msg: &str) -> ! {
    eprintln!("ERROR: {}", msg);
    eprintln!();
    usage();
    std::process::exit(2);
}

fn fatal(msg: &str) -> ! {
    eprintln!("FATAL: {}", msg);
    std::process::exit(1);
}
