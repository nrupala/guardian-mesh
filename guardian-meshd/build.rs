// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&["proto/guardian_mesh.proto"], &["proto"])?;

    // Emit GM_GIT_COMMIT: from env GUARDIAN_MESH_GIT_COMMIT if set,
    // else from git rev-parse HEAD, else "unknown".
    let git_commit = std::env::var("GUARDIAN_MESH_GIT_COMMIT")
        .unwrap_or_else(|_| {
            Command::new("git")
                .args(&["rev-parse", "HEAD"])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "unknown".to_string())
        });
    println!("cargo:rustc-env=GM_GIT_COMMIT={}", git_commit);

    // Emit GM_SOURCE_DATE_EPOCH: from env SOURCE_DATE_EPOCH if set, else "0".
    let source_date_epoch = std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=GM_SOURCE_DATE_EPOCH={}", source_date_epoch);

    // Rerun if these env vars change.
    println!("cargo:rerun-if-env-changed=GUARDIAN_MESH_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    Ok(())
}
