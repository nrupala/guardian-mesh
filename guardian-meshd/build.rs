// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&["proto/guardian_mesh.proto"], &["proto"])?;
    Ok(())
}
