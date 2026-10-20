// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

pub mod protocol_firewall;
pub mod sealed_envelope;
pub mod handshake_bus;
pub mod enclave;
pub mod policy;
pub mod config;
pub mod certificate;

pub mod proto {
    tonic::include_proto!("guardian_mesh");
}
