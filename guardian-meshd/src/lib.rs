// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod protocol_firewall;
pub mod sealed_envelope;
pub mod handshake_bus;
pub mod enclave;
pub mod policy;
pub mod config;

pub mod proto {
    tonic::include_proto!("guardian_mesh");
}
