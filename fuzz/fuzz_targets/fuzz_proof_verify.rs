// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Fixed verifying key for this fuzzer, generated once per process from a fixed seed
static VERIFYING_KEY: OnceLock<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> = OnceLock::new();

fn get_verifying_key() -> &'static ml_dsa::VerifyingKey<ml_dsa::MlDsa65> {
    VERIFYING_KEY.get_or_init(|| {
        // Fixed 32-byte seed for reproducible key generation
        let seed_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice())
            .expect("32 bytes fits Seed");
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
        sk.verifying_key()
    })
}

// Fuzz target: proof verification
// Splits the input as: first 4 bytes = CRC32C digest (little-endian),
// next up to 3500 bytes = signature, remainder = payload.
// Calls verify_proto_envelope with the fixed key.
// Also attempts to decode the whole input as a verifying key, and if successful,
// retries verification against that attacker-controlled key.
// Panics are bugs; errors are healthy.

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return; // Need at least 4 bytes for CRC
    }
    
    // Split input: first 4 bytes = CRC32C (little-endian)
    let crc_bytes = &data[0..4];
    let crc = u32::from_le_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
    
    // Next up to 3500 bytes = signature
    let sig_end = std::cmp::min(4 + 3500, data.len());
    let signature = &data[4..sig_end];
    
    // Remainder = payload
    let payload = if sig_end < data.len() {
        &data[sig_end..]
    } else {
        &[]
    };
    
    // Verify against the fixed key
    let vk = get_verifying_key();
    let _ = guardian_meshd::sealed_envelope::verify_proto_envelope(
        payload,
        crc,
        signature,
        vk,
    );
    
    // Also attempt to decode the whole input as a verifying key
    if let Ok(attacker_vk) = guardian_meshd::sealed_envelope::verifying_key_from_bytes(data) {
        // If it decodes, retry verification against this attacker key
        let _ = guardian_meshd::sealed_envelope::verify_proto_envelope(
            payload,
            crc,
            signature,
            &attacker_vk,
        );
    }
    
    // All operations may return errors but must never panic
});
