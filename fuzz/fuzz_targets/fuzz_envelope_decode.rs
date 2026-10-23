// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

// Fuzz target: envelope decoding
// Attempts to decode the input as an EvaluateRequest protobuf, then
// passes the decoded payload through ProtocolFirewall::check_envelope_size.
// Panics are bugs; decode errors are expected.

fuzz_target!(|data: &[u8]| {
    // Attempt to decode as EvaluateRequest (the envelope-bearing request type
    // exposed by guardian_meshd::proto)
    if let Ok(req) = guardian_meshd::proto::EvaluateRequest::decode(data) {
        // On successful decode, extract the payload from the envelope if present
        if let Some(firewalled) = req.firewalled {
            if let Some(envelope) = firewalled.envelope {
                // Feed the payload through the firewall size check
                // Errors are healthy; panics are bugs
                let _ = guardian_meshd::protocol_firewall::ProtocolFirewall::check_envelope_size(&envelope.payload);
            }
        }
    }
    // Decode errors are the expected, healthy outcome for malformed input
});
