// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target: payload parsing through the Protocol Firewall
// Feeds raw input to ProtocolFirewall::check_envelope_size,
// check_unknown_fields, and check_nesting_depth.
// Panics are bugs; errors are healthy.

fuzz_target!(|data: &[u8]| {
    // PF-1/PF-5: Envelope size check
    let _ = guardian_meshd::protocol_firewall::ProtocolFirewall::check_envelope_size(data);
    
    // PF-12: Unknown fields check (requires valid JSON)
    let _ = guardian_meshd::protocol_firewall::ProtocolFirewall::check_unknown_fields(data);
    
    // PF-13: Nesting depth check (requires valid JSON)
    let _ = guardian_meshd::protocol_firewall::ProtocolFirewall::check_nesting_depth(data);
    
    // All three checks may return errors (parse failures, validation failures)
    // but must never panic.
});
