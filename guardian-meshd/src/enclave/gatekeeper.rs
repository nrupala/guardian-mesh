// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use super::{EnclaveContext, Verdict, ContainmentStage};
use crate::handshake_bus::HandshakeBus;
use crate::protocol_firewall::{ProtocolFirewall, ThrottleReason};
use crate::sealed_envelope::{verify_proto_envelope, verifying_key_from_bytes};

pub struct GatekeeperEnclave;

impl GatekeeperEnclave {
    pub fn evaluate(ctx: &mut EnclaveContext, bus: &HandshakeBus, firewall: &ProtocolFirewall, policy_throttle_rate: usize) {
        ctx.stage = ContainmentStage::Warn;

        let firewalled = match &ctx.request.firewalled {
            Some(f) => f,
            None => {
                ctx.verdict = Some(Verdict::Block);
                ctx.reason = Some("Missing firewalled request".into());
                return;
            }
        };

        if !bus.session_exists(&firewalled.handshake_session) {
            // WO-19: evict firewall state for expired/unknown sessions before blocking
            firewall.evict_session(&firewalled.handshake_session);
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some("Invalid or expired handshake session".into());
            return;
        }

        let payload = firewalled.envelope.as_ref()
            .map(|e| e.payload.as_slice())
            .unwrap_or(&[]);

        let hmac_ok = bus
            .verify_hmac(
                &firewalled.handshake_session,
                payload,
                &firewalled.hmac_tag,
            )
            .unwrap_or(false);

        if !hmac_ok {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some("HMAC tag mismatch in Gatekeeper".into());
            return;
        }

        // WO-2: Protocol Firewall enforcement on client envelopes.
        // Apply PF rules in order; first failure blocks.
        
        let envelope = match firewalled.envelope.as_ref() {
            Some(e) => e,
            None => {
                ctx.verdict = Some(Verdict::Block);
                ctx.reason = Some("Missing envelope for Protocol Firewall checks".into());
                return;
            }
        };

        // PF-1/PF-5: Envelope/payload size bounds (64 KiB)
        let size_result = ProtocolFirewall::check_envelope_size(&envelope.payload);
        firewall.record_rule("PF-1", size_result.is_ok());
        if let Err(reason) = size_result {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(reason);
            return;
        }

        // PF-12: Reject unknown fields in ActionDescriptor JSON
        let unknown_fields_result = ProtocolFirewall::check_unknown_fields(&envelope.payload);
        firewall.record_rule("PF-12", unknown_fields_result.is_ok());
        if let Err(reason) = unknown_fields_result {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(reason);
            return;
        }

        // PF-13: Nesting depth max 4
        let nesting_result = ProtocolFirewall::check_nesting_depth(&envelope.payload);
        firewall.record_rule("PF-13", nesting_result.is_ok());
        if let Err(reason) = nesting_result {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(reason);
            return;
        }

        // PF-14: Nonce uniqueness (sliding window)
        if let Err(reason) = firewall.check_nonce_uniqueness(&firewalled.handshake_session, &envelope.nonce) {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(reason);
            return;
        }

        // PF-15/PF-16: Timestamp windows (stale > 5s, future > 1s)
        // The client sends timestamp as unix NANOSECONDS (u64)
        let timestamp_result = ProtocolFirewall::check_timestamp_windows(envelope.timestamp);
        // Record: on Ok record pass for BOTH PF-15 and PF-16; on Err record fail for the rule named in the error
        match &timestamp_result {
            Ok(()) => {
                firewall.record_rule("PF-15", true);
                firewall.record_rule("PF-16", true);
            }
            Err(reason) => {
                // Parse the prefix before the first space to identify the rule
                let rule = if reason.starts_with("PF-15") {
                    "PF-15"
                } else if reason.starts_with("PF-16") {
                    "PF-16"
                } else {
                    "PF-15" // fallback if neither
                };
                firewall.record_rule(rule, false);
            }
        }
        if let Err(reason) = timestamp_result {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(reason);
            return;
        }

        // PF-17: Signature format budget
        let sig_format_result = ProtocolFirewall::check_signature_format(&envelope.ml_dsa_65_signature);
        firewall.record_rule("PF-17", sig_format_result.is_ok());
        if let Err(reason) = sig_format_result {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(reason);
            return;
        }

        // WO-5: Policy-configured per-session rate limit (checked first)
        if let Ok(Some(throttle_reason)) = firewall.check_policy_rate(&firewalled.handshake_session, policy_throttle_rate) {
            ctx.verdict = Some(Verdict::Throttle);
            ctx.reason = Some(match throttle_reason {
                ThrottleReason::ProtocolFirewall => "PF-18 rate limit breach: E_RATE_LIMITED".to_string(),
                ThrottleReason::PolicyRate => "Policy rate limit breach".to_string(),
            });
            return;
        }

        // PF-18: Rate limit (100 msg/s per external session)
        // WO-5: PF-18 breach now returns THROTTLE verdict instead of permission_denied error
        if let Ok(Some(throttle_reason)) = firewall.check_rate_limit(&firewalled.handshake_session) {
            ctx.verdict = Some(Verdict::Throttle);
            ctx.reason = Some(match throttle_reason {
                ThrottleReason::ProtocolFirewall => "PF-18 rate limit breach: E_RATE_LIMITED".to_string(),
                ThrottleReason::PolicyRate => "Policy rate limit breach".to_string(),
            });
            return;
        }

        // WO-1: the HMAC proves the caller holds the session key; it
        // does not prove the envelope was signed by the caller who
        // opened the session. Verify the envelope's ML-DSA-65
        // signature against the public key bound to the session at
        // Handshake time. Every failure mode — no key bound, a
        // malformed bound key, a missing/malformed signature, or a
        // signature that does not verify — blocks here, so the
        // evaluation never reaches the Arbiter unauthenticated.
        if let Err(reason) = verify_request_signature(firewalled, bus) {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(reason);
            return;
        }

        ctx.verdict = Some(Verdict::Allow);
        ctx.reason = Some("Gatekeeper passed (Protocol Firewall + HMAC + signature verified)".into());
    }
}

/// Verify the firewalled envelope's ML-DSA-65 signature against the
/// public key bound to its handshake session. The returned error is
/// a plain reason naming the signature failure; the caller blocks.
fn verify_request_signature(
    firewalled: &crate::proto::FirewalledRequest,
    bus: &HandshakeBus,
) -> Result<(), String> {
    let envelope = firewalled.envelope.as_ref().ok_or_else(|| {
        "Request signature verification failed: missing sealed envelope".to_string()
    })?;

    let bound_key = bus
        .session_public_key(&firewalled.handshake_session)
        .ok_or_else(|| {
            "Request signature verification failed: no ML-DSA-65 public key is bound to this session"
                .to_string()
        })?;

    let verifying_key = verifying_key_from_bytes(&bound_key).map_err(|e| {
        format!("Request signature verification failed: bound session key is malformed ({})", e)
    })?;

    verify_proto_envelope(
        &envelope.payload,
        envelope.crc32c,
        &envelope.ml_dsa_65_signature,
        &verifying_key,
    )
    .map_err(|e| format!("Request signature verification failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_firewall::ProtocolFirewall;
    use crate::proto::{
        ActionDescriptor, EvaluateRequest, FirewalledRequest,
        SealedEnvelope as ProtoSealedEnvelope,
    };
    use crate::sealed_envelope::{generate_keypair, SealedEnvelope};

    // WO-2: PF-12 enforces the exact field set the shipped client uses (webui/src/lib/gmClient.ts).
    // The client sends: actionType, context, target, metadata (all camelCase).
    const PAYLOAD: &[u8] = b"{\"actionType\":\"TOOL_CALL\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{}}";

    fn proto_envelope(sealed: &SealedEnvelope) -> ProtoSealedEnvelope {
        ProtoSealedEnvelope {
            payload: sealed.payload.clone(),
            payload_type: sealed.payload_type.clone(),
            crc32c: sealed.crc32c_digest,
            ml_dsa_65_signature: sealed.ml_dsa_65_signature.clone(),
            timestamp: sealed.timestamp,
            nonce: sealed.nonce.to_vec(),
        }
    }

    fn ctx_for(bus: &HandshakeBus, session_id: &str, envelope: ProtoSealedEnvelope) -> EnclaveContext {
        // HMAC is computed over the envelope payload exactly as sent,
        // so signature failures below are never HMAC failures.
        let hmac_tag = bus
            .compute_hmac(session_id, &envelope.payload)
            .unwrap();
        let req = EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope),
                source_enclave: "webui".into(),
                handshake_session: session_id.to_string(),
                hmac_tag,
            }),
            action: Some(ActionDescriptor {
                action_type: "TOOL_CALL".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
        };
        EnclaveContext::new(req)
    }

    fn session_with_key(bus: &HandshakeBus, vk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65>) -> String {
        bus.create_session_full("webui", &vk.encode()).session_id
    }

    fn assert_signature_block(ctx: &EnclaveContext) {
        assert_eq!(ctx.verdict, Some(Verdict::Block));
        let reason = ctx.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("signature"),
            "block reason must name the signature failure, got: {}",
            reason
        );
    }

    #[test]
    fn valid_signature_passes_gatekeeper() {
        let (sk, vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let firewall = ProtocolFirewall::new();
        let sid = session_with_key(&bus, &vk);
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus, &firewall, 100);
        assert_eq!(ctx.verdict, Some(Verdict::Allow));
    }

    #[test]
    fn tampered_payload_is_denied() {
        let (sk, vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let firewall = ProtocolFirewall::new();
        let sid = session_with_key(&bus, &vk);
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        // Payload replaced after signing; CRC refreshed so the
        // integrity check passes and only the signature can fail.
        sealed.payload = b"{\"actionType\":\"CODE_EXECUTE\",\"context\":\"x\",\"target\":\"y\",\"metadata\":{}}".to_vec();
        sealed.crc32c_digest = crc32c::crc32c(&sealed.payload);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus, &firewall, 100);
        assert_signature_block(&ctx);
    }

    #[test]
    fn signature_from_a_different_key_is_denied() {
        let (_sk_bound, vk_bound) = generate_keypair();
        let (sk_other, _vk_other) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let firewall = ProtocolFirewall::new();
        let sid = session_with_key(&bus, &vk_bound);
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk_other);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus, &firewall, 100);
        assert_signature_block(&ctx);
    }

    #[test]
    fn missing_signature_is_denied() {
        let (sk, vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let firewall = ProtocolFirewall::new();
        let sid = session_with_key(&bus, &vk);
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        sealed.ml_dsa_65_signature = Vec::new();
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus, &firewall, 100);
        assert_signature_block(&ctx);
    }

    #[test]
    fn garbage_signature_is_denied() {
        let (sk, vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let firewall = ProtocolFirewall::new();
        let sid = session_with_key(&bus, &vk);
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        sealed.ml_dsa_65_signature = vec![0xAB; 3309];
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus, &firewall, 100);
        assert_signature_block(&ctx);
    }

    #[test]
    fn session_without_bound_key_is_denied() {
        let (sk, _vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let firewall = ProtocolFirewall::new();
        // Legacy session created without registering a public key.
        let sid = bus.create_session("webui");
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus, &firewall, 100);
        assert_signature_block(&ctx);
    }

    // WO-19: Dead-session eviction test
    #[test]
    fn dead_session_evicts_firewall_state() {
        let (sk, _vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let firewall = ProtocolFirewall::new();
        
        let session_id = "dead_session_id";
        
        // Seed the firewall with nonce state for this session
        firewall.check_nonce_uniqueness(session_id, b"test_nonce").unwrap();
        assert_eq!(firewall.session_count(), 1);
        
        // Create a request with NO bus session (dead/expired)
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let envelope = proto_envelope(&sealed);
        
        // Build request manually without computing HMAC (dead session)
        let req = EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope),
                source_enclave: "webui".into(),
                handshake_session: session_id.to_string(),
                hmac_tag: vec![0u8; 32], // Dummy HMAC
            }),
            action: Some(ActionDescriptor {
                action_type: "TOOL_CALL".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
        };
        let mut ctx = EnclaveContext::new(req);
        
        GatekeeperEnclave::evaluate(&mut ctx, &bus, &firewall, 100);
        
        // Verdict should be Block with invalid session reason
        assert_eq!(ctx.verdict, Some(Verdict::Block));
        let reason = ctx.reason.clone().unwrap_or_default();
        assert!(reason.contains("Invalid") || reason.contains("expired"));
        
        // The firewall's session_count for that ID should be gone
        assert_eq!(firewall.session_count(), 0);
        
        // The same nonce should be accepted again on a fresh check
        assert!(firewall.check_nonce_uniqueness(session_id, b"test_nonce").is_ok());
    }
}
