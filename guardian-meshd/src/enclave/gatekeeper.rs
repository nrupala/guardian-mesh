// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{EnclaveContext, Verdict, ContainmentStage};
use crate::handshake_bus::HandshakeBus;
use crate::sealed_envelope::{verify_proto_envelope, verifying_key_from_bytes};

pub struct GatekeeperEnclave;

impl GatekeeperEnclave {
    pub fn evaluate(ctx: &mut EnclaveContext, bus: &HandshakeBus) {
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
        ctx.reason = Some("Gatekeeper passed (HMAC + request signature verified)".into());
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
    use crate::proto::{
        ActionDescriptor, EvaluateRequest, FirewalledRequest,
        SealedEnvelope as ProtoSealedEnvelope,
    };
    use crate::sealed_envelope::{generate_keypair, SealedEnvelope};

    const PAYLOAD: &[u8] = b"{\"action_type\":\"TOOL_CALL\"}";

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
        let sid = session_with_key(&bus, &vk);
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus);
        assert_eq!(ctx.verdict, Some(Verdict::Allow));
    }

    #[test]
    fn tampered_payload_is_denied() {
        let (sk, vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let sid = session_with_key(&bus, &vk);
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        // Payload replaced after signing; CRC refreshed so the
        // integrity check passes and only the signature can fail.
        sealed.payload = b"{\"action_type\":\"CODE_EXECUTE\"}".to_vec();
        sealed.crc32c_digest = crc32c::crc32c(&sealed.payload);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus);
        assert_signature_block(&ctx);
    }

    #[test]
    fn signature_from_a_different_key_is_denied() {
        let (_sk_bound, vk_bound) = generate_keypair();
        let (sk_other, _vk_other) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let sid = session_with_key(&bus, &vk_bound);
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk_other);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus);
        assert_signature_block(&ctx);
    }

    #[test]
    fn missing_signature_is_denied() {
        let (sk, vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let sid = session_with_key(&bus, &vk);
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        sealed.ml_dsa_65_signature = Vec::new();
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus);
        assert_signature_block(&ctx);
    }

    #[test]
    fn garbage_signature_is_denied() {
        let (sk, vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        let sid = session_with_key(&bus, &vk);
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        sealed.ml_dsa_65_signature = vec![0xAB; 3309];
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus);
        assert_signature_block(&ctx);
    }

    #[test]
    fn session_without_bound_key_is_denied() {
        let (sk, _vk) = generate_keypair();
        let bus = HandshakeBus::new(b"test-secret");
        // Legacy session created without registering a public key.
        let sid = bus.create_session("webui");
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let mut ctx = ctx_for(&bus, &sid, proto_envelope(&sealed));
        GatekeeperEnclave::evaluate(&mut ctx, &bus);
        assert_signature_block(&ctx);
    }
}
