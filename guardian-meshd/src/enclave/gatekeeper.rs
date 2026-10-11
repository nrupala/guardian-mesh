// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{EnclaveContext, Verdict, ContainmentStage};
use crate::handshake_bus::HandshakeBus;

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

        ctx.verdict = Some(Verdict::Allow);
        ctx.reason = Some("Gatekeeper passed (HMAC verified)".into());
    }
}
