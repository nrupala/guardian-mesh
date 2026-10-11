// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{EnclaveContext, Verdict, ContainmentStage};
use crate::protocol_firewall::ProtocolFirewall;

pub struct SentinelEnclave;

impl SentinelEnclave {
    pub fn evaluate(ctx: &mut EnclaveContext) {
        ctx.stage = ContainmentStage::Detect;

        let payload = ctx.request.firewalled.as_ref()
            .and_then(|f| f.envelope.as_ref())
            .map(|e| e.payload.as_slice())
            .unwrap_or(&[]);

        let context = ctx.request.action.as_ref()
            .map(|a| a.context.as_str())
            .unwrap_or("");

        let target = ctx.request.action.as_ref()
            .map(|a| a.target.as_str())
            .unwrap_or("");

        let report = ProtocolFirewall::run_full_check(
            payload, 0, context, target,
        );

        if !report.rules_failed.is_empty() {
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(format!(
                "Protocol Firewall blocked: {:?}",
                report.rules_failed
            ));
            return;
        }

        ctx.verdict = Some(Verdict::Allow);
        ctx.reason = Some("PF rules passed, forwarding to Gatekeeper".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{EvaluateRequest, ActionDescriptor, FirewalledRequest, SealedEnvelope};

    #[test]
    fn sentinel_allows_clean_request() {
        let envelope = SealedEnvelope {
            payload: b"valid payload".to_vec(),
            ..Default::default()
        };
        let req = EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope),
                ..Default::default()
            }),
            action: Some(ActionDescriptor {
                action_type: "TOOL_CALL".into(),
                context: "test".into(),
                target: "safe".into(),
                metadata: Default::default(),
            }),
        };
        let mut ctx = EnclaveContext::new(req);
        SentinelEnclave::evaluate(&mut ctx);
        assert_eq!(ctx.verdict, Some(Verdict::Allow));
    }
}
