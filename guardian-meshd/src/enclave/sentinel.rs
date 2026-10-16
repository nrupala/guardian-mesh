// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use super::{EnclaveContext, Verdict, ContainmentStage};

pub struct SentinelEnclave;

impl SentinelEnclave {
    pub fn evaluate(ctx: &mut EnclaveContext) {
        ctx.stage = ContainmentStage::Detect;

        // The Sentinel is for behavioral observation and anomaly
        // detection. Protocol Firewall enforcement (PF-1..PF-18) is
        // the Gatekeeper's responsibility per WO-2. The Sentinel
        // currently passes all requests through — real behavioral
        // checks (jailbreak patterns, exfiltration signals, drift
        // detection) are future work orders.

        ctx.verdict = Some(Verdict::Allow);
        ctx.reason = Some("Sentinel observation passed, forwarding to Gatekeeper".into());
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
