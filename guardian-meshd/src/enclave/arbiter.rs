// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use super::{EnclaveContext, Verdict, ContainmentStage};
use crate::policy::PolicyEngine;

pub struct ArbiterEnclave;

impl ArbiterEnclave {
    pub fn evaluate(ctx: &mut EnclaveContext, policy: &PolicyEngine) {
        ctx.stage = ContainmentStage::Analyze;

        let action_type = ctx
            .request
            .action
            .as_ref()
            .map(|a| a.action_type.as_str())
            .unwrap_or("UNKNOWN");

        match policy.decide(action_type) {
            true => {
                ctx.verdict = Some(Verdict::Allow);
                ctx.reason = Some("Arbiter approved via policy engine".into());
            }
            false => {
                ctx.verdict = Some(Verdict::Block);
                ctx.reason = Some("Arbiter denied via policy engine".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{EvaluateRequest, ActionDescriptor};

    #[test]
    fn arbiter_allows_tool_call() {
        let req = EvaluateRequest {
            action: Some(ActionDescriptor {
                action_type: "TOOL_CALL".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut ctx = EnclaveContext::new(req);
        let policy = PolicyEngine::new();
        ArbiterEnclave::evaluate(&mut ctx, &policy);
        assert_eq!(ctx.verdict, Some(Verdict::Allow));
    }

    #[test]
    fn arbiter_blocks_code_execute() {
        let req = EvaluateRequest {
            action: Some(ActionDescriptor {
                action_type: "CODE_EXECUTE".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut ctx = EnclaveContext::new(req);
        let policy = PolicyEngine::new();
        ArbiterEnclave::evaluate(&mut ctx, &policy);
        assert_eq!(ctx.verdict, Some(Verdict::Block));
    }
}
