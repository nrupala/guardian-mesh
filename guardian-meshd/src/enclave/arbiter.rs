// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use super::{EnclaveContext, Verdict, ContainmentStage, ReasonDetail};
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

        // WO-5: Precedence order — BLOCK takes priority, then ESCALATE, then policy decision
        let is_blocked = !policy.decide(action_type);
        let requires_escalation = policy.requires_escalation(action_type);

        if is_blocked {
            // Blocked actions stay blocked even if on escalate list
            ctx.verdict = Some(Verdict::Block);
            let reason = "Arbiter denied via policy engine".to_string();
            ctx.reason = Some(reason.clone());
            ctx.structured_reasons.push(ReasonDetail {
                rule_id: "POLICY".to_string(),
                detail: reason,
                remediation: "Use an action type the current policy allows, or have the policy changed by its owner.".to_string(),
            });
        } else if requires_escalation {
            // Action is allowed by policy but requires human decision
            ctx.verdict = Some(Verdict::Escalate);
            let reason = format!("Action type '{}' requires human escalation per policy", action_type);
            ctx.reason = Some(reason.clone());
            ctx.structured_reasons.push(ReasonDetail {
                rule_id: "POLICY_ESCALATION".to_string(),
                detail: reason,
                remediation: "Obtain a human approval for this action type, or choose a different action.".to_string(),
            });
        } else {
            // Action is allowed and does not require escalation
            ctx.verdict = Some(Verdict::Allow);
            let reason = "Arbiter approved via policy engine".to_string();
            ctx.reason = Some(reason.clone());
            ctx.structured_reasons.push(ReasonDetail {
                rule_id: "POLICY".to_string(),
                detail: reason,
                remediation: "".to_string(),
            });
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
