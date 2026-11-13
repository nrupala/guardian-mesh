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

        // Content rules (payload-shaped policy, e.g. DCR-REDIRECT-FRAGMENT)
        // rank with BLOCK: below a type-level policy block, above
        // escalation and allow.
        let content_block = if is_blocked {
            None
        } else {
            ctx.request
                .action
                .as_ref()
                .and_then(|action| policy.check_content_rules(action))
        };

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
        } else if let Some(block) = content_block {
            // Payload violates a content rule: BLOCK, with the rule
            // named in the reason the Witness seals into the proof.
            ctx.verdict = Some(Verdict::Block);
            ctx.reason = Some(block.detail.clone());
            ctx.structured_reasons.push(block);
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

    fn dcr_request(action_type: &str, context: &str) -> EvaluateRequest {
        EvaluateRequest {
            action: Some(ActionDescriptor {
                action_type: action_type.into(),
                context: context.into(),
                target: "https://conduit.example/oauth/register".into(),
                metadata: Default::default(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn arbiter_blocks_dcr_fragment_with_the_rule_named() {
        let req = dcr_request(
            "NETWORK_REQUEST",
            r#"{"client_name":"Proof Client","redirect_uris":["https://client.example/callback#frag"]}"#,
        );
        let mut ctx = EnclaveContext::new(req);
        let policy = PolicyEngine::new();
        ArbiterEnclave::evaluate(&mut ctx, &policy);
        assert_eq!(ctx.verdict, Some(Verdict::Block));
        let reason = ctx.reason.clone().unwrap_or_default();
        assert!(
            reason.contains(crate::policy::DCR_REDIRECT_FRAGMENT_RULE),
            "verdict reason must name the blocking rule, got: {reason}"
        );
        assert!(ctx
            .structured_reasons
            .iter()
            .any(|r| r.rule_id == crate::policy::DCR_REDIRECT_FRAGMENT_RULE));
    }

    #[test]
    fn arbiter_allows_clean_dcr_registration() {
        let req = dcr_request(
            "NETWORK_REQUEST",
            r#"{"client_name":"Proof Client","redirect_uris":["https://client.example/callback"]}"#,
        );
        let mut ctx = EnclaveContext::new(req);
        let policy = PolicyEngine::new();
        ArbiterEnclave::evaluate(&mut ctx, &policy);
        assert_eq!(ctx.verdict, Some(Verdict::Allow));
    }

    #[test]
    fn arbiter_policy_block_keeps_precedence_over_content_rule() {
        // A type-level policy block keeps its own reason even when the
        // payload would also violate the content rule.
        let req = dcr_request(
            "CODE_EXECUTE",
            r#"{"redirect_uris":["https://client.example/callback#frag"]}"#,
        );
        let mut ctx = EnclaveContext::new(req);
        let policy = PolicyEngine::new();
        ArbiterEnclave::evaluate(&mut ctx, &policy);
        assert_eq!(ctx.verdict, Some(Verdict::Block));
        assert!(ctx.structured_reasons.iter().any(|r| r.rule_id == "POLICY"));
        assert!(!ctx
            .structured_reasons
            .iter()
            .any(|r| r.rule_id == crate::policy::DCR_REDIRECT_FRAGMENT_RULE));
    }

    #[test]
    fn arbiter_ignores_fragment_in_non_registration_payload() {
        let req = dcr_request("TOOL_CALL", "summarize document #42");
        let mut ctx = EnclaveContext::new(req);
        let policy = PolicyEngine::new();
        ArbiterEnclave::evaluate(&mut ctx, &policy);
        assert_eq!(ctx.verdict, Some(Verdict::Allow));
    }
}
