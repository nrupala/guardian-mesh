// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

pub mod sentinel;
pub mod gatekeeper;
pub mod witness;
pub mod arbiter;
pub mod vault;

use crate::proto::EvaluateRequest;

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Allow,
    Block,
    Throttle,
    Escalate,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Block => "BLOCK",
            Self::Throttle => "THROTTLE",
            Self::Escalate => "ESCALATE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContainmentStage {
    Normal,
    Detect,
    Warn,
    Throttle,
    Isolate,
    Analyze,
    Terminate,
}

impl ContainmentStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Detect => "DETECT",
            Self::Warn => "WARN",
            Self::Throttle => "THROTTLE",
            Self::Isolate => "ISOLATE",
            Self::Analyze => "ANALYZE",
            Self::Terminate => "TERMINATE",
        }
    }
}

pub struct EnclaveContext {
    pub request: EvaluateRequest,
    pub stage: ContainmentStage,
    pub verdict: Option<Verdict>,
    pub reason: Option<String>,
    pub witness_signature: Vec<u8>,
}

impl EnclaveContext {
    pub fn new(request: EvaluateRequest) -> Self {
        Self {
            request,
            stage: ContainmentStage::Normal,
            verdict: None,
            reason: None,
            witness_signature: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::EvaluateRequest;

    #[test]
    fn enclave_context_default_state() {
        let ctx = EnclaveContext::new(EvaluateRequest::default());
        assert_eq!(ctx.stage, ContainmentStage::Normal);
        assert!(ctx.verdict.is_none());
        assert!(ctx.reason.is_none());
        assert!(ctx.witness_signature.is_empty());
    }

    #[test]
    fn verdict_as_str() {
        assert_eq!(Verdict::Allow.as_str(), "ALLOW");
        assert_eq!(Verdict::Block.as_str(), "BLOCK");
        assert_eq!(Verdict::Throttle.as_str(), "THROTTLE");
        assert_eq!(Verdict::Escalate.as_str(), "ESCALATE");
    }

    #[test]
    fn containment_stage_as_str() {
        assert_eq!(ContainmentStage::Normal.as_str(), "NORMAL");
        assert_eq!(ContainmentStage::Terminate.as_str(), "TERMINATE");
    }
}
