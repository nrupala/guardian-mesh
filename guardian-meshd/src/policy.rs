// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub action_type: String,
    pub allow: bool,
    pub priority: u32,
}

pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    overrides: HashMap<String, bool>,
    escalate_actions: Vec<String>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            overrides: HashMap::new(),
            escalate_actions: Vec::new(),
        };
        engine.load_defaults();
        engine
    }

    pub fn with_escalate_actions(escalate_actions: Vec<String>) -> Self {
        let mut engine = Self::new();
        engine.escalate_actions = escalate_actions;
        engine
    }

    pub fn requires_escalation(&self, action_type: &str) -> bool {
        self.escalate_actions.iter().any(|a| a == action_type)
    }

    fn load_defaults(&mut self) {
        let defaults = vec![
            ("TOOL_CALL", true, 100),
            ("CODE_EXECUTE", false, 10),
            ("NETWORK_REQUEST", true, 50),
            ("FILE_WRITE", true, 50),
            ("FILE_READ", true, 60),
            ("MEMORY_WRITE", true, 70),
            ("MEMORY_READ", true, 80),
            ("AGENT_SPAWN", false, 20),
            ("AGENT_MESSAGE", true, 90),
            ("GENERATE", true, 100),
            ("MODEL_LOAD", true, 50),
        ];

        for (action_type, allow, priority) in defaults {
            self.rules.push(PolicyRule {
                action_type: action_type.to_string(),
                allow,
                priority,
            });
        }
    }

    pub fn decide(&self, action_type: &str) -> bool {
        if let Some(&override_val) = self.overrides.get(action_type) {
            return override_val;
        }

        for rule in &self.rules {
            if rule.action_type == action_type {
                return rule.allow;
            }
        }
        false
    }

    pub fn set_override(&mut self, action_type: &str, allow: bool) {
        self.overrides.insert(action_type.to_string(), allow);
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_allow_tool_call() {
        let engine = PolicyEngine::new();
        assert!(engine.decide("TOOL_CALL"));
    }

    #[test]
    fn defaults_block_code_execute() {
        let engine = PolicyEngine::new();
        assert!(!engine.decide("CODE_EXECUTE"));
    }

    #[test]
    fn unknown_action_blocked() {
        let engine = PolicyEngine::new();
        assert!(!engine.decide("UNKNOWN_ACTION"));
    }

    #[test]
    fn override_allows_blocked_action() {
        let mut engine = PolicyEngine::new();
        assert!(!engine.decide("CODE_EXECUTE"));
        engine.set_override("CODE_EXECUTE", true);
        assert!(engine.decide("CODE_EXECUTE"));
    }

    #[test]
    fn override_blocks_allowed_action() {
        let mut engine = PolicyEngine::new();
        assert!(engine.decide("GENERATE"));
        engine.set_override("GENERATE", false);
        assert!(!engine.decide("GENERATE"));
    }
}
