// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::Path;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub action_type: String,
    pub allow: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundle {
    pub version: u64,
    pub rules: Vec<PolicyRule>,
    pub escalate_actions: Vec<String>,
    pub prev_hash: String,
}

impl PolicyBundle {
    /// Compute the canonical string representation of this bundle.
    /// This format is deterministic and used for hashing and persistence.
    pub fn to_canonical_string(&self) -> String {
        let mut canonical = String::new();
        canonical.push_str("guardian-mesh-policy-v1\n");
        canonical.push_str(&format!("version={}\n", self.version));
        canonical.push_str(&format!("prev={}\n", self.prev_hash));
        
        // Sort rules by action_type ascending
        let mut sorted_rules = self.rules.clone();
        sorted_rules.sort_by(|a, b| a.action_type.cmp(&b.action_type));
        
        for rule in &sorted_rules {
            canonical.push_str(&format!("rule={}|{}|{}\n", 
                rule.action_type, 
                if rule.allow { "1" } else { "0" }, 
                rule.priority));
        }
        
        // Sort and deduplicate escalate actions
        let mut sorted_escalate = self.escalate_actions.clone();
        sorted_escalate.sort();
        sorted_escalate.dedup();
        
        for action in &sorted_escalate {
            canonical.push_str(&format!("esc={}\n", action));
        }
        
        canonical
    }
    
    /// Parse a canonical bundle string.
    pub fn from_canonical_str(s: &str) -> Result<Self, String> {
        let mut lines = s.lines();
        
        // Line 1: header
        if lines.next() != Some("guardian-mesh-policy-v1") {
            return Err("invalid bundle header".into());
        }
        
        // Line 2: version
        let version_line = lines.next().ok_or("missing version line")?;
        let version = version_line.strip_prefix("version=")
            .ok_or("invalid version format")?
            .parse::<u64>()
            .map_err(|_| "invalid version number")?;
        
        // Line 3: prev_hash
        let prev_line = lines.next().ok_or("missing prev line")?;
        let prev_hash = prev_line.strip_prefix("prev=")
            .ok_or("invalid prev format")?
            .to_string();
        
        let mut rules = Vec::new();
        let mut escalate_actions = Vec::new();
        
        for line in lines {
            if line.is_empty() {
                continue;
            }
            
            if let Some(rule_part) = line.strip_prefix("rule=") {
                let parts: Vec<&str> = rule_part.split('|').collect();
                if parts.len() != 3 {
                    return Err(format!("invalid rule format: {}", line));
                }
                rules.push(PolicyRule {
                    action_type: parts[0].to_string(),
                    allow: parts[1] == "1",
                    priority: parts[2].parse::<u32>()
                        .map_err(|_| format!("invalid priority: {}", parts[2]))?,
                });
            } else if let Some(esc_part) = line.strip_prefix("esc=") {
                escalate_actions.push(esc_part.to_string());
            } else {
                return Err(format!("unrecognized line: {}", line));
            }
        }
        
        let bundle = PolicyBundle {
            version,
            rules,
            escalate_actions,
            prev_hash,
        };
        
        bundle.validate()?;
        Ok(bundle)
    }
    
    /// Compute the SHA-256 content hash of this bundle.
    pub fn content_hash(&self) -> String {
        let canonical = self.to_canonical_string();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
    
    /// Validate this bundle (fail-closed).
    pub fn validate(&self) -> Result<(), String> {
        if self.version < 1 {
            return Err("version must be >= 1".into());
        }
        
        if self.rules.is_empty() {
            return Err("at least one rule is required".into());
        }
        
        let mut seen_actions = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.action_type.is_empty() {
                return Err("empty action_type not allowed".into());
            }
            if !Self::is_valid_action_name(&rule.action_type) {
                return Err(format!("invalid action_type characters: {}", rule.action_type));
            }
            if !seen_actions.insert(&rule.action_type) {
                return Err(format!("duplicate action_type: {}", rule.action_type));
            }
        }
        
        for action in &self.escalate_actions {
            if !Self::is_valid_action_name(action) {
                return Err(format!("invalid escalate action characters: {}", action));
            }
        }
        
        Ok(())
    }
    
    fn is_valid_action_name(s: &str) -> bool {
        if s.is_empty() || s.len() > 64 {
            return false;
        }
        s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }
}

pub struct PolicyEngine {
    bundle: PolicyBundle,
    overrides: HashMap<String, bool>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let escalate_actions = Vec::new();
        Self::with_escalate_actions(escalate_actions)
    }

    pub fn with_escalate_actions(escalate_actions: Vec<String>) -> Self {
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

        let mut rules = Vec::new();
        for (action_type, allow, priority) in defaults {
            rules.push(PolicyRule {
                action_type: action_type.to_string(),
                allow,
                priority,
            });
        }

        let bundle = PolicyBundle {
            version: 1,
            rules,
            escalate_actions,
            prev_hash: "genesis".to_string(),
        };

        Self {
            bundle,
            overrides: HashMap::new(),
        }
    }

    pub fn requires_escalation(&self, action_type: &str) -> bool {
        self.bundle.escalate_actions.iter().any(|a| a == action_type)
    }

    pub fn decide(&self, action_type: &str) -> bool {
        if let Some(&override_val) = self.overrides.get(action_type) {
            return override_val;
        }

        for rule in &self.bundle.rules {
            if rule.action_type == action_type {
                return rule.allow;
            }
        }
        false
    }

    pub fn set_override(&mut self, action_type: &str, allow: bool) {
        self.overrides.insert(action_type.to_string(), allow);
    }

    pub fn bundle(&self) -> &PolicyBundle {
        &self.bundle
    }

    pub fn policy_version(&self) -> u64 {
        self.bundle.version
    }

    pub fn content_hash(&self) -> String {
        self.bundle.content_hash()
    }

    pub fn validate_next(&self, bundle: &PolicyBundle) -> Result<(), String> {
        if bundle.version != self.bundle.version + 1 {
            return Err(format!(
                "expected version {}, got {}",
                self.bundle.version + 1,
                bundle.version
            ));
        }

        let current_hash = self.bundle.content_hash();
        if bundle.prev_hash != current_hash {
            return Err(format!(
                "prev_hash mismatch: expected {}, got {}",
                current_hash,
                bundle.prev_hash
            ));
        }

        bundle.validate()?;
        Ok(())
    }

    /// Apply a new bundle. Assumes validate_next has passed.
    /// Replaces rules and escalate_actions, and clears overrides.
    pub fn apply_bundle(&mut self, bundle: PolicyBundle) {
        self.bundle = bundle;
        self.overrides.clear();
    }

    /// Load a persisted policy bundle from the policy directory.
    /// Returns None if the file does not exist.
    /// Returns Err if the file exists but cannot be parsed (fail-closed).
    pub fn load_from_file(policy_dir: &Path) -> Result<Option<PolicyBundle>, String> {
        let policy_file = policy_dir.join("current_policy.txt");
        if !policy_file.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(&policy_file)
            .map_err(|e| format!("failed to read policy file: {}", e))?;

        let bundle = PolicyBundle::from_canonical_str(&contents)?;
        Ok(Some(bundle))
    }

    /// Persist a policy bundle to the policy directory atomically.
    /// Uses a temp file + rename to avoid torn writes.
    pub fn persist_bundle(bundle: &PolicyBundle, policy_dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(policy_dir)
            .map_err(|e| format!("failed to create policy directory: {}", e))?;

        let canonical = bundle.to_canonical_string();
        let policy_file = policy_dir.join("current_policy.txt");
        let temp_file = policy_dir.join("current_policy.txt.tmp");

        std::fs::write(&temp_file, canonical)
            .map_err(|e| format!("failed to write temp policy file: {}", e))?;

        std::fs::rename(&temp_file, &policy_file)
            .map_err(|e| format!("failed to rename policy file: {}", e))?;

        Ok(())
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

    // PolicyBundle tests
    #[test]
    fn canonical_bytes_deterministic_regardless_of_rule_order() {
        let rules1 = vec![
            PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 },
            PolicyRule { action_type: "CODE_EXECUTE".into(), allow: false, priority: 10 },
        ];
        let rules2 = vec![
            PolicyRule { action_type: "CODE_EXECUTE".into(), allow: false, priority: 10 },
            PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 },
        ];
        
        let bundle1 = PolicyBundle {
            version: 1,
            rules: rules1,
            escalate_actions: vec![],
            prev_hash: "genesis".into(),
        };
        
        let bundle2 = PolicyBundle {
            version: 1,
            rules: rules2,
            escalate_actions: vec![],
            prev_hash: "genesis".into(),
        };
        
        assert_eq!(bundle1.to_canonical_string(), bundle2.to_canonical_string());
        assert_eq!(bundle1.content_hash(), bundle2.content_hash());
    }

    #[test]
    fn hash_changes_when_rule_flips() {
        let bundle1 = PolicyBundle {
            version: 1,
            rules: vec![PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 }],
            escalate_actions: vec![],
            prev_hash: "genesis".into(),
        };
        
        let bundle2 = PolicyBundle {
            version: 1,
            rules: vec![PolicyRule { action_type: "TOOL_CALL".into(), allow: false, priority: 100 }],
            escalate_actions: vec![],
            prev_hash: "genesis".into(),
        };
        
        assert_ne!(bundle1.content_hash(), bundle2.content_hash());
    }

    #[test]
    fn canonical_round_trip() {
        let bundle = PolicyBundle {
            version: 42,
            rules: vec![
                PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 },
                PolicyRule { action_type: "CODE_EXECUTE".into(), allow: false, priority: 10 },
            ],
            escalate_actions: vec!["CODE_EXECUTE".into(), "AGENT_SPAWN".into()],
            prev_hash: "abc123".into(),
        };
        
        let canonical = bundle.to_canonical_string();
        let parsed = PolicyBundle::from_canonical_str(&canonical).unwrap();
        
        // Note: escalate_actions are sorted and deduplicated by canonicalization
        let mut expected_escalate = bundle.escalate_actions.clone();
        expected_escalate.sort();
        expected_escalate.dedup();
        
        assert_eq!(parsed.version, bundle.version);
        assert_eq!(parsed.prev_hash, bundle.prev_hash);
        
        // Rules are sorted by action_type in canonical form
        let mut expected_rules = bundle.rules.clone();
        expected_rules.sort_by(|a, b| a.action_type.cmp(&b.action_type));
        assert_eq!(parsed.rules, expected_rules);
        assert_eq!(parsed.escalate_actions, expected_escalate);
    }

    #[test]
    fn validate_next_rejects_wrong_version() {
        let engine = PolicyEngine::new();
        
        // Wrong: version jumps by 2
        let bundle = PolicyBundle {
            version: 3,
            rules: vec![PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 }],
            escalate_actions: vec![],
            prev_hash: engine.content_hash(),
        };
        assert!(engine.validate_next(&bundle).is_err());
        
        // Wrong: same version
        let bundle2 = PolicyBundle {
            version: 1,
            rules: vec![PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 }],
            escalate_actions: vec![],
            prev_hash: engine.content_hash(),
        };
        assert!(engine.validate_next(&bundle2).is_err());
    }

    #[test]
    fn validate_next_rejects_wrong_prev_hash() {
        let engine = PolicyEngine::new();
        
        let bundle = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 }],
            escalate_actions: vec![],
            prev_hash: "wrong_hash".into(),
        };
        
        assert!(engine.validate_next(&bundle).is_err());
    }

    #[test]
    fn validate_next_rejects_duplicate_action() {
        let engine = PolicyEngine::new();
        
        let bundle = PolicyBundle {
            version: 2,
            rules: vec![
                PolicyRule { action_type: "TOOL_CALL".into(), allow: true, priority: 100 },
                PolicyRule { action_type: "TOOL_CALL".into(), allow: false, priority: 10 },
            ],
            escalate_actions: vec![],
            prev_hash: engine.content_hash(),
        };
        
        assert!(engine.validate_next(&bundle).is_err());
    }

    #[test]
    fn validate_next_rejects_empty_action() {
        let engine = PolicyEngine::new();
        
        let bundle = PolicyBundle {
            version: 2,
            rules: vec![
                PolicyRule { action_type: "".into(), allow: true, priority: 100 },
            ],
            escalate_actions: vec![],
            prev_hash: engine.content_hash(),
        };
        
        assert!(engine.validate_next(&bundle).is_err());
    }

    #[test]
    fn validate_next_rejects_invalid_characters() {
        let engine = PolicyEngine::new();
        
        let bundle = PolicyBundle {
            version: 2,
            rules: vec![
                PolicyRule { action_type: "tool-call".into(), allow: true, priority: 100 },
            ],
            escalate_actions: vec![],
            prev_hash: engine.content_hash(),
        };
        
        assert!(engine.validate_next(&bundle).is_err());
    }

    #[test]
    fn validate_next_rejects_zero_rules() {
        let engine = PolicyEngine::new();
        
        let bundle = PolicyBundle {
            version: 2,
            rules: vec![],
            escalate_actions: vec![],
            prev_hash: engine.content_hash(),
        };
        
        assert!(engine.validate_next(&bundle).is_err());
    }

    #[test]
    fn apply_bundle_replaces_rules_and_clears_overrides() {
        let mut engine = PolicyEngine::new();
        
        // Set an override
        engine.set_override("CODE_EXECUTE", true);
        assert!(engine.decide("CODE_EXECUTE"));
        
        // Apply a new bundle
        let new_bundle = PolicyBundle {
            version: 2,
            rules: vec![
                PolicyRule { action_type: "TOOL_CALL".into(), allow: false, priority: 100 },
            ],
            escalate_actions: vec![],
            prev_hash: engine.content_hash(),
        };
        
        engine.apply_bundle(new_bundle);
        
        // Override should be cleared
        assert!(!engine.decide("CODE_EXECUTE")); // Unknown action returns false
        assert!(!engine.decide("TOOL_CALL")); // New rule applies
        assert_eq!(engine.policy_version(), 2);
    }
}
