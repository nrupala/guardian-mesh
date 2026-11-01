// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashMap};
use sha2::{Sha256, Digest};
use crate::policy::PolicyBundle;

pub const DEFAULT_TENANT: &str = "default";

/// Validates a tenant ID according to the specification:
/// 1..=64 chars; first char ASCII lowercase alnum; remaining chars ASCII lowercase alnum, `-`, or `_`.
pub fn validate_tenant_id(id: &str) -> Result<String, String> {
    if id.is_empty() {
        return Err("tenant id cannot be empty".to_string());
    }
    if id.len() > 64 {
        return Err(format!("tenant id too long: {} chars (max 64)", id.len()));
    }
    
    let mut chars = id.chars();
    let first = chars.next().unwrap();
    
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(format!("tenant id must start with ASCII lowercase alphanumeric, got '{}'", first));
    }
    
    for (i, c) in chars.enumerate() {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' && c != '_' {
            return Err(format!("invalid character '{}' at position {} in tenant id", c, i + 2));
        }
    }
    
    Ok(id.to_string())
}

#[derive(Debug, Clone)]
pub struct RateBudget {
    pub limit: u64,
    pub used: u64,
}

impl RateBudget {
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub seq: u64,
    pub action_id: String,
    pub verdict: String,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEntry {
    fn compute_hash(prev_hash: &str, seq: u64, action_id: &str, verdict: &str) -> String {
        let input = format!("{}|{}|{}|{}", prev_hash, seq, action_id, verdict);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }
    
    fn new(prev_hash: String, seq: u64, action_id: String, verdict: String) -> Self {
        let hash = Self::compute_hash(&prev_hash, seq, &action_id, &verdict);
        AuditEntry {
            seq,
            action_id,
            verdict,
            prev_hash,
            hash,
        }
    }
}

pub struct TenantRegistry {
    registered: BTreeSet<String>,
    policies: HashMap<String, PolicyBundle>,
    key_bindings: HashMap<String, String>, // fingerprint -> tenant_id
    budgets: HashMap<String, RateBudget>,
    audit_partitions: HashMap<String, Vec<AuditEntry>>,
}

impl TenantRegistry {
    pub fn new(configured: &[String], default_budget: u64) -> Result<Self, String> {
        let mut registered = BTreeSet::new();
        
        // Always register DEFAULT_TENANT
        registered.insert(DEFAULT_TENANT.to_string());
        
        // Validate and register configured tenants
        for tenant in configured {
            validate_tenant_id(tenant)?;
            registered.insert(tenant.clone());
        }
        
        // Initialize budgets for all registered tenants
        let mut budgets = HashMap::new();
        for tenant in &registered {
            budgets.insert(tenant.clone(), RateBudget {
                limit: default_budget,
                used: 0,
            });
        }
        
        Ok(TenantRegistry {
            registered,
            policies: HashMap::new(),
            key_bindings: HashMap::new(),
            budgets,
            audit_partitions: HashMap::new(),
        })
    }
    
    pub fn is_registered(&self, tenant: &str) -> bool {
        self.registered.contains(tenant)
    }
    
    pub fn tenant_ids(&self) -> Vec<String> {
        self.registered.iter().cloned().collect()
    }
    
    fn require_registered(&self, tenant: &str) -> Result<(), String> {
        if !self.is_registered(tenant) {
            return Err(format!("tenant '{}' is not registered", tenant));
        }
        Ok(())
    }
    
    pub fn set_policy(&mut self, tenant: &str, bundle: PolicyBundle) -> Result<(), String> {
        validate_tenant_id(tenant)?;
        self.require_registered(tenant)?;
        self.policies.insert(tenant.to_string(), bundle);
        Ok(())
    }
    
    pub fn policy_for(&self, tenant: &str) -> Option<&PolicyBundle> {
        self.policies.get(tenant)
    }
    
    pub fn tenant_policy_decision(&self, tenant: &str, action_type: &str) -> Option<bool> {
        let bundle = self.policy_for(tenant)?;
        
        // Find all rules matching this action_type
        let matching_rules: Vec<_> = bundle.rules.iter()
            .filter(|r| r.action_type == action_type)
            .collect();
        
        if matching_rules.is_empty() {
            return None;
        }
        
        // Find the highest priority
        let max_priority = matching_rules.iter()
            .map(|r| r.priority)
            .max()
            .unwrap();
        
        // Among highest priority rules, if any deny, return deny
        let highest_priority_rules: Vec<_> = matching_rules.iter()
            .filter(|r| r.priority == max_priority)
            .collect();
        
        for rule in &highest_priority_rules {
            if !rule.allow {
                return Some(false);
            }
        }
        
        // All highest priority rules allow
        Some(true)
    }
    
    pub fn bind_key(&mut self, fingerprint: &str, tenant: &str) -> Result<(), String> {
        validate_tenant_id(tenant)?;
        self.require_registered(tenant)?;
        
        // Validate fingerprint format
        if fingerprint.len() != 64 {
            return Err(format!("fingerprint must be exactly 64 hex chars, got {}", fingerprint.len()));
        }
        if !fingerprint.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            return Err("fingerprint must be lowercase hex".to_string());
        }
        
        // Check for cross-tenant binding
        if let Some(existing_tenant) = self.key_bindings.get(fingerprint) {
            if existing_tenant != tenant {
                return Err(format!("cross-tenant key binding: fingerprint already bound to tenant '{}'", existing_tenant));
            }
            // Same tenant rebind is OK
            return Ok(());
        }
        
        self.key_bindings.insert(fingerprint.to_string(), tenant.to_string());
        Ok(())
    }
    
    pub fn tenant_for_key(&self, fingerprint: &str) -> Option<&str> {
        self.key_bindings.get(fingerprint).map(|s| s.as_str())
    }
    
    pub fn check_key_access(&self, fingerprint: &str, tenant: &str) -> Result<(), String> {
        if let Some(bound_tenant) = self.tenant_for_key(fingerprint) {
            if bound_tenant != tenant {
                return Err(format!("cross-tenant key access: key bound to '{}', requested by '{}'", bound_tenant, tenant));
            }
        }
        Ok(())
    }
    
    pub fn try_consume_budget(&mut self, tenant: &str) -> Result<bool, String> {
        self.require_registered(tenant)?;
        
        let budget = self.budgets.get_mut(tenant)
            .ok_or_else(|| format!("no budget for tenant '{}'", tenant))?;
        
        // Limit of 0 means unlimited
        if budget.limit == 0 {
            budget.used += 1;
            return Ok(true);
        }
        
        if budget.used >= budget.limit {
            return Ok(false);
        }
        
        budget.used += 1;
        Ok(true)
    }
    
    pub fn budget(&self, tenant: &str) -> Option<(u64, u64, u64)> {
        self.budgets.get(tenant).map(|b| {
            (b.limit, b.used, b.remaining())
        })
    }
    
    pub fn append_audit(&mut self, tenant: &str, action_id: &str, verdict: &str) -> Result<u64, String> {
        self.require_registered(tenant)?;
        
        let partition = self.audit_partitions.entry(tenant.to_string())
            .or_insert_with(Vec::new);
        
        let seq = partition.len() as u64 + 1;
        let prev_hash = if partition.is_empty() {
            "0".repeat(64)
        } else {
            partition.last().unwrap().hash.clone()
        };
        
        let entry = AuditEntry::new(prev_hash, seq, action_id.to_string(), verdict.to_string());
        partition.push(entry);
        
        Ok(seq)
    }
    
    pub fn audit_entries(&self, tenant: &str) -> Vec<AuditEntry> {
        self.audit_partitions.get(tenant)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
    
    pub fn audit_count(&self, tenant: &str) -> u64 {
        self.audit_partitions.get(tenant)
            .map(|v| v.len() as u64)
            .unwrap_or(0)
    }
    
    pub fn verify_partition(&self, tenant: &str) -> bool {
        let partition = match self.audit_partitions.get(tenant) {
            Some(p) => p,
            None => return true, // Empty partition is valid
        };
        
        if partition.is_empty() {
            return true;
        }
        
        for (i, entry) in partition.iter().enumerate() {
            let expected_seq = i as u64 + 1;
            if entry.seq != expected_seq {
                return false;
            }
            
            let expected_prev_hash = if i == 0 {
                "0".repeat(64)
            } else {
                partition[i - 1].hash.clone()
            };
            
            if entry.prev_hash != expected_prev_hash {
                return false;
            }
            
            let expected_hash = AuditEntry::compute_hash(&entry.prev_hash, entry.seq, &entry.action_id, &entry.verdict);
            if entry.hash != expected_hash {
                return false;
            }
        }
        
        true
    }
}

pub fn cross_tenant_authorized(actor: &str, target: &str, confirmations: u32) -> bool {
    if actor == target {
        return true;
    }
    confirmations >= 2
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_tenant_id() {
        // Valid IDs
        assert!(validate_tenant_id("a").is_ok());
        assert!(validate_tenant_id("abc123").is_ok());
        assert!(validate_tenant_id("tenant-1").is_ok());
        assert!(validate_tenant_id("tenant_2").is_ok());
        assert!(validate_tenant_id("a1-b2_c3").is_ok());
        assert!(validate_tenant_id("0tenant").is_ok()); // starts with digit is OK
        
        // Invalid IDs
        assert!(validate_tenant_id("").is_err()); // empty
        assert!(validate_tenant_id("A").is_err()); // uppercase first char
        assert!(validate_tenant_id("Abc").is_err()); // uppercase
        assert!(validate_tenant_id("aBc").is_err()); // uppercase in middle
        assert!(validate_tenant_id("abc!").is_err()); // bad char
        assert!(validate_tenant_id("abc def").is_err()); // space
        assert!(validate_tenant_id(&"a".repeat(65)).is_err()); // too long
    }
    
    #[test]
    fn test_default_tenant_always_registered() {
        let registry = TenantRegistry::new(&[], 100).unwrap();
        assert!(registry.is_registered(DEFAULT_TENANT));
        assert_eq!(registry.tenant_ids(), vec![DEFAULT_TENANT.to_string()]);
    }
    
    #[test]
    fn test_unknown_tenant_errors() {
        let registry = TenantRegistry::new(&[], 100).unwrap();
        assert!(!registry.is_registered("unknown"));
        assert!(registry.require_registered("unknown").is_err());
    }
    
    #[test]
    fn test_policy_decision_per_tenant() {
        let mut registry = TenantRegistry::new(&["tenant-a".to_string(), "tenant-b".to_string()], 100).unwrap();
        
        let bundle_a = PolicyBundle {
            version: 1,
            rules: vec![
                crate::policy::PolicyRule {
                    action_type: "test-action".to_string(),
                    allow: false,
                    priority: 10,
                }
            ],
            escalate_actions: vec![],
            prev_hash: "0".repeat(64),
        };
        
        let bundle_b = PolicyBundle {
            version: 1,
            rules: vec![
                crate::policy::PolicyRule {
                    action_type: "test-action".to_string(),
                    allow: true,
                    priority: 10,
                }
            ],
            escalate_actions: vec![],
            prev_hash: "0".repeat(64),
        };
        
        registry.set_policy("tenant-a", bundle_a).unwrap();
        registry.set_policy("tenant-b", bundle_b).unwrap();
        
        // Tenant A denies, tenant B allows the same action
        assert_eq!(registry.tenant_policy_decision("tenant-a", "test-action"), Some(false));
        assert_eq!(registry.tenant_policy_decision("tenant-b", "test-action"), Some(true));
        
        // No bundle for default tenant
        assert_eq!(registry.tenant_policy_decision(DEFAULT_TENANT, "test-action"), None);
        
        // No matching rule
        assert_eq!(registry.tenant_policy_decision("tenant-a", "other-action"), None);
    }
    
    #[test]
    fn test_policy_decision_deny_wins_tie() {
        let mut registry = TenantRegistry::new(&[], 100).unwrap();
        
        let bundle = PolicyBundle {
            version: 1,
            rules: vec![
                crate::policy::PolicyRule {
                    action_type: "test-action".to_string(),
                    allow: true,
                    priority: 10,
                },
                crate::policy::PolicyRule {
                    action_type: "test-action".to_string(),
                    allow: false,
                    priority: 10,
                }
            ],
            escalate_actions: vec![],
            prev_hash: "0".repeat(64),
        };
        
        registry.set_policy(DEFAULT_TENANT, bundle).unwrap();
        
        // Deny wins when priority is tied
        assert_eq!(registry.tenant_policy_decision(DEFAULT_TENANT, "test-action"), Some(false));
    }
    
    #[test]
    fn test_key_binding() {
        let mut registry = TenantRegistry::new(&["tenant-a".to_string(), "tenant-b".to_string()], 100).unwrap();
        let fp = "a".repeat(64);
        
        // Bind key to tenant-a
        assert!(registry.bind_key(&fp, "tenant-a").is_ok());
        assert_eq!(registry.tenant_for_key(&fp), Some("tenant-a"));
        
        // Same-tenant rebind is OK
        assert!(registry.bind_key(&fp, "tenant-a").is_ok());
        
        // Cross-tenant rebind is Err
        let result = registry.bind_key(&fp, "tenant-b");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cross-tenant"));
        
        // check_key_access
        assert!(registry.check_key_access(&fp, "tenant-a").is_ok());
        let result = registry.check_key_access(&fp, "tenant-b");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cross-tenant"));
        
        // Unbound key is OK for any tenant
        let fp2 = "b".repeat(64);
        assert!(registry.check_key_access(&fp2, "tenant-a").is_ok());
        assert!(registry.check_key_access(&fp2, "tenant-b").is_ok());
        
        // Bad fingerprint
        assert!(registry.bind_key("short", "tenant-a").is_err());
        assert!(registry.bind_key(&"Z".repeat(64), "tenant-a").is_err()); // uppercase
    }
    
    #[test]
    fn test_budget_isolation() {
        let mut registry = TenantRegistry::new(&["tenant-a".to_string(), "tenant-b".to_string()], 2).unwrap();
        
        // Consume tenant-a's budget completely
        assert_eq!(registry.try_consume_budget("tenant-a").unwrap(), true);
        assert_eq!(registry.try_consume_budget("tenant-a").unwrap(), true);
        assert_eq!(registry.try_consume_budget("tenant-a").unwrap(), false); // exhausted
        assert_eq!(registry.try_consume_budget("tenant-a").unwrap(), false); // still exhausted
        
        // Tenant-b's budget is untouched
        assert_eq!(registry.try_consume_budget("tenant-b").unwrap(), true);
        assert_eq!(registry.try_consume_budget("tenant-b").unwrap(), true);
        assert_eq!(registry.try_consume_budget("tenant-b").unwrap(), false);
        
        // Check that exhausted tenant-a did not increment past limit
        let (limit, used, remaining) = registry.budget("tenant-a").unwrap();
        assert_eq!(limit, 2);
        assert_eq!(used, 2);
        assert_eq!(remaining, 0);
    }
    
    #[test]
    fn test_budget_unlimited() {
        let mut registry = TenantRegistry::new(&[], 0).unwrap();
        
        // Limit 0 means unlimited
        for _ in 0..100 {
            assert_eq!(registry.try_consume_budget(DEFAULT_TENANT).unwrap(), true);
        }
        
        let (limit, used, _) = registry.budget(DEFAULT_TENANT).unwrap();
        assert_eq!(limit, 0);
        assert_eq!(used, 100);
    }
    
    #[test]
    fn test_audit_isolation() {
        let mut registry = TenantRegistry::new(&["tenant-a".to_string(), "tenant-b".to_string()], 100).unwrap();
        
        registry.append_audit("tenant-a", "action-1", "ALLOW").unwrap();
        registry.append_audit("tenant-a", "action-2", "BLOCK").unwrap();
        registry.append_audit("tenant-b", "action-3", "ALLOW").unwrap();
        
        // Each partition has its own entries
        assert_eq!(registry.audit_count("tenant-a"), 2);
        assert_eq!(registry.audit_count("tenant-b"), 1);
        assert_eq!(registry.audit_count(DEFAULT_TENANT), 0);
        
        let entries_a = registry.audit_entries("tenant-a");
        assert_eq!(entries_a.len(), 2);
        assert_eq!(entries_a[0].action_id, "action-1");
        assert_eq!(entries_a[1].action_id, "action-2");
        
        let entries_b = registry.audit_entries("tenant-b");
        assert_eq!(entries_b.len(), 1);
        assert_eq!(entries_b[0].action_id, "action-3");
        
        // Per-partition seq starts at 1
        assert_eq!(entries_a[0].seq, 1);
        assert_eq!(entries_a[1].seq, 2);
        assert_eq!(entries_b[0].seq, 1);
    }
    
    #[test]
    fn test_audit_chain_verification() {
        let mut registry = TenantRegistry::new(&[], 100).unwrap();
        
        // Empty partition is valid
        assert!(registry.verify_partition(DEFAULT_TENANT));
        
        registry.append_audit(DEFAULT_TENANT, "action-1", "ALLOW").unwrap();
        registry.append_audit(DEFAULT_TENANT, "action-2", "BLOCK").unwrap();
        
        // Valid chain
        assert!(registry.verify_partition(DEFAULT_TENANT));
        
        // Corrupt a stored entry
        let partition = registry.audit_partitions.get_mut(DEFAULT_TENANT).unwrap();
        partition[1].verdict = "CORRUPTED".to_string(); // hash no longer matches
        
        // Verification fails
        assert!(!registry.verify_partition(DEFAULT_TENANT));
    }
    
    #[test]
    fn test_cross_tenant_authorized() {
        // Same tenant
        assert!(cross_tenant_authorized("tenant-a", "tenant-a", 0));
        
        // Different tenant, insufficient confirmations
        assert!(!cross_tenant_authorized("tenant-a", "tenant-b", 0));
        assert!(!cross_tenant_authorized("tenant-a", "tenant-b", 1));
        
        // Different tenant, sufficient confirmations
        assert!(cross_tenant_authorized("tenant-a", "tenant-b", 2));
        assert!(cross_tenant_authorized("tenant-a", "tenant-b", 3));
    }
}
