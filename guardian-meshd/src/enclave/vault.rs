// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: MIT

use super::EnclaveContext;
use sha2::{Sha256, Digest};
use std::collections::VecDeque;
use std::fs::{OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone)]
pub struct AuditEntry {
    pub action_id: String,
    pub verdict: String,
    pub reason: String,
    pub enclave_chain: String,
    pub timestamp: u64,
    pub digest: String,
}

pub struct VaultEnclave {
    audit_trail: Mutex<VecDeque<AuditEntry>>,
    max_entries: usize,
    audit_path: PathBuf,
}

impl VaultEnclave {
    pub fn new(max_entries: usize, audit_path: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&audit_path);
        Self {
            audit_trail: Mutex::new(VecDeque::with_capacity(max_entries)),
            max_entries,
            audit_path,
        }
    }

    pub fn seal(&self, ctx: &EnclaveContext) {
        let verdict = ctx.verdict.as_ref()
            .map(|v| v.as_str().to_string())
            .unwrap_or_default();
        let reason = ctx.reason.clone().unwrap_or_default();

        let action_id = ctx
            .request
            .action
            .as_ref()
            .map(|a| hex::encode(a.action_type.as_bytes()))
            .unwrap_or_default();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let chain_str = "Sentinel→Gatekeeper→Witness→Arbiter→Vault";
        let mut hasher = Sha256::new();
        hasher.update(action_id.as_bytes());
        hasher.update(verdict.as_bytes());
        hasher.update(now.to_le_bytes());
        let digest = hex::encode(hasher.finalize());

        let entry = AuditEntry {
            action_id: action_id.clone(),
            verdict: verdict.clone(),
            reason,
            enclave_chain: chain_str.into(),
            timestamp: now,
            digest,
        };

        {
            let mut trail = self.audit_trail.lock().unwrap();
            if trail.len() >= self.max_entries {
                trail.pop_front();
            }
            trail.push_back(entry.clone());
        }

        let _ = self.persist_entry(&entry, action_id, verdict);
    }

    fn persist_entry(&self, entry: &AuditEntry, action_id: String, verdict: String) -> std::io::Result<()> {
        let today = chrono_now_date();
        let file_path = self.audit_path.join(format!("audit_{}.jsonl", today));
        let line = format!(
            "{}|{}|{}|{}|{}|{}\n",
            entry.timestamp,
            action_id,
            verdict,
            entry.enclave_chain,
            entry.digest,
            entry.reason
        );
        let mut file = OpenOptions::new().create(true).append(true).open(&file_path)?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    pub fn get_audit_trail(&self) -> Vec<AuditEntry> {
        let trail = self.audit_trail.lock().unwrap();
        trail.iter().cloned().collect()
    }
}

fn chrono_now_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs / 86400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::{EnclaveContext, Verdict, ContainmentStage};
    use crate::proto::{EvaluateRequest, ActionDescriptor};


    fn make_test_ctx() -> EnclaveContext {
        let mut ctx = EnclaveContext::new(EvaluateRequest {
            action: Some(ActionDescriptor {
                action_type: "TOOL_CALL".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        ctx.verdict = Some(Verdict::Allow);
        ctx.reason = Some("test".into());
        ctx.stage = ContainmentStage::Normal;
        ctx
    }

    #[test]
    fn vault_seal_creates_entry() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(100, dir.path().to_path_buf());
        let ctx = make_test_ctx();
        vault.seal(&ctx);
        let trail = vault.get_audit_trail();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].verdict, "ALLOW");
    }

    #[test]
    fn vault_respects_max_entries() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(3, dir.path().to_path_buf());
        for _ in 0..5 {
            vault.seal(&make_test_ctx());
        }
        let trail = vault.get_audit_trail();
        assert_eq!(trail.len(), 3);
    }

    #[test]
    fn vault_persists_audit_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(100, dir.path().to_path_buf());
        vault.seal(&make_test_ctx());
        let entries = std::fs::read_dir(dir.path()).unwrap();
        let count = entries.filter_map(|e| e.ok()).count();
        assert!(count >= 1);
    }
}
