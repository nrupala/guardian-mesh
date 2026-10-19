// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use super::EnclaveContext;
use sha2::{Sha256, Digest};
use std::collections::VecDeque;
use std::fs::{OpenOptions};
use std::io::{Write, BufRead, BufReader};
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
    last_chain_hash: Mutex<String>,
}

impl VaultEnclave {
    pub fn new(max_entries: usize, audit_path: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&audit_path);
        // Initialize with genesis hash (all zeros for the first entry)
        let last_hash = Self::load_last_chain_hash(&audit_path)
            .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string());
        Self {
            audit_trail: Mutex::new(VecDeque::with_capacity(max_entries)),
            max_entries,
            audit_path,
            last_chain_hash: Mutex::new(last_hash),
        }
    }

    fn load_last_chain_hash(audit_path: &PathBuf) -> Option<String> {
        // Read the last entry from all audit files to get the last chain hash
        let entries = std::fs::read_dir(audit_path).ok()?;
        let mut all_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with("audit_") && s.ends_with(".jsonl"))
                    .unwrap_or(false)
            })
            .collect();
        
        // Sort by modification time to get the most recent file
        all_files.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
        
        // Read the last line from the most recent file
        if let Some(last_file) = all_files.last() {
            if let Ok(file) = std::fs::File::open(last_file.path()) {
                let reader = BufReader::new(file);
                let last_line = reader.lines().filter_map(|l| l.ok()).last();
                if let Some(line) = last_line {
                    // Parse: timestamp|action_id|verdict|enclave_chain|digest|reason
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 5 {
                        return Some(parts[4].to_string());
                    }
                }
            }
        }
        None
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
        
        // Hash chain: hash(prev_hash || timestamp || action_id || verdict || enclave_chain || reason)
        let prev_hash = self.last_chain_hash.lock().unwrap().clone();
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(now.to_le_bytes());
        hasher.update(action_id.as_bytes());
        hasher.update(verdict.as_bytes());
        hasher.update(chain_str.as_bytes());
        hasher.update(reason.as_bytes());
        let digest = hex::encode(hasher.finalize());

        let entry = AuditEntry {
            action_id: action_id.clone(),
            verdict: verdict.clone(),
            reason: reason.clone(),
            enclave_chain: chain_str.into(),
            timestamp: now,
            digest: digest.clone(),
        };

        {
            let mut trail = self.audit_trail.lock().unwrap();
            if trail.len() >= self.max_entries {
                trail.pop_front();
            }
            trail.push_back(entry.clone());
        }

        let _ = self.persist_entry(&entry, action_id, verdict, reason);
        
        // Update the last chain hash
        *self.last_chain_hash.lock().unwrap() = digest;
    }

    fn persist_entry(&self, entry: &AuditEntry, action_id: String, verdict: String, reason: String) -> std::io::Result<()> {
        let today = chrono_now_date();
        let file_path = self.audit_path.join(format!("audit_{}.jsonl", today));
        let line = format!(
            "{}|{}|{}|{}|{}|{}\n",
            entry.timestamp,
            action_id,
            verdict,
            entry.enclave_chain,
            entry.digest,
            reason
        );
        let mut file = OpenOptions::new().create(true).append(true).open(&file_path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn read_audit_log(&self) -> Result<Vec<ParsedAuditEntry>, String> {
        let mut all_entries = Vec::new();
        let entries = std::fs::read_dir(&self.audit_path)
            .map_err(|e| format!("Failed to read audit directory: {}", e))?;
        
        let mut all_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with("audit_") && s.ends_with(".jsonl"))
                    .unwrap_or(false)
            })
            .collect();
        
        // Sort files by name (audit_<timestamp>.jsonl) to maintain order
        all_files.sort_by_key(|e| {
            e.path()
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
                .unwrap_or_default()
        });

        for file_entry in all_files {
            let file = std::fs::File::open(file_entry.path())
                .map_err(|e| format!("Failed to open audit file: {}", e))?;
            let reader = BufReader::new(file);
            
            for line in reader.lines() {
                let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
                if line.trim().is_empty() {
                    continue;
                }
                
                // Parse: timestamp|action_id|verdict|enclave_chain|digest|reason
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() < 6 {
                    return Err(format!("Malformed audit entry (expected 6 fields): {}", line));
                }
                
                let timestamp = parts[0].parse::<u64>()
                    .map_err(|_| format!("Invalid timestamp in audit entry: {}", parts[0]))?;
                
                all_entries.push(ParsedAuditEntry {
                    timestamp,
                    action_id: parts[1].to_string(),
                    verdict: parts[2].to_string(),
                    enclave_chain: parts[3].to_string(),
                    chain_hash: parts[4].to_string(),
                    reason: parts[5..].join("|"), // Reason might contain pipes
                });
            }
        }
        
        Ok(all_entries)
    }

    pub fn verify_chain(&self, entries: &[ParsedAuditEntry]) -> ChainVerification {
        if entries.is_empty() {
            return ChainVerification {
                verified: true,
                entries_checked: 0,
                first_break_position: None,
                status_message: "Log is empty (no entries to verify)".to_string(),
            };
        }

        let mut prev_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        
        for (idx, entry) in entries.iter().enumerate() {
            // Re-compute the expected hash for this entry
            let mut hasher = Sha256::new();
            hasher.update(prev_hash.as_bytes());
            hasher.update(entry.timestamp.to_le_bytes());
            hasher.update(entry.action_id.as_bytes());
            hasher.update(entry.verdict.as_bytes());
            hasher.update(entry.enclave_chain.as_bytes());
            hasher.update(entry.reason.as_bytes());
            let expected_hash = hex::encode(hasher.finalize());
            
            // Compare with stored hash
            if expected_hash != entry.chain_hash {
                return ChainVerification {
                    verified: false,
                    entries_checked: idx as u64,
                    first_break_position: Some(idx as u64),
                    status_message: format!(
                        "Chain break at position {}: expected hash {}, found {}",
                        idx, &expected_hash[..16], &entry.chain_hash[..16]
                    ),
                };
            }
            
            prev_hash = entry.chain_hash.clone();
        }
        
        ChainVerification {
            verified: true,
            entries_checked: entries.len() as u64,
            first_break_position: None,
            status_message: format!("Chain verified: {} entries checked, all valid", entries.len()),
        }
    }

    pub fn get_audit_trail(&self) -> Vec<AuditEntry> {
        let trail = self.audit_trail.lock().unwrap();
        trail.iter().cloned().collect()
    }
}

pub struct ParsedAuditEntry {
    pub timestamp: u64,
    pub action_id: String,
    pub verdict: String,
    pub enclave_chain: String,
    pub chain_hash: String,
    pub reason: String,
}

pub struct ChainVerification {
    pub verified: bool,
    pub entries_checked: u64,
    pub first_break_position: Option<u64>,
    pub status_message: String,
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

    #[test]
    fn read_audit_log_returns_entries_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(100, dir.path().to_path_buf());
        
        // Create 3 entries
        for _ in 0..3 {
            vault.seal(&make_test_ctx());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        
        let entries = vault.read_audit_log().unwrap();
        assert_eq!(entries.len(), 3);
        
        // Verify they are in timestamp order
        for i in 1..entries.len() {
            assert!(entries[i].timestamp >= entries[i-1].timestamp);
        }
    }

    #[test]
    fn chain_verification_passes_for_untouched_log() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(100, dir.path().to_path_buf());
        
        // Create entries
        for _ in 0..5 {
            vault.seal(&make_test_ctx());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        
        let entries = vault.read_audit_log().unwrap();
        let verification = vault.verify_chain(&entries);
        
        assert!(verification.verified, "Chain should verify: {}", verification.status_message);
        assert_eq!(verification.entries_checked, 5);
        assert!(verification.first_break_position.is_none());
    }

    #[test]
    fn chain_verification_detects_tampered_entry() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(100, dir.path().to_path_buf());
        
        // Create entries
        for _ in 0..5 {
            vault.seal(&make_test_ctx());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        
        // Read and tamper with the third entry in the file
        let mut entries = vault.read_audit_log().unwrap();
        entries[2].reason = "TAMPERED".to_string();
        
        let verification = vault.verify_chain(&entries);
        
        assert!(!verification.verified, "Chain should not verify after tampering");
        assert_eq!(verification.first_break_position, Some(2));
        assert!(verification.status_message.contains("Chain break at position 2"));
    }

    #[test]
    fn empty_log_verification() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(100, dir.path().to_path_buf());
        
        let entries = vault.read_audit_log().unwrap();
        let verification = vault.verify_chain(&entries);
        
        assert!(verification.verified);
        assert_eq!(verification.entries_checked, 0);
        assert!(verification.status_message.contains("empty"));
    }

    #[test]
    fn chain_hash_links_properly() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultEnclave::new(100, dir.path().to_path_buf());
        
        vault.seal(&make_test_ctx());
        std::thread::sleep(std::time::Duration::from_millis(10));
        vault.seal(&make_test_ctx());
        
        let entries = vault.read_audit_log().unwrap();
        assert_eq!(entries.len(), 2);
        
        // The first entry's hash should start from genesis
        let genesis = "0000000000000000000000000000000000000000000000000000000000000000";
        let mut hasher = Sha256::new();
        hasher.update(genesis.as_bytes());
        hasher.update(entries[0].timestamp.to_le_bytes());
        hasher.update(entries[0].action_id.as_bytes());
        hasher.update(entries[0].verdict.as_bytes());
        hasher.update(entries[0].enclave_chain.as_bytes());
        hasher.update(entries[0].reason.as_bytes());
        let expected_first = hex::encode(hasher.finalize());
        assert_eq!(entries[0].chain_hash, expected_first);
        
        // The second entry's hash should chain from the first
        let mut hasher = Sha256::new();
        hasher.update(entries[0].chain_hash.as_bytes());
        hasher.update(entries[1].timestamp.to_le_bytes());
        hasher.update(entries[1].action_id.as_bytes());
        hasher.update(entries[1].verdict.as_bytes());
        hasher.update(entries[1].enclave_chain.as_bytes());
        hasher.update(entries[1].reason.as_bytes());
        let expected_second = hex::encode(hasher.finalize());
        assert_eq!(entries[1].chain_hash, expected_second);
    }
}
