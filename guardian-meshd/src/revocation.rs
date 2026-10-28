// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

//! WO-12: Revocation service
//!
//! Dual-control revocation of sessions, keys, and certificates with DC-14
//! propagation bound enforcement.

use serde::{Deserialize, Serialize, Serializer, Deserializer};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationKind {
    Session,
    Key,
    Certificate,
}

impl RevocationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationKind::Session => "SESSION",
            RevocationKind::Key => "KEY",
            RevocationKind::Certificate => "CERTIFICATE",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "SESSION" => Ok(RevocationKind::Session),
            "KEY" => Ok(RevocationKind::Key),
            "CERTIFICATE" => Ok(RevocationKind::Certificate),
            _ => Err(format!("unknown revocation kind: {}", s)),
        }
    }
}

impl Serialize for RevocationKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RevocationKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RevocationKind::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub kind: RevocationKind,
    pub target_id: String,
    pub reason: String,
    pub proposer: String,
    pub approver: String,
    pub revoked_at: u64,
    pub propagation_ms: u64,
}

/// Build the canonical revocation string for signing.
/// Format: guardian-mesh-revocation-v1\nkind=<KIND>\ntarget=<target_id>\nreason=<reason>\nproposer=<proposer>\n
pub fn canonical_revocation_string(
    kind: RevocationKind,
    target_id: &str,
    reason: &str,
    proposer: &str,
) -> String {
    format!(
        "guardian-mesh-revocation-v1\nkind={}\ntarget={}\nreason={}\nproposer={}\n",
        kind.as_str(),
        target_id,
        reason,
        proposer
    )
}

/// Compute the change ID (SHA-256 hex) of the canonical revocation string.
pub fn revocation_change_id(
    kind: RevocationKind,
    target_id: &str,
    reason: &str,
    proposer: &str,
) -> String {
    let canonical = canonical_revocation_string(kind, target_id, reason, proposer);
    let hash = Sha256::digest(canonical.as_bytes());
    hex::encode(hash)
}

/// Validate revocation parameters.
pub fn validate_revocation(
    kind: RevocationKind,
    target_id: &str,
    reason: &str,
) -> Result<(), String> {
    // Validate reason
    if reason.is_empty() {
        return Err("reason must be non-empty".into());
    }
    if reason.len() > 256 {
        return Err("reason must be ≤ 256 characters".into());
    }
    if reason.contains('\n') || reason.contains('\r') {
        return Err("reason must not contain newline or carriage return".into());
    }
    if reason.chars().any(|c| c.is_control()) {
        return Err("reason must not contain control characters".into());
    }

    // Validate target_id based on kind
    match kind {
        RevocationKind::Session => {
            if target_id.len() != 32 {
                return Err("SESSION target must be exactly 32 lowercase hex characters".into());
            }
            if !target_id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
                return Err("SESSION target must be lowercase hex".into());
            }
        }
        RevocationKind::Key => {
            if target_id.len() != 64 {
                return Err("KEY target must be exactly 64 lowercase hex characters".into());
            }
            if !target_id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
                return Err("KEY target must be lowercase hex".into());
            }
        }
        RevocationKind::Certificate => {
            if target_id.is_empty() {
                return Err("CERTIFICATE target must be non-empty".into());
            }
            if target_id.len() > 128 {
                return Err("CERTIFICATE target must be ≤ 128 characters".into());
            }
            if target_id.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err("CERTIFICATE target must not contain whitespace or control characters".into());
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
pub struct RevocationRegistry {
    revocation_path: PathBuf,
    entries: Mutex<Vec<RevocationEntry>>,
}

impl RevocationRegistry {
    pub fn new(revocation_dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&revocation_dir)
            .map_err(|e| format!("failed to create revocation directory: {}", e))?;

        let revocation_file = revocation_dir.join("revocations.jsonl");
        let mut entries = Vec::new();

        if revocation_file.exists() {
            let file = fs::File::open(&revocation_file)
                .map_err(|e| format!("failed to open revocations file: {}", e))?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.map_err(|e| format!("failed to read revocation line: {}", e))?;
                if line.trim().is_empty() {
                    continue;
                }

                let entry: RevocationEntry = serde_json::from_str(&line)
                    .map_err(|e| format!("failed to parse revocation entry: {}", e))?;
                entries.push(entry);
            }
        }

        Ok(Self {
            revocation_path: revocation_file,
            entries: Mutex::new(entries),
        })
    }

    pub fn is_revoked(&self, kind: RevocationKind, target_id: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        entries.iter().any(|e| e.kind == kind && e.target_id == target_id)
    }

    pub fn get(&self, kind: RevocationKind, target_id: &str) -> Option<RevocationEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .find(|e| e.kind == kind && e.target_id == target_id)
            .cloned()
    }

    pub fn count(&self) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.len()
    }

    pub fn record(&self, entry: RevocationEntry) -> Result<(), String> {
        // Persist first (fail-closed discipline)
        let json_line = serde_json::to_string(&entry)
            .map_err(|e| format!("failed to serialize revocation entry: {}", e))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.revocation_path)
            .map_err(|e| format!("failed to open revocations file for append: {}", e))?;

        writeln!(file, "{}", json_line)
            .map_err(|e| format!("failed to write revocation entry: {}", e))?;

        file.flush()
            .map_err(|e| format!("failed to flush revocations file: {}", e))?;

        // Now add to memory
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_canonical_string_format() {
        let s = canonical_revocation_string(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "test reason",
            "alice",
        );
        assert_eq!(
            s,
            "guardian-mesh-revocation-v1\nkind=SESSION\ntarget=abc123def456abc123def456abc123de\nreason=test reason\nproposer=alice\n"
        );
    }

    #[test]
    fn test_change_id_stable() {
        let id1 = revocation_change_id(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "test reason",
            "alice",
        );
        let id2 = revocation_change_id(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "test reason",
            "alice",
        );
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_change_id_changes_with_reason() {
        let id1 = revocation_change_id(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "reason one",
            "alice",
        );
        let id2 = revocation_change_id(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "reason two",
            "alice",
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_validate_bad_session_id() {
        let err = validate_revocation(
            RevocationKind::Session,
            "tooshort",
            "valid reason",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("exactly 32"));
    }

    #[test]
    fn test_validate_bad_key_fingerprint() {
        let err = validate_revocation(
            RevocationKind::Key,
            "abc",
            "valid reason",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("exactly 64"));
    }

    #[test]
    fn test_validate_empty_reason() {
        let err = validate_revocation(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("non-empty"));
    }

    #[test]
    fn test_validate_reason_with_newline() {
        let err = validate_revocation(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "bad\nreason",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("newline"));
    }

    #[test]
    fn test_registry_record_and_retrieval() {
        let temp_dir = TempDir::new().unwrap();
        let registry = RevocationRegistry::new(temp_dir.path().to_path_buf()).unwrap();

        let entry = RevocationEntry {
            kind: RevocationKind::Session,
            target_id: "abc123def456abc123def456abc123de".into(),
            reason: "test revocation".into(),
            proposer: "alice".into(),
            approver: "bob".into(),
            revoked_at: 1234567890,
            propagation_ms: 42,
        };

        registry.record(entry.clone()).unwrap();

        assert!(registry.is_revoked(RevocationKind::Session, "abc123def456abc123def456abc123de"));
        assert!(!registry.is_revoked(RevocationKind::Session, "deadbeefdeadbeefdeadbeefdeadbeef"));
        assert_eq!(registry.count(), 1);

        let retrieved = registry.get(RevocationKind::Session, "abc123def456abc123def456abc123de").unwrap();
        assert_eq!(retrieved.reason, "test revocation");
        assert_eq!(retrieved.proposer, "alice");
        assert_eq!(retrieved.approver, "bob");
    }

    #[test]
    fn test_registry_reload() {
        let temp_dir = TempDir::new().unwrap();

        {
            let registry = RevocationRegistry::new(temp_dir.path().to_path_buf()).unwrap();
            let entry = RevocationEntry {
                kind: RevocationKind::Key,
                target_id: "abc123def456abc123def456abc123def456abc123def456abc123def456abc123de".into(),
                reason: "compromised key".into(),
                proposer: "alice".into(),
                approver: "bob".into(),
                revoked_at: 1234567890,
                propagation_ms: 100,
            };
            registry.record(entry).unwrap();
        }

        // Reload
        let registry2 = RevocationRegistry::new(temp_dir.path().to_path_buf()).unwrap();
        assert_eq!(registry2.count(), 1);
        assert!(registry2.is_revoked(
            RevocationKind::Key,
            "abc123def456abc123def456abc123def456abc123def456abc123def456abc123de"
        ));
    }

    #[test]
    fn test_registry_corrupt_line_fails() {
        let temp_dir = TempDir::new().unwrap();
        let revocation_file = temp_dir.path().join("revocations.jsonl");

        // Write a corrupt line
        std::fs::write(&revocation_file, "not valid json\n").unwrap();

        let result = RevocationRegistry::new(temp_dir.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse"));
    }
}
