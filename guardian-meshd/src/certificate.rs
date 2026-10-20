// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

//! WO-6: Release-evidence certification
//!
//! Certificates bind a gate verdict to an evidence pack under the daemon's
//! cryptographic signature. The certificate schema is defined in
//! specs/CERTIFICATE_SCHEMA.md.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::proto::{TestCounts, CertificateBody};
use crate::sealed_envelope::{compute_fingerprint, SealedEnvelope};
use crate::enclave::vault::VaultEnclave;
use ml_dsa::{MlDsa65, SigningKey, VerifyingKey};

/// Maximum evidence size: 10 MB.
/// Evidence packs are documents (test results, source trees), not envelopes.
pub const MAX_EVIDENCE_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub schema: String,
    pub schema_version: u32,
    pub serial: String,
    pub issuer: String,
    pub product: String,
    pub version: String,
    pub verdict: String,
    pub evidence_hash: String,
    pub evidence_scope: String,
    pub tests: Tests,
    pub policy: String,
    pub pf_outcomes: Option<String>,
    pub issued_at: u64,
    pub supersedes: Option<String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tests {
    pub passed: u32,
    pub failed: u32,
    pub total: u32,
}

/// Certificate body for sealing (excludes fingerprint field)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateBodyForSealing {
    schema: String,
    schema_version: u32,
    serial: String,
    issuer: String,
    product: String,
    version: String,
    verdict: String,
    evidence_hash: String,
    evidence_scope: String,
    tests: Tests,
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pf_outcomes: Option<String>,
    issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateStatus {
    Active,
    Superseded,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryEntry {
    body: Certificate,
    status: CertificateStatus,
    superseded_by: Option<String>,
    revocation_reason: Option<String>,
}

pub struct CertificateRegistry {
    registry_path: PathBuf,
    entries: Mutex<HashMap<String, RegistryEntry>>,
    next_serial: Mutex<u64>,
    issuer_fingerprint: String,
    vault: Arc<VaultEnclave>,
}

impl CertificateRegistry {
    pub fn new<P: AsRef<Path>>(
        registry_path: P,
        vault: Arc<VaultEnclave>,
        verifying_key: &VerifyingKey<MlDsa65>,
    ) -> Result<Self, String> {
        let registry_path = registry_path.as_ref().to_path_buf();

        fs::create_dir_all(&registry_path)
            .map_err(|e| format!("failed to create registry directory: {}", e))?;

        let issuer_fingerprint = compute_fingerprint(verifying_key);

        let mut entries = HashMap::new();
        let mut max_serial = 0u64;

        // Load existing registry entries
        let registry_file = registry_path.join("certificates.jsonl");
        if registry_file.exists() {
            let file = fs::File::open(&registry_file)
                .map_err(|e| format!("failed to open registry file: {}", e))?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.map_err(|e| format!("failed to read registry line: {}", e))?;
                if line.trim().is_empty() {
                    continue;
                }

                let entry: RegistryEntry = serde_json::from_str(&line)
                    .map_err(|e| format!("failed to parse registry entry: {}", e))?;

                // Extract serial number to compute max
                if let Some(num_str) = entry.body.serial.split('-').last() {
                    if let Ok(num) = num_str.parse::<u64>() {
                        max_serial = max_serial.max(num);
                    }
                }

                entries.insert(entry.body.serial.clone(), entry);
            }
        }

        Ok(Self {
            registry_path,
            entries: Mutex::new(entries),
            next_serial: Mutex::new(max_serial + 1),
            issuer_fingerprint,
            vault,
        })
    }

    fn generate_serial(&self) -> String {
        let mut next = self.next_serial.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let date_str = unix_timestamp_to_yyyymmdd(now);
        let serial = format!(
            "cert-{}-{:06}",
            date_str,
            *next
        );
        *next += 1;
        serial
    }

    pub fn issue_certificate(
        &self,
        product: String,
        version: String,
        verdict: String,
        evidence: &[u8],
        claimed_hash: &str,
        evidence_scope: String,
        tests: Tests,
        policy: String,
        signing_key: &SigningKey<MlDsa65>,
    ) -> Result<IssuanceResult, String> {
        // Enforce evidence size cap
        if evidence.len() > MAX_EVIDENCE_SIZE {
            return Err(format!(
                "Evidence size {} bytes exceeds the {} byte limit",
                evidence.len(),
                MAX_EVIDENCE_SIZE
            ));
        }

        // Compute SHA-256 over the presented evidence
        let computed_hash = hex::encode(Sha256::digest(evidence));

        // Hash mismatch → refuse issuance
        if computed_hash != claimed_hash.to_lowercase() {
            return Ok(IssuanceResult::Refused(format!(
                "Evidence hash mismatch: computed {}, claimed {}",
                computed_hash, claimed_hash
            )));
        }

        // Handle BLOCKED verdict
        if verdict == "BLOCKED" {
            let mut revocation_msg = String::new();
            let mut entries = self.entries.lock().unwrap();

            // Find and revoke any ACTIVE certificate for this product+version
            for entry in entries.values_mut() {
                if entry.body.product == product
                    && entry.body.version == version
                    && entry.status == CertificateStatus::Active
                {
                    entry.status = CertificateStatus::Revoked;
                    entry.revocation_reason = Some(format!("BLOCKED verdict for {}@{}", product, version));
                    revocation_msg = format!(
                        "Certificate {} revoked due to BLOCKED verdict",
                        entry.body.serial
                    );

                    self.persist_entry(&entry)?;
                    self.vault.record_certificate_event(
                        &entry.body.serial,
                        "CERTIFICATE_REVOKED",
                        &format!("{}@{} - BLOCKED verdict for {}@{}", product, version, product, version),
                    )?;
                    break;
                }
            }

            let refusal = if revocation_msg.is_empty() {
                format!("Issuance refused: verdict is BLOCKED")
            } else {
                format!("Issuance refused: verdict is BLOCKED. {}", revocation_msg)
            };

            return Ok(IssuanceResult::Refused(refusal));
        }

        // Only PASS or PASS WITH FINDINGS may be issued
        if verdict != "PASS" && verdict != "PASS WITH FINDINGS" {
            return Ok(IssuanceResult::Refused(format!(
                "Issuance refused: verdict '{}' is not PASS or PASS WITH FINDINGS",
                verdict
            )));
        }

        // Issue the certificate
        let serial = self.generate_serial();
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Find the previous ACTIVE certificate for this product (any version)
        let mut superseded_serial: Option<String> = None;
        {
            let mut entries = self.entries.lock().unwrap();
            for entry in entries.values_mut() {
                if entry.body.product == product && entry.status == CertificateStatus::Active {
                    entry.status = CertificateStatus::Superseded;
                    entry.superseded_by = Some(serial.clone());
                    superseded_serial = Some(entry.body.serial.clone());
                    self.persist_entry(&entry)?;
                    self.vault.record_certificate_event(
                        &entry.body.serial,
                        "CERTIFICATE_SUPERSEDED",
                        &format!("{}@{} - Superseded by {}", product, version, serial),
                    )?;
                    break;
                }
            }
        }

        // Build the certificate body for sealing (without fingerprint field)
        let cert_for_sealing = CertificateBodyForSealing {
            schema: "guardian-mesh/certificate".to_string(),
            schema_version: 1,
            serial: serial.clone(),
            issuer: self.issuer_fingerprint.clone(),
            product: product.clone(),
            version: version.clone(),
            verdict: verdict.clone(),
            evidence_hash: computed_hash.clone(),
            evidence_scope: evidence_scope.clone(),
            tests: tests.clone(),
            policy: policy.clone(),
            pf_outcomes: None,
            issued_at,
            supersedes: superseded_serial.clone(),
        };

        // Serialize to canonical JSON (without fingerprint field)
        let payload = serde_json::to_vec(&cert_for_sealing)
            .map_err(|e| format!("failed to serialize certificate body: {}", e))?;

        // Compute fingerprint as SHA-256 of the exact payload bytes (without fingerprint field)
        let fingerprint = hex::encode(Sha256::digest(&payload));

        // Seal the certificate
        let sealed = SealedEnvelope::new(
            payload.clone(),
            b"guardian_mesh.Certificate".to_vec(),
            signing_key,
        );

        // Build full certificate with fingerprint for storage
        let cert = Certificate {
            schema: "guardian-mesh/certificate".to_string(),
            schema_version: 1,
            serial: serial.clone(),
            issuer: self.issuer_fingerprint.clone(),
            product,
            version,
            verdict,
            evidence_hash: computed_hash,
            evidence_scope,
            tests,
            policy,
            pf_outcomes: None,
            issued_at,
            supersedes: superseded_serial,
            fingerprint: fingerprint.clone(),
        };

        // Store in registry
        let entry = RegistryEntry {
            body: cert.clone(),
            status: CertificateStatus::Active,
            superseded_by: None,
            revocation_reason: None,
        };

        {
            let mut entries = self.entries.lock().unwrap();
            entries.insert(serial.clone(), entry.clone());
        }

        self.persist_entry(&entry)?;
        self.vault.record_certificate_event(
            &serial,
            "CERTIFICATE_ISSUED",
            &format!("{}@{} - Certificate issued", entry.body.product, entry.body.version),
        )?;

        Ok(IssuanceResult::Issued {
            serial,
            fingerprint,
            certificate: sealed,
        })
    }

    pub fn revoke_certificate(&self, serial: &str, reason: &str) -> Result<String, String> {
        let mut entries = self.entries.lock().unwrap();

        let entry = entries
            .get_mut(serial)
            .ok_or_else(|| format!("Certificate {} not found", serial))?;

        if entry.status == CertificateStatus::Revoked {
            return Ok(format!(
                "Certificate {} was already revoked",
                serial
            ));
        }

        entry.status = CertificateStatus::Revoked;
        entry.revocation_reason = Some(reason.to_string());

        self.persist_entry(&entry)?;
        self.vault.record_certificate_event(
            serial,
            "CERTIFICATE_REVOKED",
            &format!("{}@{} - {}", entry.body.product, entry.body.version, reason),
        )?;

        Ok(format!("Certificate {} revoked", serial))
    }

    pub fn get_status(&self, serial: &str) -> (CertificateStatus, Option<Certificate>) {
        let entries = self.entries.lock().unwrap();
        match entries.get(serial) {
            Some(entry) => (entry.status.clone(), Some(entry.body.clone())),
            None => (CertificateStatus::Unknown, None),
        }
    }

    fn persist_entry(&self, entry: &RegistryEntry) -> Result<(), String> {
        let registry_file = self.registry_path.join("certificates.jsonl");
        let line = serde_json::to_string(entry)
            .map_err(|e| format!("failed to serialize registry entry: {}", e))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&registry_file)
            .map_err(|e| format!("failed to open registry file: {}", e))?;

        writeln!(file, "{}", line)
            .map_err(|e| format!("failed to write registry entry: {}", e))?;

        file.sync_all()
            .map_err(|e| format!("failed to sync registry file: {}", e))?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum IssuanceResult {
    Issued {
        serial: String,
        fingerprint: String,
        certificate: SealedEnvelope,
    },
    Refused(String),
}

impl Certificate {
    pub fn to_proto_body(&self) -> CertificateBody {
        CertificateBody {
            schema: self.schema.clone(),
            schema_version: self.schema_version,
            serial: self.serial.clone(),
            issuer: self.issuer.clone(),
            product: self.product.clone(),
            version: self.version.clone(),
            verdict: self.verdict.clone(),
            evidence_hash: self.evidence_hash.clone(),
            evidence_scope: self.evidence_scope.clone(),
            tests: Some(TestCounts {
                passed: self.tests.passed,
                failed: self.tests.failed,
                total: self.tests.total,
            }),
            policy: self.policy.clone(),
            pf_outcomes: self.pf_outcomes.clone().unwrap_or_default(),
            issued_at: self.issued_at,
            supersedes: self.supersedes.clone().unwrap_or_default(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

/// Convert Unix timestamp (seconds) to YYYYMMDD string
fn unix_timestamp_to_yyyymmdd(unix_secs: u64) -> String {
    // Days since Unix epoch (1970-01-01)
    let days_since_epoch = unix_secs / 86400;
    
    // Algorithm: civil date from days since epoch
    // Based on Howard Hinnant's date algorithm
    let z = days_since_epoch + 719468; // Days from 0000-03-01 to 1970-01-01
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    
    format!("{:04}{:02}{:02}", y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_envelope::generate_keypair;

    #[test]
    fn issue_certificate_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("registry");
        let audit_path = dir.path().join("audit");
        let (sk, vk) = generate_keypair();

        let vault = Arc::new(VaultEnclave::new(1000, audit_path));
        let registry = CertificateRegistry::new(&registry_path, vault, &vk).unwrap();

        let evidence = b"test evidence pack";
        let evidence_hash = hex::encode(Sha256::digest(evidence));

        let result = registry
            .issue_certificate(
                "test-product".to_string(),
                "1.0.0".to_string(),
                "PASS".to_string(),
                evidence,
                &evidence_hash,
                "working-tree".to_string(),
                Tests {
                    passed: 10,
                    failed: 0,
                    total: 10,
                },
                "gate-v1.0".to_string(),
                &sk,
            )
            .unwrap();

        match result {
            IssuanceResult::Issued {
                serial,
                fingerprint,
                certificate,
            } => {
                assert!(serial.starts_with("cert-"));
                assert_eq!(fingerprint.len(), 64);
                assert!(!certificate.payload.is_empty());
            }
            IssuanceResult::Refused(reason) => panic!("Expected issuance, got refusal: {}", reason),
        }
    }

    #[test]
    fn hash_mismatch_refuses_issuance() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, dir.path().join("aud")));
        let registry =
            CertificateRegistry::new(dir.path().join("reg"), vault, &vk)
                .unwrap();

        let evidence = b"test evidence";
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = registry
            .issue_certificate(
                "test".to_string(),
                "1.0".to_string(),
                "PASS".to_string(),
                evidence,
                wrong_hash,
                "working-tree".to_string(),
                Tests {
                    passed: 1,
                    failed: 0,
                    total: 1,
                },
                "gate".to_string(),
                &sk,
            )
            .unwrap();

        match result {
            IssuanceResult::Refused(reason) => {
                assert!(reason.contains("hash mismatch"));
            }
            IssuanceResult::Issued { .. } => panic!("Expected refusal, got issuance"),
        }
    }

    #[test]
    fn blocked_verdict_refuses_and_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, dir.path().join("aud")));
        let registry =
            CertificateRegistry::new(dir.path().join("reg"), vault, &vk)
                .unwrap();

        let evidence = b"evidence";
        let hash = hex::encode(Sha256::digest(evidence));

        // Issue an ACTIVE certificate first
        let result1 = registry
            .issue_certificate(
                "prod".to_string(),
                "1.0".to_string(),
                "PASS".to_string(),
                evidence,
                &hash,
                "working-tree".to_string(),
                Tests {
                    passed: 5,
                    failed: 0,
                    total: 5,
                },
                "gate".to_string(),
                &sk,
            )
            .unwrap();

        let serial1 = match result1 {
            IssuanceResult::Issued { serial, .. } => serial,
            _ => panic!("Expected issuance"),
        };

        // BLOCKED verdict should refuse and revoke
        let result2 = registry
            .issue_certificate(
                "prod".to_string(),
                "1.0".to_string(),
                "BLOCKED".to_string(),
                evidence,
                &hash,
                "working-tree".to_string(),
                Tests {
                    passed: 0,
                    failed: 1,
                    total: 1,
                },
                "gate".to_string(),
                &sk,
            )
            .unwrap();

        match result2 {
            IssuanceResult::Refused(reason) => {
                assert!(reason.contains("BLOCKED"));
                assert!(reason.contains("revoked") || reason.contains("Issuance refused"));
            }
            IssuanceResult::Issued { .. } => panic!("BLOCKED should refuse issuance"),
        }

        // Check that the first certificate is now REVOKED
        let (status, _) = registry.get_status(&serial1);
        assert_eq!(status, CertificateStatus::Revoked);
    }

    #[test]
    fn supersession_across_versions() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, dir.path().join("aud")));
        let registry =
            CertificateRegistry::new(dir.path().join("reg"), vault, &vk)
                .unwrap();

        let evidence1 = b"evidence v1";
        let hash1 = hex::encode(Sha256::digest(evidence1));

        let result1 = registry
            .issue_certificate(
                "myapp".to_string(),
                "1.0.0".to_string(),
                "PASS".to_string(),
                evidence1,
                &hash1,
                "working-tree".to_string(),
                Tests {
                    passed: 10,
                    failed: 0,
                    total: 10,
                },
                "gate-v1".to_string(),
                &sk,
            )
            .unwrap();

        let serial1 = match result1 {
            IssuanceResult::Issued { serial, .. } => serial,
            _ => panic!("Expected issuance"),
        };

        // Issue for v2.0.0 - should supersede v1.0.0
        let evidence2 = b"evidence v2";
        let hash2 = hex::encode(Sha256::digest(evidence2));

        let result2 = registry
            .issue_certificate(
                "myapp".to_string(),
                "2.0.0".to_string(),
                "PASS".to_string(),
                evidence2,
                &hash2,
                "full-history".to_string(),
                Tests {
                    passed: 20,
                    failed: 0,
                    total: 20,
                },
                "gate-v2".to_string(),
                &sk,
            )
            .unwrap();

        let serial2 = match result2 {
            IssuanceResult::Issued { serial, .. } => serial,
            _ => panic!("Expected issuance"),
        };

        // Check that v1 is superseded
        let (status1, _) = registry.get_status(&serial1);
        assert_eq!(status1, CertificateStatus::Superseded);

        // Check that v2 is active and names v1 in supersedes
        let (status2, body2) = registry.get_status(&serial2);
        assert_eq!(status2, CertificateStatus::Active);
        let body2 = body2.unwrap();
        assert_eq!(body2.supersedes, Some(serial1));
    }

    #[test]
    fn explicit_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, dir.path().join("aud")));
        let registry =
            CertificateRegistry::new(dir.path().join("reg"), vault, &vk)
                .unwrap();

        let evidence = b"evidence";
        let hash = hex::encode(Sha256::digest(evidence));

        let result = registry
            .issue_certificate(
                "prod".to_string(),
                "1.0".to_string(),
                "PASS".to_string(),
                evidence,
                &hash,
                "working-tree".to_string(),
                Tests {
                    passed: 1,
                    failed: 0,
                    total: 1,
                },
                "gate".to_string(),
                &sk,
            )
            .unwrap();

        let serial = match result {
            IssuanceResult::Issued { serial, .. } => serial,
            _ => panic!("Expected issuance"),
        };

        // Revoke the certificate
        let msg = registry
            .revoke_certificate(&serial, "operator decision")
            .unwrap();
        assert!(msg.contains("revoked"));

        // Check status
        let (status, _) = registry.get_status(&serial);
        assert_eq!(status, CertificateStatus::Revoked);
    }

    #[test]
    fn status_of_unknown_serial() {
        let dir = tempfile::tempdir().unwrap();
        let (_, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, dir.path().join("aud")));
        let registry =
            CertificateRegistry::new(dir.path().join("reg"), vault, &vk)
                .unwrap();

        let (status, body) = registry.get_status("cert-00000000-999999");
        assert_eq!(status, CertificateStatus::Unknown);
        assert!(body.is_none());
    }

    #[test]
    fn certificate_verifies_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("registry");
        let audit_path = dir.path().join("audit");
        let (sk, vk) = generate_keypair();

        // First instance: issue a certificate
        let vault1 = Arc::new(VaultEnclave::new(1000, audit_path.clone()));
        let registry1 = CertificateRegistry::new(&registry_path, vault1, &vk).unwrap();

        let evidence = b"test evidence";
        let hash = hex::encode(Sha256::digest(evidence));

        let result = registry1
            .issue_certificate(
                "prod".to_string(),
                "1.0".to_string(),
                "PASS".to_string(),
                evidence,
                &hash,
                "working-tree".to_string(),
                Tests {
                    passed: 1,
                    failed: 0,
                    total: 1,
                },
                "gate".to_string(),
                &sk,
            )
            .unwrap();

        let serial = match result {
            IssuanceResult::Issued { serial, .. } => serial,
            _ => panic!("Expected issuance"),
        };

        // Second instance: load from the same registry
        let vault2 = Arc::new(VaultEnclave::new(1000, audit_path.clone()));
        let registry2 = CertificateRegistry::new(&registry_path, vault2, &vk).unwrap();

        let (status, body) = registry2.get_status(&serial);
        assert_eq!(status, CertificateStatus::Active);
        assert!(body.is_some());
        assert_eq!(body.unwrap().product, "prod");
    }

    #[test]
    fn evidence_size_cap_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, dir.path().join("aud")));
        let registry =
            CertificateRegistry::new(dir.path().join("reg"), vault, &vk)
                .unwrap();

        // Create evidence larger than MAX_EVIDENCE_SIZE
        let large_evidence = vec![0u8; MAX_EVIDENCE_SIZE + 1];
        let hash = hex::encode(Sha256::digest(&large_evidence));

        let result = registry.issue_certificate(
            "prod".to_string(),
            "1.0".to_string(),
            "PASS".to_string(),
            &large_evidence,
            &hash,
            "working-tree".to_string(),
            Tests {
                passed: 1,
                failed: 0,
                total: 1,
            },
            "gate".to_string(),
            &sk,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("exceeds"));
        assert!(err.contains("byte limit"));
    }

    #[test]
    fn fingerprint_recomputable_from_sealed_payload() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, dir.path().join("aud")));
        let registry =
            CertificateRegistry::new(dir.path().join("reg"), vault, &vk)
                .unwrap();

        let evidence = b"test evidence";
        let hash = hex::encode(Sha256::digest(evidence));

        let result = registry
            .issue_certificate(
                "prod".to_string(),
                "1.0".to_string(),
                "PASS".to_string(),
                evidence,
                &hash,
                "working-tree".to_string(),
                Tests {
                    passed: 5,
                    failed: 0,
                    total: 5,
                },
                "gate".to_string(),
                &sk,
            )
            .unwrap();

        match result {
            IssuanceResult::Issued {
                serial,
                fingerprint,
                certificate,
            } => {
                // Recompute fingerprint from the sealed payload
                let recomputed_fingerprint = hex::encode(Sha256::digest(&certificate.payload));
                
                // Verify it matches the returned fingerprint
                assert_eq!(fingerprint, recomputed_fingerprint, 
                    "Fingerprint must be recomputable from sealed payload");

                // Verify the sealed payload does NOT contain a "fingerprint" field
                let payload_str = String::from_utf8_lossy(&certificate.payload);
                assert!(!payload_str.contains("\"fingerprint\""), 
                    "Sealed payload must not contain fingerprint field");

                // Verify the certificate can be verified
                assert!(certificate.verify(&vk).is_ok(), 
                    "Certificate signature must verify");

                // Get status and verify fingerprint matches
                let (status, body) = registry.get_status(&serial);
                assert_eq!(status, CertificateStatus::Active);
                let body = body.unwrap();
                assert_eq!(body.fingerprint, fingerprint, 
                    "Stored fingerprint must match returned fingerprint");
                assert_eq!(body.fingerprint, recomputed_fingerprint, 
                    "Stored fingerprint must equal recomputed fingerprint");
            }
            IssuanceResult::Refused(reason) => panic!("Expected issuance, got refusal: {}", reason),
        }
    }

    #[test]
    fn lifecycle_events_in_vault_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit");
        let (sk, vk) = generate_keypair();
        let vault = Arc::new(VaultEnclave::new(1000, audit_path.clone()));
        let registry = CertificateRegistry::new(dir.path().join("reg"), vault.clone(), &vk).unwrap();

        let evidence = b"test evidence";
        let hash = hex::encode(Sha256::digest(evidence));

        // Issue a certificate
        let result = registry
            .issue_certificate(
                "prod".to_string(),
                "1.0".to_string(),
                "PASS".to_string(),
                evidence,
                &hash,
                "working-tree".to_string(),
                Tests {
                    passed: 5,
                    failed: 0,
                    total: 5,
                },
                "gate".to_string(),
                &sk,
            )
            .unwrap();

        let serial = match result {
            IssuanceResult::Issued { serial, .. } => serial,
            _ => panic!("Expected issuance"),
        };

        // Read the vault audit log
        let audit_log = vault.read_audit_log().unwrap();
        
        // Verify that a CERTIFICATE_ISSUED event appears
        let issued_event = audit_log.iter().find(|e| e.verdict == "CERTIFICATE_ISSUED");
        assert!(issued_event.is_some(), "CERTIFICATE_ISSUED event must appear in vault audit log");
        
        let issued = issued_event.unwrap();
        assert_eq!(issued.action_id, hex::encode(serial.as_bytes()));

        // Verify chain integrity
        let verification = vault.verify_chain(&audit_log);
        assert!(verification.verified, "Audit chain must verify after certificate event");
    }
}
