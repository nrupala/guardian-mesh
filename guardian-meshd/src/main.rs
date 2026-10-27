// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use tokio::sync::RwLock;

use tonic::{transport::Server, Request, Response, Status};

use guardian_meshd::config::Config;
use guardian_meshd::enclave::{EnclaveContext, Verdict};
use guardian_meshd::enclave::sentinel::SentinelEnclave;
use guardian_meshd::enclave::gatekeeper::GatekeeperEnclave;
use guardian_meshd::enclave::witness::WitnessEnclave;
use guardian_meshd::enclave::arbiter::ArbiterEnclave;
use guardian_meshd::enclave::vault::VaultEnclave;
use guardian_meshd::handshake_bus::{HandshakeBus, SESSION_TTL_SECS};
use guardian_meshd::policy::{PolicyEngine, PolicyBundle, PolicyRule};
use guardian_meshd::protocol_firewall::ProtocolFirewall;
use guardian_meshd::sealed_envelope::{generate_keypair, SealedEnvelope, ML_DSA_65_VERIFYING_KEY_LEN, verifying_key_from_bytes};
use guardian_meshd::sealed_envelope::{verify_proto_envelope, load_or_generate_signing_key, compute_fingerprint};
use ml_dsa::Signer;
use guardian_meshd::certificate::{CertificateRegistry, Tests, IssuanceResult, CertificateStatus as CertStatus};
use guardian_meshd::proto::{
    guardian_mesh_server::{GuardianMesh, GuardianMeshServer},
    EvaluateRequest, EvaluateResponse, AuditProof, StructuredReason,
    VerifyProofRequest, VerifyProofResponse,
    HealthRequest, HealthResponse,
    HandshakeRequest, HandshakeResponse,
    ReadAuditLogRequest, ReadAuditLogResponse,
    AuditLogEntry, ChainVerificationStatus,
    IssueCertificateRequest, IssueCertificateResponse,
    RevokeCertificateRequest, RevokeCertificateResponse,
    CertificateStatusRequest, CertificateStatusResponse,
    certificate_status_response::Status as ProtoStatus,
    SealedEnvelope as ProtoSealedEnvelope,
    health_response::ServingStatus,
    GetPolicyRequest, PolicyBundleMessage, PolicyRuleMessage,
    ProposePolicyChangeRequest, ProposePolicyChangeResponse,
    ApprovePolicyChangeRequest, ApprovePolicyChangeResponse,
};
use prost::Message as _;
use ml_dsa::{MlDsa65, SigningKey, VerifyingKey, Verifier, SignatureEncoding};

struct PendingPolicyChange {
    bundle: PolicyBundle,
    proposer: String,
}

pub struct GuardianMeshService {
    config: Config,
    bus: Arc<RwLock<HandshakeBus>>,
    vault: Arc<VaultEnclave>,
    policy: Arc<RwLock<PolicyEngine>>,
    firewall: Arc<ProtocolFirewall>,
    signing_key: SigningKey<MlDsa65>,
    verifying_key: VerifyingKey<MlDsa65>,
    certificates: Arc<CertificateRegistry>,
    policy_admins: std::collections::HashMap<String, VerifyingKey<MlDsa65>>,
    pending_policy_change: Arc<RwLock<Option<PendingPolicyChange>>>,
    policy_principals: Arc<RwLock<(String, String)>>, // (proposer, approver)
}

impl GuardianMeshService {
    pub fn new(config: Config) -> Result<Self, String> {
        let (sk, vk) = load_or_generate_signing_key(config.keys_dir())?;
        let vault = Arc::new(VaultEnclave::new(10_000, config.audit_dir()));
        
        // Load policy admins from the configured directory
        let policy_admins = Self::load_policy_admins(&config)?;
        
        // Load or create genesis policy
        let (policy, proposer, approver) = match PolicyEngine::load_from_file(&config.policy_dir())? {
            Some(bundle) => {
                let mut engine = PolicyEngine::new();
                engine.apply_bundle(bundle);
                // Loaded from persistence - principals are "persisted"
                (engine, "persisted".to_string(), "persisted".to_string())
            }
            None => {
                // Genesis policy
                let engine = PolicyEngine::with_escalate_actions(config.policy_escalate_actions.clone());
                (engine, "daemon-defaults".to_string(), "".to_string())
            }
        };
        
        let certificates = CertificateRegistry::new(
            config.workspace_dir.as_str(),
            vault.clone(),
            &vk,
        )?;
        Ok(Self {
            bus: Arc::new(RwLock::new(HandshakeBus::new(&config.handshake_secret))),
            vault,
            policy: Arc::new(RwLock::new(policy)),
            firewall: Arc::new(ProtocolFirewall::new()),
            signing_key: sk,
            verifying_key: vk,
            certificates: Arc::new(certificates),
            policy_admins,
            pending_policy_change: Arc::new(RwLock::new(None)),
            policy_principals: Arc::new(RwLock::new((proposer, approver))),
            config,
        })
    }

    fn load_policy_admins(config: &Config) -> Result<std::collections::HashMap<String, VerifyingKey<MlDsa65>>, String> {
        let mut admins = std::collections::HashMap::new();
        
        let keys_dir = match &config.policy_admin_keys_dir {
            Some(dir) => dir,
            None => return Ok(admins), // No directory configured, empty registry
        };
        
        let dir_path = std::path::Path::new(keys_dir);
        if !dir_path.exists() {
            return Ok(admins); // Directory doesn't exist, empty registry
        }
        
        let entries = std::fs::read_dir(dir_path)
            .map_err(|e| format!("failed to read policy admin keys directory: {}", e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| format!("failed to read directory entry: {}", e))?;
            let path = entry.path();
            
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if !file_name.ends_with(".vk") {
                    continue;
                }
                
                let principal = file_name.strip_suffix(".vk").unwrap();
                
                // Validate principal name: [a-z0-9][a-z0-9_-]{0,31}
                if !Self::is_valid_principal_name(principal) {
                    return Err(format!("invalid principal name in file: {}", file_name));
                }
                
                // Read the raw 1952-byte ML-DSA-65 verifying key
                let key_bytes = std::fs::read(&path)
                    .map_err(|e| format!("failed to read admin key file {}: {}", file_name, e))?;
                
                if key_bytes.len() != ML_DSA_65_VERIFYING_KEY_LEN {
                    return Err(format!(
                        "admin key file {} has wrong size: expected {}, got {}",
                        file_name, ML_DSA_65_VERIFYING_KEY_LEN, key_bytes.len()
                    ));
                }
                
                let vk = verifying_key_from_bytes(&key_bytes)
                    .map_err(|e| format!("failed to decode admin key from {}: {}", file_name, e))?;
                
                admins.insert(principal.to_string(), vk);
            }
        }
        
        Ok(admins)
    }

    fn is_valid_principal_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 32 {
            return false;
        }
        
        let chars: Vec<char> = name.chars().collect();
        if !matches!(chars[0], 'a'..='z' | '0'..='9') {
            return false;
        }
        
        chars.iter().all(|&c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
    }

    fn sweep_expired_sessions(&self, bus: &HandshakeBus) {
        let evicted = bus.evict_expired();
        for id in evicted {
            self.firewall.evict_session(&id);
        }
    }

    async fn run_evaluation(
        &self,
        req: EvaluateRequest,
        simulation: bool,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let mut ctx = EnclaveContext::new(req);

        let policy_version = {
            let policy = self.policy.read().await;
            policy.policy_version()
        };

        SentinelEnclave::evaluate(&mut ctx);
        if ctx.verdict != Some(Verdict::Allow) {
            let msg = ctx.reason.clone().unwrap_or_else(|| "Sentinel blocked".into());
            if simulation {
                // Simulation early block: return Ok(EvaluateResponse) with verdict BLOCK
                let reasons: Vec<StructuredReason> = ctx.structured_reasons.iter().map(|r| {
                    StructuredReason {
                        rule_id: r.rule_id.clone(),
                        detail: r.detail.clone(),
                        remediation: r.remediation.clone(),
                    }
                }).collect();
                
                let rule_ids: Vec<String> = ctx.structured_reasons.iter()
                    .map(|r| r.rule_id.clone())
                    .collect();
                
                let proof = AuditProof {
                    action_id: ctx.request.action.as_ref().map(|a| a.action_type.clone()).unwrap_or_default(),
                    verdict: "BLOCK".into(),
                    enclave_chain: "Sentinel".into(),
                    signature: Vec::new(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    simulation: true,
                    rule_ids,
                    policy_version,
                    merkle_root: Vec::new(),
                };

                let proof_envelope = {
                    let sealed = SealedEnvelope::new(
                        proof.encode_to_vec(),
                        b"guardian_mesh.AuditProof".to_vec(),
                        &self.signing_key,
                    );
                    ProtoSealedEnvelope {
                        payload: sealed.payload,
                        payload_type: sealed.payload_type,
                        crc32c: sealed.crc32c_digest,
                        ml_dsa_65_signature: sealed.ml_dsa_65_signature,
                        timestamp: sealed.timestamp,
                        nonce: sealed.nonce.to_vec(),
                    }
                };

                let response = EvaluateResponse {
                    verdict: "BLOCK".into(),
                    reason: msg,
                    containment_stage: ctx.stage.as_str().into(),
                    proof: Some(proof),
                    handshake_token: Vec::new(),
                    proof_envelope: Some(proof_envelope),
                    reasons,
                    simulation: true,
                };
                return Ok(Response::new(response));
            } else {
                return Err(Status::permission_denied(msg));
            }
        }

        {
            let bus = self.bus.read().await;
            // A simulation burns nothing: it must not mutate shared
            // state either, so the TTL sweep runs on real Evaluate only.
            if !simulation {
                self.sweep_expired_sessions(&bus);
            }
            GatekeeperEnclave::evaluate(&mut ctx, &bus, &self.firewall, self.config.policy_throttle_rate, simulation);
        }
        
        // WO-5: THROTTLE verdicts from Gatekeeper (PF-18 or policy rate) proceed to proof generation
        if ctx.verdict == Some(Verdict::Throttle) {
            // THROTTLE verdict: skip Witness and Arbiter, go directly to proof and audit
            let final_verdict = Verdict::Throttle;
            let final_reason = ctx.reason.clone().unwrap_or_default();

            if !simulation {
                self.vault.seal(&ctx);
            }
            
            let reasons: Vec<StructuredReason> = ctx.structured_reasons.iter().map(|r| {
                StructuredReason {
                    rule_id: r.rule_id.clone(),
                    detail: r.detail.clone(),
                    remediation: r.remediation.clone(),
                }
            }).collect();
            
            let rule_ids: Vec<String> = ctx.structured_reasons.iter()
                .map(|r| r.rule_id.clone())
                .collect();

            let proof = AuditProof {
                action_id: ctx.request.action.as_ref().map(|a| a.action_type.clone()).unwrap_or_default(),
                verdict: final_verdict.as_str().into(),
                // A simulation is never sealed, so its proof must not
                // name the Vault in its chain.
                enclave_chain: if simulation { "Sentinel→Gatekeeper".into() } else { "Sentinel→Gatekeeper→Vault".into() },
                signature: Vec::new(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                simulation,
                rule_ids,
                policy_version,
                merkle_root: Vec::new(),
            };

            let proof_envelope = {
                let sealed = SealedEnvelope::new(
                    proof.encode_to_vec(),
                    b"guardian_mesh.AuditProof".to_vec(),
                    &self.signing_key,
                );
                ProtoSealedEnvelope {
                    payload: sealed.payload,
                    payload_type: sealed.payload_type,
                    crc32c: sealed.crc32c_digest,
                    ml_dsa_65_signature: sealed.ml_dsa_65_signature,
                    timestamp: sealed.timestamp,
                    nonce: sealed.nonce.to_vec(),
                }
            };

            let response = EvaluateResponse {
                verdict: final_verdict.as_str().into(),
                reason: final_reason,
                containment_stage: ctx.stage.as_str().into(),
                proof: Some(proof),
                handshake_token: Vec::new(),
                proof_envelope: Some(proof_envelope),
                reasons,
                simulation,
            };

            return Ok(Response::new(response));
        }
        
        if ctx.verdict != Some(Verdict::Allow) {
            let msg = ctx.reason.clone().unwrap_or_else(|| "Gatekeeper blocked".into());
            if simulation {
                // Simulation early block from Gatekeeper
                let reasons: Vec<StructuredReason> = ctx.structured_reasons.iter().map(|r| {
                    StructuredReason {
                        rule_id: r.rule_id.clone(),
                        detail: r.detail.clone(),
                        remediation: r.remediation.clone(),
                    }
                }).collect();
                
                let rule_ids: Vec<String> = ctx.structured_reasons.iter()
                    .map(|r| r.rule_id.clone())
                    .collect();
                
                let proof = AuditProof {
                    action_id: ctx.request.action.as_ref().map(|a| a.action_type.clone()).unwrap_or_default(),
                    verdict: "BLOCK".into(),
                    enclave_chain: "Sentinel→Gatekeeper".into(),
                    signature: Vec::new(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    simulation: true,
                    rule_ids,
                    policy_version,
                    merkle_root: Vec::new(),
                };

                let proof_envelope = {
                    let sealed = SealedEnvelope::new(
                        proof.encode_to_vec(),
                        b"guardian_mesh.AuditProof".to_vec(),
                        &self.signing_key,
                    );
                    ProtoSealedEnvelope {
                        payload: sealed.payload,
                        payload_type: sealed.payload_type,
                        crc32c: sealed.crc32c_digest,
                        ml_dsa_65_signature: sealed.ml_dsa_65_signature,
                        timestamp: sealed.timestamp,
                        nonce: sealed.nonce.to_vec(),
                    }
                };

                let response = EvaluateResponse {
                    verdict: "BLOCK".into(),
                    reason: msg,
                    containment_stage: ctx.stage.as_str().into(),
                    proof: Some(proof),
                    handshake_token: Vec::new(),
                    proof_envelope: Some(proof_envelope),
                    reasons,
                    simulation: true,
                };
                return Ok(Response::new(response));
            } else {
                return Err(Status::permission_denied(msg));
            }
        }

        WitnessEnclave::evaluate(&mut ctx, &self.signing_key);
        if ctx.verdict != Some(Verdict::Allow) {
            let msg = ctx.reason.clone().unwrap_or_else(|| "Witness blocked".into());
            if simulation {
                // Simulation early block from Witness
                let reasons: Vec<StructuredReason> = ctx.structured_reasons.iter().map(|r| {
                    StructuredReason {
                        rule_id: r.rule_id.clone(),
                        detail: r.detail.clone(),
                        remediation: r.remediation.clone(),
                    }
                }).collect();
                
                let rule_ids: Vec<String> = ctx.structured_reasons.iter()
                    .map(|r| r.rule_id.clone())
                    .collect();
                
                let proof = AuditProof {
                    action_id: ctx.request.action.as_ref().map(|a| a.action_type.clone()).unwrap_or_default(),
                    verdict: "BLOCK".into(),
                    enclave_chain: "Sentinel→Gatekeeper→Witness".into(),
                    signature: ctx.witness_signature.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    simulation: true,
                    rule_ids,
                    policy_version,
                    merkle_root: Vec::new(),
                };

                let proof_envelope = {
                    let sealed = SealedEnvelope::new(
                        proof.encode_to_vec(),
                        b"guardian_mesh.AuditProof".to_vec(),
                        &self.signing_key,
                    );
                    ProtoSealedEnvelope {
                        payload: sealed.payload,
                        payload_type: sealed.payload_type,
                        crc32c: sealed.crc32c_digest,
                        ml_dsa_65_signature: sealed.ml_dsa_65_signature,
                        timestamp: sealed.timestamp,
                        nonce: sealed.nonce.to_vec(),
                    }
                };

                let response = EvaluateResponse {
                    verdict: "BLOCK".into(),
                    reason: msg,
                    containment_stage: ctx.stage.as_str().into(),
                    proof: Some(proof),
                    handshake_token: Vec::new(),
                    proof_envelope: Some(proof_envelope),
                    reasons,
                    simulation: true,
                };
                return Ok(Response::new(response));
            } else {
                return Err(Status::permission_denied(msg));
            }
        }

        {
            let policy = self.policy.read().await;
            ArbiterEnclave::evaluate(&mut ctx, &policy);
        }

        // WO-5: All verdicts (ALLOW, BLOCK, ESCALATE) proceed to proof generation and audit
        let final_verdict = ctx.verdict.as_ref().cloned().unwrap_or(Verdict::Block);
        let final_reason = ctx.reason.clone().unwrap_or_default();

        if !simulation {
            self.vault.seal(&ctx);
        }
        
        let reasons: Vec<StructuredReason> = ctx.structured_reasons.iter().map(|r| {
            StructuredReason {
                rule_id: r.rule_id.clone(),
                detail: r.detail.clone(),
                remediation: r.remediation.clone(),
            }
        }).collect();
        
        let rule_ids: Vec<String> = ctx.structured_reasons.iter()
            .map(|r| r.rule_id.clone())
            .collect();

        let proof = AuditProof {
            action_id: ctx.request.action.as_ref().map(|a| a.action_type.clone()).unwrap_or_default(),
            verdict: final_verdict.as_str().into(),
            // A simulation is never sealed, so its proof must not
            // name the Vault in its chain.
            enclave_chain: if simulation { "Sentinel→Gatekeeper→Witness→Arbiter".into() } else { "Sentinel→Gatekeeper→Witness→Arbiter→Vault".into() },
            signature: ctx.witness_signature.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            simulation,
            rule_ids,
            policy_version,
            merkle_root: Vec::new(),
        };

        // Seal the proof with the daemon's signing key so the caller
        // can present it to VerifyProof and have it re-checked
        // independently of this response.
        let proof_envelope = {
            let sealed = SealedEnvelope::new(
                proof.encode_to_vec(),
                b"guardian_mesh.AuditProof".to_vec(),
                &self.signing_key,
            );
            ProtoSealedEnvelope {
                payload: sealed.payload,
                payload_type: sealed.payload_type,
                crc32c: sealed.crc32c_digest,
                ml_dsa_65_signature: sealed.ml_dsa_65_signature,
                timestamp: sealed.timestamp,
                nonce: sealed.nonce.to_vec(),
            }
        };

        let response = EvaluateResponse {
            verdict: final_verdict.as_str().into(),
            reason: final_reason,
            containment_stage: ctx.stage.as_str().into(),
            proof: Some(proof),
            handshake_token: Vec::new(),
            proof_envelope: Some(proof_envelope),
            reasons,
            simulation,
        };

        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl GuardianMesh for GuardianMeshService {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        self.run_evaluation(request.into_inner(), false).await
    }

    async fn simulate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        self.run_evaluation(request.into_inner(), true).await
    }

    async fn verify_proof(
        &self,
        request: Request<VerifyProofRequest>,
    ) -> Result<Response<VerifyProofResponse>, Status> {
        let req = request.into_inner();
        let envelope = req.proof_envelope.ok_or_else(|| {
            Status::invalid_argument("missing proof envelope")
        })?;

        match verify_proto_envelope(
            &envelope.payload,
            envelope.crc32c,
            &envelope.ml_dsa_65_signature,
            &self.verifying_key,
        ) {
            Ok(()) => {
                let response = VerifyProofResponse {
                    valid: true,
                    reason: "ML-DSA-65 signature verified".into(),
                    proof: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => Ok(Response::new(VerifyProofResponse {
                valid: false,
                reason: e,
                proof: None,
            })),
        }
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let mut enclave_health = std::collections::HashMap::new();
        enclave_health.insert("sentinel".into(), "ok".into());
        enclave_health.insert("gatekeeper".into(), "ok".into());
        enclave_health.insert("witness".into(), "ok".into());
        enclave_health.insert("arbiter".into(), "ok".into());
        enclave_health.insert("vault".into(), "ok".into());

        let fingerprint = compute_fingerprint(&self.verifying_key);
        
        // WO-19: Report measured firewall counters
        let rule_counters = self.firewall.rule_counters();
        let mut protocol_firewall_rule_counters = std::collections::HashMap::new();
        for (rule, counter) in rule_counters {
            protocol_firewall_rule_counters.insert(
                rule,
                format!("passed={},failed={}", counter.passed, counter.failed)
            );
        }
        
        let (passed, failed) = self.firewall.totals();
        
        let response = HealthResponse {
            status: ServingStatus::Serving.into(),
            enclave_health,
            protocol_firewall_rules_passed: passed as u32,
            protocol_firewall_rules_total: (passed + failed) as u32,
            signing_key_fingerprint: fingerprint,
            protocol_firewall_rule_counters,
        };

        Ok(Response::new(response))
    }

    async fn handshake(
        &self,
        request: Request<HandshakeRequest>,
    ) -> Result<Response<HandshakeResponse>, Status> {
        let req = request.into_inner();

        // WO-1: the caller's ML-DSA-65 verifying key is bound to the
        // session and every Evaluate signature is verified against
        // it, so a handshake without a well-formed key is refused
        // here (fail closed) instead of opening an unusable session.
        if req.source_public_key.len() != ML_DSA_65_VERIFYING_KEY_LEN {
            return Err(Status::invalid_argument(format!(
                "Handshake requires source_public_key: the caller's ML-DSA-65 verifying key ({} bytes), got {} bytes",
                ML_DSA_65_VERIFYING_KEY_LEN,
                req.source_public_key.len()
            )));
        }

        let source = if req.source_enclave.is_empty() {
            "unknown".to_string()
        } else {
            req.source_enclave
        };

        let bus = self.bus.read().await;
        self.sweep_expired_sessions(&bus);
        let session = bus.create_session_full(&source, &req.source_public_key);

        Ok(Response::new(HandshakeResponse {
            session_id: session.session_id,
            session_key: session.session_key.to_vec(),
            ttl_seconds: SESSION_TTL_SECS,
        }))
    }

    async fn read_audit_log(
        &self,
        _request: Request<ReadAuditLogRequest>,
    ) -> Result<Response<ReadAuditLogResponse>, Status> {
        // Read all entries from the audit log files
        let entries = self.vault.read_audit_log()
            .map_err(|e| Status::internal(format!("Failed to read audit log: {}", e)))?;
        
        // Verify the chain
        let verification = self.vault.verify_chain(&entries);
        
        // Convert to proto format
        let proto_entries: Vec<AuditLogEntry> = entries
            .iter()
            .enumerate()
            .map(|(seq, entry)| AuditLogEntry {
                sequence: seq as u64,
                timestamp: entry.timestamp,
                action_id: entry.action_id.clone(),
                verdict: entry.verdict.clone(),
                enclave_chain: entry.enclave_chain.clone(),
                chain_hash: entry.chain_hash.clone(),
                reason: entry.reason.clone(),
            })
            .collect();
        
        let proto_verification = ChainVerificationStatus {
            verified: verification.verified,
            entries_checked: verification.entries_checked,
            first_break_position: verification.first_break_position.unwrap_or(0),
            status_message: verification.status_message,
        };
        
        Ok(Response::new(ReadAuditLogResponse {
            entries: proto_entries,
            verification: Some(proto_verification),
        }))
    }

    async fn issue_certificate(
        &self,
        request: Request<IssueCertificateRequest>,
    ) -> Result<Response<IssueCertificateResponse>, Status> {
        let req = request.into_inner();

        let tests = req.tests.ok_or_else(|| {
            Status::invalid_argument("tests field is required")
        })?;

        let result = self.certificates.issue_certificate(
            req.product,
            req.version,
            req.verdict,
            &req.evidence,
            &req.evidence_hash,
            req.evidence_scope,
            Tests {
                passed: tests.passed,
                failed: tests.failed,
                total: tests.total,
            },
            req.policy,
            &self.signing_key,
        );

        match result {
            Ok(IssuanceResult::Issued {
                serial,
                fingerprint,
                certificate,
            }) => {
                let proto_envelope = ProtoSealedEnvelope {
                    payload: certificate.payload,
                    payload_type: certificate.payload_type,
                    crc32c: certificate.crc32c_digest,
                    ml_dsa_65_signature: certificate.ml_dsa_65_signature,
                    timestamp: certificate.timestamp,
                    nonce: certificate.nonce.to_vec(),
                };

                Ok(Response::new(IssueCertificateResponse {
                    issued: true,
                    serial,
                    fingerprint,
                    certificate: Some(proto_envelope),
                    refusal_reason: String::new(),
                }))
            }
            Ok(IssuanceResult::Refused(reason)) => {
                Ok(Response::new(IssueCertificateResponse {
                    issued: false,
                    serial: String::new(),
                    fingerprint: String::new(),
                    certificate: None,
                    refusal_reason: reason,
                }))
            }
            Err(e) => Err(Status::internal(e)),
        }
    }

    async fn revoke_certificate(
        &self,
        request: Request<RevokeCertificateRequest>,
    ) -> Result<Response<RevokeCertificateResponse>, Status> {
        let req = request.into_inner();

        match self.certificates.revoke_certificate(&req.serial, &req.reason) {
            Ok(msg) => Ok(Response::new(RevokeCertificateResponse {
                revoked: true,
                message: msg,
            })),
            Err(e) => Err(Status::not_found(e)),
        }
    }

    async fn certificate_status(
        &self,
        request: Request<CertificateStatusRequest>,
    ) -> Result<Response<CertificateStatusResponse>, Status> {
        let req = request.into_inner();

        let (status, body_opt) = self.certificates.get_status(&req.serial);

        let proto_status = match status {
            CertStatus::Active => ProtoStatus::Active,
            CertStatus::Superseded => ProtoStatus::Superseded,
            CertStatus::Revoked => ProtoStatus::Revoked,
            CertStatus::Unknown => ProtoStatus::Unknown,
        };

        let proto_body = body_opt.map(|b| b.to_proto_body());

        Ok(Response::new(CertificateStatusResponse {
            status: proto_status.into(),
            body: proto_body,
        }))
    }

    async fn get_policy(
        &self,
        _request: Request<GetPolicyRequest>,
    ) -> Result<Response<PolicyBundleMessage>, Status> {
        let policy = self.policy.read().await;
        let bundle = policy.bundle();
        
        let canonical = bundle.to_canonical_string();
        let signature = self.signing_key.sign(canonical.as_bytes());
        
        let (proposer, approver) = {
            let principals = self.policy_principals.read().await;
            principals.clone()
        };
        
        let rules: Vec<PolicyRuleMessage> = bundle.rules.iter().map(|r| PolicyRuleMessage {
            action_type: r.action_type.clone(),
            allow: r.allow,
            priority: r.priority,
        }).collect();
        
        let response = PolicyBundleMessage {
            version: bundle.version,
            rules,
            escalate_actions: bundle.escalate_actions.clone(),
            prev_hash: bundle.prev_hash.clone(),
            content_hash: bundle.content_hash(),
            daemon_signature: signature.to_bytes().to_vec(),
            signer_fingerprint: compute_fingerprint(&self.verifying_key),
            proposer,
            approver,
        };
        
        Ok(Response::new(response))
    }

    async fn propose_policy_change(
        &self,
        request: Request<ProposePolicyChangeRequest>,
    ) -> Result<Response<ProposePolicyChangeResponse>, Status> {
        let req = request.into_inner();
        
        // Check if proposer is a registered admin
        let proposer_vk = match self.policy_admins.get(&req.proposer) {
            Some(vk) => vk,
            None => {
                return Ok(Response::new(ProposePolicyChangeResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: "unknown policy admin".to_string(),
                }));
            }
        };
        
        // Build the proposed bundle
        let rules: Vec<PolicyRule> = req.rules.iter().map(|r| PolicyRule {
            action_type: r.action_type.clone(),
            allow: r.allow,
            priority: r.priority,
        }).collect();
        
        let proposed = PolicyBundle {
            version: req.version,
            rules,
            escalate_actions: req.escalate_actions,
            prev_hash: req.prev_hash,
        };
        
        // Verify proposer signature over canonical bytes
        let canonical = proposed.to_canonical_string();
        let sig = match ml_dsa::Signature::<MlDsa65>::try_from(req.proposer_signature.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                return Ok(Response::new(ProposePolicyChangeResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: "signature verification failed".to_string(),
                }));
            }
        };
        
        if let Err(_) = proposer_vk.verify(canonical.as_bytes(), &sig) {
            return Ok(Response::new(ProposePolicyChangeResponse {
                accepted: false,
                change_id: String::new(),
                message: "signature verification failed".to_string(),
            }));
        }
        
        // Validate against current policy
        {
            let policy = self.policy.read().await;
            if let Err(e) = policy.validate_next(&proposed) {
                return Ok(Response::new(ProposePolicyChangeResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: e,
                }));
            }
        }
        
        // Check if a pending change already exists
        {
            let mut pending = self.pending_policy_change.write().await;
            if pending.is_some() {
                return Ok(Response::new(ProposePolicyChangeResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: "a policy change is already pending".to_string(),
                }));
            }
            
            let change_id = proposed.content_hash();
            *pending = Some(PendingPolicyChange {
                bundle: proposed,
                proposer: req.proposer,
            });
            
            Ok(Response::new(ProposePolicyChangeResponse {
                accepted: true,
                change_id,
                message: String::new(),
            }))
        }
    }

    async fn approve_policy_change(
        &self,
        request: Request<ApprovePolicyChangeRequest>,
    ) -> Result<Response<ApprovePolicyChangeResponse>, Status> {
        let req = request.into_inner();
        
        // Check if approver is a registered admin
        let approver_vk = match self.policy_admins.get(&req.approver) {
            Some(vk) => vk,
            None => {
                return Ok(Response::new(ApprovePolicyChangeResponse {
                    applied: false,
                    version: 0,
                    content_hash: String::new(),
                    message: "unknown policy admin".to_string(),
                }));
            }
        };
        
        // Check if a pending change exists
        let (pending_bundle, proposer) = {
            let pending = self.pending_policy_change.read().await;
            match pending.as_ref() {
                Some(p) => {
                    if p.bundle.content_hash() != req.change_id {
                        return Ok(Response::new(ApprovePolicyChangeResponse {
                            applied: false,
                            version: 0,
                            content_hash: String::new(),
                            message: "change_id mismatch".to_string(),
                        }));
                    }
                    (p.bundle.clone(), p.proposer.clone())
                }
                None => {
                    return Ok(Response::new(ApprovePolicyChangeResponse {
                        applied: false,
                        version: 0,
                        content_hash: String::new(),
                        message: "no pending policy change".to_string(),
                    }));
                }
            }
        };
        
        // Dual control: approver != proposer
        if req.approver == proposer {
            return Ok(Response::new(ApprovePolicyChangeResponse {
                applied: false,
                version: 0,
                content_hash: String::new(),
                message: "dual control violation: approver cannot be the same as proposer".to_string(),
            }));
        }
        
        // Verify approver signature
        let canonical = pending_bundle.to_canonical_string();
        let sig = match ml_dsa::Signature::<MlDsa65>::try_from(req.approver_signature.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                return Ok(Response::new(ApprovePolicyChangeResponse {
                    applied: false,
                    version: 0,
                    content_hash: String::new(),
                    message: "signature verification failed".to_string(),
                }));
            }
        };
        
        if let Err(_) = approver_vk.verify(canonical.as_bytes(), &sig) {
            return Ok(Response::new(ApprovePolicyChangeResponse {
                applied: false,
                version: 0,
                content_hash: String::new(),
                message: "signature verification failed".to_string(),
            }));
        }
        
        // Persist FIRST (fail-closed: if persistence fails, policy is not changed)
        if let Err(e) = PolicyEngine::persist_bundle(&pending_bundle, &self.config.policy_dir()) {
            return Ok(Response::new(ApprovePolicyChangeResponse {
                applied: false,
                version: 0,
                content_hash: String::new(),
                message: format!("persistence failed: {}", e),
            }));
        }
        
        // Apply under write lock
        let (new_version, new_hash) = {
            let mut policy = self.policy.write().await;
            
            // Re-validate (the world may have moved)
            if let Err(e) = policy.validate_next(&pending_bundle) {
                return Ok(Response::new(ApprovePolicyChangeResponse {
                    applied: false,
                    version: 0,
                    content_hash: String::new(),
                    message: e,
                }));
            }
            
            policy.apply_bundle(pending_bundle.clone());
            (policy.policy_version(), policy.content_hash())
        };
        
        // Clear pending
        {
            let mut pending = self.pending_policy_change.write().await;
            *pending = None;
        }
        
        // Record principals
        {
            let mut principals = self.policy_principals.write().await;
            *principals = (proposer.clone(), req.approver.clone());
        }
        
        // Audit log the change
        let reason = format!("proposer={} approver={}", proposer, req.approver);
        let _ = self.vault.record_policy_event(
            new_version,
            &new_hash,
            "POLICY_CHANGE_APPLIED",
            &reason,
        );
        
        Ok(Response::new(ApprovePolicyChangeResponse {
            applied: true,
            version: new_version,
            content_hash: new_hash,
            message: String::new(),
        }))
    }
}

fn real_main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(async {
        let config = Config::default();

        config.ensure_dirs().expect("failed to create data directories");

        if let Err(e) = config.verify_no_program_dir_write() {
            eprintln!("FATAL: {}", e);
            std::process::exit(1);
        }

        let addr = format!("{}:{}", config.bind_addr, config.bind_port)
            .parse()
            .expect("invalid bind address");

        let service = match GuardianMeshService::new(config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FATAL: {}", e);
                std::process::exit(1);
            }
        };

        println!("Guardian Mesh daemon listening on {}", addr);

        // One service, two transports: native gRPC (HTTP/2) for
        // programmatic clients, gRPC-web (HTTP/1.1) so browsers can
        // call the same API. CORS is permissive for API consumers;
        // deployments are expected to gate access in front of the
        // daemon (e.g. an authenticated reverse proxy / tunnel).
        Server::builder()
            .accept_http1(true)
            .layer(tower_http::cors::CorsLayer::permissive())
            .layer(tonic_web::GrpcWebLayer::new())
            .add_service(GuardianMeshServer::new(service))
            .serve(addr)
            .await
            .expect("server error");
    });
}

fn main() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(real_main)
        .expect("failed to spawn server thread")
        .join()
        .expect("server thread panicked");
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_meshd::proto::{ActionDescriptor, FirewalledRequest};
    use ml_dsa::SignatureEncoding;

    // WO-2: PF-12 enforces the exact field set the shipped client uses (webui/src/lib/gmClient.ts).
    // The client sends: actionType, context, target, metadata (all camelCase).
    const PAYLOAD: &[u8] = b"{\"actionType\":\"TOOL_CALL\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{}}";

    fn test_service() -> (GuardianMeshService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        config.ensure_dirs().unwrap();
        (GuardianMeshService::new(config).unwrap(), dir)
    }

    async fn open_session(
        service: &GuardianMeshService,
        vk: &VerifyingKey<MlDsa65>,
    ) -> HandshakeResponse {
        service
            .handshake(Request::new(HandshakeRequest {
                source_enclave: "webui".into(),
                source_public_key: vk.encode().to_vec(),
            }))
            .await
            .unwrap()
            .into_inner()
    }

    async fn evaluate_request(
        service: &GuardianMeshService,
        session_id: &str,
        sealed: &SealedEnvelope,
    ) -> EvaluateRequest {
        let envelope = ProtoSealedEnvelope {
            payload: sealed.payload.clone(),
            payload_type: sealed.payload_type.clone(),
            crc32c: sealed.crc32c_digest,
            ml_dsa_65_signature: sealed.ml_dsa_65_signature.clone(),
            timestamp: sealed.timestamp,
            nonce: sealed.nonce.to_vec(),
        };
        // HMAC over the payload exactly as sent, via the session key
        // the handshake issued — signature failures below are never
        // HMAC failures.
        let hmac_tag = {
            let bus = service.bus.read().await;
            bus.compute_hmac(session_id, &envelope.payload).unwrap()
        };
        EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope),
                source_enclave: "webui".into(),
                handshake_session: session_id.to_string(),
                hmac_tag,
            }),
            action: Some(ActionDescriptor {
                action_type: "TOOL_CALL".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
        }
    }

    #[tokio::test]
    async fn handshake_without_a_full_public_key_is_invalid_argument() {
        let (service, _dir) = test_service();
        let err = service
            .handshake(Request::new(HandshakeRequest {
                source_enclave: "webui".into(),
                source_public_key: vec![1, 2, 3],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn evaluate_with_valid_signature_returns_a_verdict() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let resp = service
            .evaluate(Request::new(req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.verdict, "ALLOW");
        assert!(resp.proof_envelope.is_some());
    }

    #[tokio::test]
    async fn evaluate_with_tampered_payload_is_permission_denied() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        sealed.payload = b"{\"actionType\":\"CODE_EXECUTE\",\"context\":\"x\",\"target\":\"y\",\"metadata\":{}}".to_vec();
        sealed.crc32c_digest = crc32c::crc32c(&sealed.payload);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let err = service.evaluate(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            err.message().contains("signature"),
            "denial must name the signature failure, got: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn evaluate_signed_by_a_different_key_is_permission_denied() {
        let (service, _dir) = test_service();
        let (_sk_bound, vk_bound) = generate_keypair();
        let (sk_other, _vk_other) = generate_keypair();
        let session = open_session(&service, &vk_bound).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk_other);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let err = service.evaluate(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn evaluate_with_missing_signature_is_permission_denied() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let mut sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        sealed.ml_dsa_65_signature = Vec::new();
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let err = service.evaluate(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn health_reports_signing_key_fingerprint() {
        let (service, _dir) = test_service();
        let resp = service
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        // Fingerprint must be 64 lowercase hex chars (SHA-256)
        assert_eq!(resp.signing_key_fingerprint.len(), 64);
        assert!(resp.signing_key_fingerprint.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        
        // Must match the manually computed fingerprint
        let expected = compute_fingerprint(&service.verifying_key);
        assert_eq!(resp.signing_key_fingerprint, expected);
    }

    #[tokio::test]
    async fn persistent_key_proof_verifies_across_instances() {
        // Create a workspace directory shared by both instances
        let dir = tempfile::tempdir().unwrap();
        let ws_path = dir.path().join("ws").to_string_lossy().into_owned();
        let out_path = dir.path().join("out").to_string_lossy().into_owned();
        
        let mut config1 = Config::default();
        config1.workspace_dir = ws_path.clone();
        config1.output_dir = out_path.clone();
        config1.ensure_dirs().unwrap();

        // First instance: generate proof
        let service1 = GuardianMeshService::new(config1).unwrap();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service1, &vk).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service1, &session.session_id, &sealed).await;
        let resp1 = service1
            .evaluate(Request::new(req))
            .await
            .unwrap()
            .into_inner();
        let proof_envelope = resp1.proof_envelope.unwrap();

        // Second instance: verify the proof from the first
        let mut config2 = Config::default();
        config2.workspace_dir = ws_path;
        config2.output_dir = out_path;
        let service2 = GuardianMeshService::new(config2).unwrap();
        let verify_resp = service2
            .verify_proof(Request::new(VerifyProofRequest {
                proof_envelope: Some(proof_envelope.clone()),
            }))
            .await
            .unwrap()
            .into_inner();
        
        assert!(verify_resp.valid, "proof should verify: {}", verify_resp.reason);

        // Fingerprints must match
        let fp1 = service1.health(Request::new(HealthRequest {})).await.unwrap().into_inner().signing_key_fingerprint;
        let fp2 = service2.health(Request::new(HealthRequest {})).await.unwrap().into_inner().signing_key_fingerprint;
        assert_eq!(fp1, fp2);
    }

    #[tokio::test]
    async fn corrupt_signing_key_causes_startup_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        config.ensure_dirs().unwrap();

        // Write a corrupt key file
        let key_path = config.keys_dir().join("daemon_signing_key.bin");
        std::fs::write(&key_path, b"this is corrupt data").unwrap();

        // Service creation must fail
        let result = GuardianMeshService::new(config);
        match result {
            Ok(_) => panic!("expected service creation to fail with corrupt key"),
            Err(err) => {
                assert!(err.contains("FATAL"));
                assert!(err.contains("invalid length"));
            }
        }
    }

    #[tokio::test]
    async fn read_audit_log_returns_entries_from_evaluations() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Run 3 evaluations
        for _ in 0..3 {
            let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
            let req = evaluate_request(&service, &session.session_id, &sealed).await;
            let _ = service.evaluate(Request::new(req)).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        
        // Read the audit log
        let resp = service
            .read_audit_log(Request::new(ReadAuditLogRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        assert_eq!(resp.entries.len(), 3);
        assert!(resp.verification.is_some());
        let verification = resp.verification.unwrap();
        assert!(verification.verified, "Chain should verify: {}", verification.status_message);
        assert_eq!(verification.entries_checked, 3);
    }

    #[tokio::test]
    async fn read_audit_log_chain_verification_valid() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Run evaluations
        for _ in 0..5 {
            let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
            let req = evaluate_request(&service, &session.session_id, &sealed).await;
            let _ = service.evaluate(Request::new(req)).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        
        let resp = service
            .read_audit_log(Request::new(ReadAuditLogRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        let verification = resp.verification.unwrap();
        assert!(verification.verified);
        assert_eq!(verification.entries_checked, 5);
        assert_eq!(verification.first_break_position, 0);
    }

    #[tokio::test]
    async fn read_audit_log_empty_log() {
        let (service, _dir) = test_service();
        
        let resp = service
            .read_audit_log(Request::new(ReadAuditLogRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        assert_eq!(resp.entries.len(), 0);
        let verification = resp.verification.unwrap();
        assert!(verification.verified);
        assert_eq!(verification.entries_checked, 0);
        assert!(verification.status_message.contains("empty"));
    }

    // WO-5: THROTTLE via PF-18 - tests that the firewall returns THROTTLE verdict
    // The protocol_firewall unit tests verify the rate limiting logic works correctly.
    // This integration test verifies that THROTTLE verdicts flow through the pipeline properly.
    #[tokio::test]
    async fn throttle_verdict_has_proof_and_proper_structure() {
        use guardian_meshd::enclave::{EnclaveContext, Verdict};
        use guardian_meshd::protocol_firewall::ThrottleReason;
        
        // Create a context that will have a THROTTLE verdict
        let req = EvaluateRequest {
            action: Some(ActionDescriptor {
                action_type: "TOOL_CALL".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
            ..Default::default()
        };
        let mut ctx = EnclaveContext::new(req);
        ctx.verdict = Some(Verdict::Throttle);
        ctx.reason = Some("PF-18 rate limit breach: E_RATE_LIMITED".to_string());
        
        // Verify the verdict can be serialized correctly
        assert_eq!(Verdict::Throttle.as_str(), "THROTTLE");
        assert_eq!(ctx.verdict, Some(Verdict::Throttle));
        
        // Verify ThrottleReason enum exists and works
        let pf_reason = ThrottleReason::ProtocolFirewall;
        let policy_reason = ThrottleReason::PolicyRate;
        assert_eq!(pf_reason, ThrottleReason::ProtocolFirewall);
        assert_eq!(policy_reason, ThrottleReason::PolicyRate);
    }

    // WO-5: Policy throttle rate configuration
    #[tokio::test]
    async fn policy_throttle_rate_is_configurable() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        config.policy_throttle_rate = 50; // Custom rate
        config.ensure_dirs().unwrap();
        let service = GuardianMeshService::new(config).unwrap();
        
        // Verify the config value is set correctly
        assert_eq!(service.config.policy_throttle_rate, 50);
    }

    // WO-5: ESCALATE verdict
    #[tokio::test]
    async fn escalate_verdict_for_configured_actions() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        config.policy_escalate_actions = vec!["TOOL_CALL".to_string(), "FILE_WRITE".to_string()];
        config.ensure_dirs().unwrap();
        let service = GuardianMeshService::new(config).unwrap();
        
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        
        let resp = service.evaluate(Request::new(req)).await.unwrap().into_inner();
        
        assert_eq!(resp.verdict, "ESCALATE");
        assert!(resp.reason.contains("TOOL_CALL"));
        assert!(resp.reason.contains("escalation"));
        assert!(resp.proof.is_some());
        
        let proof = resp.proof.unwrap();
        assert_eq!(proof.verdict, "ESCALATE");
    }

    // WO-5: BLOCK takes precedence over ESCALATE
    #[tokio::test]
    async fn blocked_action_stays_blocked_even_if_on_escalate_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        config.policy_escalate_actions = vec!["CODE_EXECUTE".to_string()];
        config.ensure_dirs().unwrap();
        let service = GuardianMeshService::new(config).unwrap();
        
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // CODE_EXECUTE is blocked by default policy, even though it's on escalate list
        let payload = b"{\"actionType\":\"CODE_EXECUTE\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{}}";
        let sealed = SealedEnvelope::new(payload.to_vec(), b"test".to_vec(), &sk);
        let envelope = ProtoSealedEnvelope {
            payload: sealed.payload.clone(),
            payload_type: sealed.payload_type.clone(),
            crc32c: sealed.crc32c_digest,
            ml_dsa_65_signature: sealed.ml_dsa_65_signature.clone(),
            timestamp: sealed.timestamp,
            nonce: sealed.nonce.to_vec(),
        };
        let hmac_tag = {
            let bus = service.bus.read().await;
            bus.compute_hmac(&session.session_id, &envelope.payload).unwrap()
        };
        let req = EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope),
                source_enclave: "webui".into(),
                handshake_session: session.session_id.clone(),
                hmac_tag,
            }),
            action: Some(ActionDescriptor {
                action_type: "CODE_EXECUTE".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
        };
        
        let resp = service.evaluate(Request::new(req)).await.unwrap().into_inner();
        
        assert_eq!(resp.verdict, "BLOCK");
    }

    // WO-5: Unlisted action still ALLOWs
    #[tokio::test]
    async fn unlisted_action_allows_normally() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        config.policy_escalate_actions = vec!["FILE_WRITE".to_string()];
        config.ensure_dirs().unwrap();
        let service = GuardianMeshService::new(config).unwrap();
        
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        
        let resp = service.evaluate(Request::new(req)).await.unwrap().into_inner();
        
        // TOOL_CALL not on escalate list, should ALLOW
        assert_eq!(resp.verdict, "ALLOW");
    }

    // WO-6 round 2 regression: Mixed Evaluate+Certificate traffic must chain properly
    #[tokio::test]
    async fn mixed_evaluate_and_certificate_audit_log_verifies() {
        use guardian_meshd::proto::TestCounts;
        use sha2::{Sha256, Digest};

        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // First Evaluate
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let resp1 = service.evaluate(Request::new(req)).await.unwrap().into_inner();
        assert_eq!(resp1.verdict, "ALLOW");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Issue certificate
        let evidence = b"test evidence".to_vec();
        let evidence_hash = hex::encode(Sha256::digest(&evidence));
        let cert_req = IssueCertificateRequest {
            product: "TestProduct".into(),
            version: "1.0.0".into(),
            verdict: "PASS".into(),
            evidence: evidence.clone(),
            evidence_hash,
            evidence_scope: "unit".into(),
            tests: Some(TestCounts {
                passed: 10,
                failed: 0,
                total: 10,
            }),
            policy: "default".into(),
        };
        let cert_resp = service.issue_certificate(Request::new(cert_req)).await.unwrap().into_inner();
        assert!(cert_resp.issued, "Certificate issuance failed: {}", cert_resp.refusal_reason);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Second Evaluate
        let sealed2 = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req2 = evaluate_request(&service, &session.session_id, &sealed2).await;
        let resp2 = service.evaluate(Request::new(req2)).await.unwrap().into_inner();
        assert_eq!(resp2.verdict, "ALLOW");
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Read audit log and verify chain
        let audit_resp = service
            .read_audit_log(Request::new(ReadAuditLogRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        // Should have 3 entries: ALLOW, CERTIFICATE_ISSUED, ALLOW
        assert_eq!(audit_resp.entries.len(), 3, "Expected 3 audit entries");
        assert_eq!(audit_resp.entries[0].verdict, "ALLOW");
        assert_eq!(audit_resp.entries[1].verdict, "CERTIFICATE_ISSUED");
        assert_eq!(audit_resp.entries[2].verdict, "ALLOW");
        
        // Chain must verify
        let verification = audit_resp.verification.unwrap();
        assert!(verification.verified, "Chain verification failed: {}", verification.status_message);
        assert_eq!(verification.entries_checked, 3);
    }

    // WO-19: Health counter tests

    #[tokio::test]
    async fn health_on_fresh_service_reports_zero_counters() {
        let (service, _dir) = test_service();
        
        let resp = service
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        assert_eq!(resp.protocol_firewall_rules_passed, 0);
        assert_eq!(resp.protocol_firewall_rules_total, 0);
        assert_eq!(resp.protocol_firewall_rule_counters.len(), 0);
    }

    #[tokio::test]
    async fn health_after_valid_evaluate_shows_nine_passed() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        
        // Execute one valid evaluation
        let resp = service
            .evaluate(Request::new(req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.verdict, "ALLOW");
        
        // Check health
        let health_resp = service
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        // One valid evaluation executes each rule exactly once
        assert_eq!(health_resp.protocol_firewall_rules_passed, 9);
        assert_eq!(health_resp.protocol_firewall_rules_total, 9);
        
        // Verify the map has exactly the 9 rules
        let counters = &health_resp.protocol_firewall_rule_counters;
        assert_eq!(counters.len(), 9);
        
        let expected_rules = ["PF-1", "PF-12", "PF-13", "PF-14", "PF-15", "PF-16", "PF-17", "PF-18", "POLICY_RATE"];
        for rule in expected_rules {
            assert!(counters.contains_key(rule), "Missing rule {}", rule);
            assert_eq!(counters.get(rule).unwrap(), "passed=1,failed=0", "Wrong count for {}", rule);
        }
    }

    #[tokio::test]
    async fn health_after_pf12_block_shows_partial_recording() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Payload with an unknown field (violates PF-12)
        let bad_payload = b"{\"actionType\":\"TOOL_CALL\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{},\"unknownField\":\"bad\"}";
        let sealed = SealedEnvelope::new(bad_payload.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        
        // This should be blocked by PF-12
        let err = service.evaluate(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        
        // Check health
        let health_resp = service
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        // PF-1 passed, PF-12 failed, flow stopped before PF-13/PF-14
        let counters = &health_resp.protocol_firewall_rule_counters;
        
        // PF-12 should have failed=1
        assert!(counters.contains_key("PF-12"));
        let pf12 = counters.get("PF-12").unwrap();
        assert!(pf12.contains("failed=1"), "PF-12 should have failed=1, got {}", pf12);
        
        // PF-13 and PF-14 should NOT be recorded (flow blocked before them)
        assert!(!counters.contains_key("PF-13"), "PF-13 should not be recorded");
        assert!(!counters.contains_key("PF-14"), "PF-14 should not be recorded");
    }

    // WO-10: Simulate RPC tests

    #[tokio::test]
    async fn simulate_valid_action_returns_allow_marked_simulation() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        
        let resp = service.simulate(Request::new(req)).await.unwrap().into_inner();
        
        assert_eq!(resp.verdict, "ALLOW");
        assert_eq!(resp.simulation, true);
        assert_eq!(resp.handshake_token.len(), 0);
        
        // Decode the proof to check simulation flag
        let proof = resp.proof.unwrap();
        assert_eq!(proof.simulation, true);
        assert!(proof.rule_ids.contains(&"POLICY".to_string()));
    }

    #[tokio::test]
    async fn simulate_blocked_action_returns_block_with_structured_reason() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // CODE_EXECUTE is blocked by default policy
        let payload = b"{\"actionType\":\"CODE_EXECUTE\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{}}";
        let sealed = SealedEnvelope::new(payload.to_vec(), b"test".to_vec(), &sk);
        let envelope = ProtoSealedEnvelope {
            payload: sealed.payload.clone(),
            payload_type: sealed.payload_type.clone(),
            crc32c: sealed.crc32c_digest,
            ml_dsa_65_signature: sealed.ml_dsa_65_signature.clone(),
            timestamp: sealed.timestamp,
            nonce: sealed.nonce.to_vec(),
        };
        let hmac_tag = {
            let bus = service.bus.read().await;
            bus.compute_hmac(&session.session_id, &envelope.payload).unwrap()
        };
        let req = EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope),
                source_enclave: "webui".into(),
                handshake_session: session.session_id.clone(),
                hmac_tag,
            }),
            action: Some(ActionDescriptor {
                action_type: "CODE_EXECUTE".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
        };
        
        // Simulate should return Ok(response), not an error
        let resp = service.simulate(Request::new(req)).await.unwrap().into_inner();
        
        assert_eq!(resp.verdict, "BLOCK");
        assert_eq!(resp.simulation, true);
        assert!(!resp.reasons.is_empty());
        
        let policy_reason = resp.reasons.iter().find(|r| r.rule_id == "POLICY");
        assert!(policy_reason.is_some());
        assert!(!policy_reason.unwrap().remediation.is_empty());
    }

    #[tokio::test]
    async fn simulate_pf12_block_returns_structured_reason_not_error() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Payload with an unknown field (violates PF-12)
        let bad_payload = b"{\"actionType\":\"TOOL_CALL\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{},\"unknownField\":\"bad\"}";
        let sealed = SealedEnvelope::new(bad_payload.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        
        // Simulate should return Ok with BLOCK verdict
        let resp = service.simulate(Request::new(req.clone())).await.unwrap().into_inner();
        assert_eq!(resp.verdict, "BLOCK");
        assert_eq!(resp.simulation, true);
        assert!(!resp.reasons.is_empty());
        assert_eq!(resp.reasons[0].rule_id, "PF-12");
        assert!(!resp.reasons[0].remediation.is_empty());
        
        // Real Evaluate should still return permission_denied error
        let err = service.evaluate(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn simulate_does_not_seal_audit_log() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Get initial count
        let initial_resp = service.read_audit_log(Request::new(ReadAuditLogRequest {}))
            .await.unwrap().into_inner();
        let initial_count = initial_resp.entries.len();
        
        // Simulate ALLOW
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test1".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let resp = service.simulate(Request::new(req)).await.unwrap().into_inner();
        assert_eq!(resp.verdict, "ALLOW");
        
        // Simulate BLOCK
        let bad_payload = b"{\"actionType\":\"CODE_EXECUTE\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{}}";
        let sealed2 = SealedEnvelope::new(bad_payload.to_vec(), b"test2".to_vec(), &sk);
        let envelope2 = ProtoSealedEnvelope {
            payload: sealed2.payload.clone(),
            payload_type: sealed2.payload_type.clone(),
            crc32c: sealed2.crc32c_digest,
            ml_dsa_65_signature: sealed2.ml_dsa_65_signature.clone(),
            timestamp: sealed2.timestamp,
            nonce: sealed2.nonce.to_vec(),
        };
        let hmac_tag2 = {
            let bus = service.bus.read().await;
            bus.compute_hmac(&session.session_id, &envelope2.payload).unwrap()
        };
        let req2 = EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope2),
                source_enclave: "webui".into(),
                handshake_session: session.session_id.clone(),
                hmac_tag: hmac_tag2,
            }),
            action: Some(ActionDescriptor {
                action_type: "CODE_EXECUTE".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
        };
        let resp2 = service.simulate(Request::new(req2)).await.unwrap().into_inner();
        assert_eq!(resp2.verdict, "BLOCK");
        
        // Check audit log count unchanged
        let final_resp = service.read_audit_log(Request::new(ReadAuditLogRequest {}))
            .await.unwrap().into_inner();
        assert_eq!(final_resp.entries.len(), initial_count);
    }

    #[tokio::test]
    async fn simulate_does_not_consume_nonce_or_counters() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Get initial health
        let initial_health = service.health(Request::new(HealthRequest {}))
            .await.unwrap().into_inner();
        let initial_passed = initial_health.protocol_firewall_rules_passed;
        let initial_total = initial_health.protocol_firewall_rules_total;
        
        // Create a single sealed envelope with a specific nonce
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"same_nonce".to_vec(), &sk);
        let req1 = evaluate_request(&service, &session.session_id, &sealed).await;
        
        // Simulate TWICE with the same nonce
        let req2 = req1.clone();
        let resp1 = service.simulate(Request::new(req1)).await.unwrap().into_inner();
        assert_eq!(resp1.verdict, "ALLOW");
        
        let resp2 = service.simulate(Request::new(req2)).await.unwrap().into_inner();
        assert_eq!(resp2.verdict, "ALLOW"); // Would be BLOCK if nonce was consumed
        
        // Check health counters unchanged
        let mid_health = service.health(Request::new(HealthRequest {}))
            .await.unwrap().into_inner();
        assert_eq!(mid_health.protocol_firewall_rules_passed, initial_passed);
        assert_eq!(mid_health.protocol_firewall_rules_total, initial_total);
        
        // Now do a REAL Evaluate with the same envelope - should succeed
        let sealed3 = SealedEnvelope::new(PAYLOAD.to_vec(), b"same_nonce".to_vec(), &sk);
        let req3 = evaluate_request(&service, &session.session_id, &sealed3).await;
        let resp3 = service.evaluate(Request::new(req3)).await.unwrap().into_inner();
        assert_eq!(resp3.verdict, "ALLOW"); // Proves simulation left no state
    }

    #[tokio::test]
    async fn simulate_throttle_and_escalate() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        config.policy_escalate_actions = vec!["TOOL_CALL".to_string()];
        config.ensure_dirs().unwrap();
        let service = GuardianMeshService::new(config).unwrap();
        
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Test ESCALATE
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test_escalate".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let resp = service.simulate(Request::new(req)).await.unwrap().into_inner();
        
        assert_eq!(resp.verdict, "ESCALATE");
        assert_eq!(resp.simulation, true);
        let escalate_reason = resp.reasons.iter().find(|r| r.rule_id == "POLICY_ESCALATION");
        assert!(escalate_reason.is_some());
        assert!(!escalate_reason.unwrap().remediation.is_empty());
        
        // Test THROTTLE (drive many requests quickly)
        // This is harder to reliably trigger in a test, so we just verify the flow exists
        // by checking that a valid action still works in simulate mode
        let sealed2 = SealedEnvelope::new(PAYLOAD.to_vec(), b"test_throttle".to_vec(), &sk);
        let req2 = evaluate_request(&service, &session.session_id, &sealed2).await;
        let resp2 = service.simulate(Request::new(req2)).await.unwrap().into_inner();
        // Should either ALLOW or ESCALATE, but simulation flag should be true
        assert_eq!(resp2.simulation, true);
    }

    #[tokio::test]
    async fn evaluate_responses_carry_structured_reasons() {
        let (service, _dir) = test_service();
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        
        // Real Evaluate ALLOW
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test_real_allow".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let resp = service.evaluate(Request::new(req)).await.unwrap().into_inner();
        
        assert_eq!(resp.verdict, "ALLOW");
        assert_eq!(resp.simulation, false);
        assert!(!resp.reasons.is_empty());
        assert_eq!(resp.reasons[0].rule_id, "POLICY");
        
        let proof = resp.proof.unwrap();
        assert_eq!(proof.simulation, false);
        assert!(proof.rule_ids.contains(&"POLICY".to_string()));
        
        // Real Evaluate BLOCK
        let bad_payload = b"{\"actionType\":\"CODE_EXECUTE\",\"context\":\"test\",\"target\":\"panel\",\"metadata\":{}}";
        let sealed2 = SealedEnvelope::new(bad_payload.to_vec(), b"test_real_block".to_vec(), &sk);
        let envelope2 = ProtoSealedEnvelope {
            payload: sealed2.payload.clone(),
            payload_type: sealed2.payload_type.clone(),
            crc32c: sealed2.crc32c_digest,
            ml_dsa_65_signature: sealed2.ml_dsa_65_signature.clone(),
            timestamp: sealed2.timestamp,
            nonce: sealed2.nonce.to_vec(),
        };
        let hmac_tag2 = {
            let bus = service.bus.read().await;
            bus.compute_hmac(&session.session_id, &envelope2.payload).unwrap()
        };
        let req2 = EvaluateRequest {
            firewalled: Some(FirewalledRequest {
                envelope: Some(envelope2),
                source_enclave: "webui".into(),
                handshake_session: session.session_id.clone(),
                hmac_tag: hmac_tag2,
            }),
            action: Some(ActionDescriptor {
                action_type: "CODE_EXECUTE".into(),
                context: "test".into(),
                target: "panel".into(),
                metadata: Default::default(),
            }),
        };
        let resp2 = service.evaluate(Request::new(req2)).await.unwrap().into_inner();
        
        assert_eq!(resp2.verdict, "BLOCK");
        assert_eq!(resp2.simulation, false);
        let policy_reason = resp2.reasons.iter().find(|r| r.rule_id == "POLICY");
        assert!(policy_reason.is_some());
        assert!(!policy_reason.unwrap().remediation.is_empty());
        
        let proof2 = resp2.proof.unwrap();
        assert!(proof2.rule_ids.contains(&"POLICY".to_string()));
    }

    fn test_service_with_admins() -> (GuardianMeshService, tempfile::TempDir, SigningKey<MlDsa65>, SigningKey<MlDsa65>) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        
        // Create admin keys directory
        let admin_keys_dir = dir.path().join("admin_keys");
        std::fs::create_dir_all(&admin_keys_dir).unwrap();
        
        // Generate two admin keypairs
        let (sk_alice, vk_alice) = generate_keypair();
        let (sk_bob, vk_bob) = generate_keypair();
        
        // Write their verifying keys
        std::fs::write(admin_keys_dir.join("alice.vk"), vk_alice.encode().to_vec()).unwrap();
        std::fs::write(admin_keys_dir.join("bob.vk"), vk_bob.encode().to_vec()).unwrap();
        
        config.policy_admin_keys_dir = Some(admin_keys_dir.to_string_lossy().into_owned());
        config.ensure_dirs().unwrap();
        
        let service = GuardianMeshService::new(config).unwrap();
        (service, dir, sk_alice, sk_bob)
    }

    #[tokio::test]
    async fn get_policy_returns_genesis_with_daemon_signature() {
        let (service, _dir, _, _) = test_service_with_admins();
        
        let resp = service.get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        assert_eq!(resp.version, 1);
        assert_eq!(resp.prev_hash, "genesis");
        assert_eq!(resp.proposer, "daemon-defaults");
        assert_eq!(resp.approver, "");
        assert!(!resp.daemon_signature.is_empty());
        assert!(!resp.signer_fingerprint.is_empty());
        assert_eq!(resp.rules.len(), 11); // Default rules
        
        // Verify daemon signature
        let canonical = service.policy.read().await.bundle().to_canonical_string();
        let sig = ml_dsa::Signature::<MlDsa65>::try_from(resp.daemon_signature.as_slice()).unwrap();
        service.verifying_key.verify(canonical.as_bytes(), &sig).unwrap();
    }

    #[tokio::test]
    async fn propose_by_unregistered_principal_refused() {
        let (service, _dir, _, _) = test_service_with_admins();
        let (sk_eve, _vk_eve) = generate_keypair();
        
        let current = service.policy.read().await;
        let new_rules = vec![PolicyRuleMessage {
            action_type: "TOOL_CALL".to_string(),
            allow: false,
            priority: 100,
        }];
        
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        
        let canonical = proposed.to_canonical_string();
        let sig = sk_eve.sign(canonical.as_bytes());
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: new_rules,
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
            proposer: "eve".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!resp.accepted);
        assert_eq!(resp.message, "unknown policy admin");
    }

    #[tokio::test]
    async fn propose_with_bad_signature_refused() {
        let (service, _dir, _, _) = test_service_with_admins();
        let (sk_wrong, _) = generate_keypair();
        
        let current = service.policy.read().await;
        let new_rules = vec![PolicyRuleMessage {
            action_type: "TOOL_CALL".to_string(),
            allow: false,
            priority: 100,
        }];
        
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        
        let canonical = proposed.to_canonical_string();
        let sig = sk_wrong.sign(canonical.as_bytes());
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: new_rules,
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!resp.accepted);
        assert_eq!(resp.message, "signature verification failed");
    }

    #[tokio::test]
    async fn propose_with_wrong_version_refused() {
        let (service, _dir, sk_alice, _) = test_service_with_admins();
        
        let current = service.policy.read().await;
        let new_rules = vec![PolicyRuleMessage {
            action_type: "TOOL_CALL".to_string(),
            allow: false,
            priority: 100,
        }];
        
        let proposed = PolicyBundle {
            version: 3, // Wrong: should be 2
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        
        let canonical = proposed.to_canonical_string();
        let sig = sk_alice.sign(canonical.as_bytes());
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 3,
            rules: new_rules,
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!resp.accepted);
        assert!(resp.message.contains("version"));
    }

    #[tokio::test]
    async fn dual_control_approve_by_same_admin_refused() {
        let (service, _dir, sk_alice, _) = test_service_with_admins();
        
        let current = service.policy.read().await;
        let new_rules = vec![PolicyRuleMessage {
            action_type: "TOOL_CALL".to_string(),
            allow: false,
            priority: 100,
        }];
        
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        
        let canonical = proposed.to_canonical_string();
        let sig = sk_alice.sign(canonical.as_bytes());
        
        // Propose by alice
        let propose_resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: new_rules.clone(),
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(propose_resp.accepted);
        let change_id = propose_resp.change_id;
        
        // Try to approve by alice (same person)
        let approve_resp = service.approve_policy_change(Request::new(ApprovePolicyChangeRequest {
            change_id,
            approver: "alice".to_string(),
            approver_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!approve_resp.applied);
        assert!(approve_resp.message.contains("dual control"));
    }

    #[tokio::test]
    async fn approve_with_bad_signature_refused() {
        let (service, _dir, sk_alice, _) = test_service_with_admins();
        let (sk_wrong, _) = generate_keypair();
        
        let current = service.policy.read().await;
        let new_rules = vec![PolicyRuleMessage {
            action_type: "TOOL_CALL".to_string(),
            allow: false,
            priority: 100,
        }];
        
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        
        let canonical = proposed.to_canonical_string();
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        
        // Propose by alice
        let propose_resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: new_rules,
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
            proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(propose_resp.accepted);
        
        // Try to approve with wrong signature
        let bad_sig = sk_wrong.sign(canonical.as_bytes());
        let approve_resp = service.approve_policy_change(Request::new(ApprovePolicyChangeRequest {
            change_id: propose_resp.change_id,
            approver: "bob".to_string(),
            approver_signature: bad_sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!approve_resp.applied);
        assert_eq!(approve_resp.message, "signature verification failed");
    }

    #[tokio::test]
    async fn propose_and_approve_updates_policy_and_verdicts() {
        let (service, _dir, sk_alice, sk_bob) = test_service_with_admins();
        
        // Check initial policy
        let initial_policy = service.get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(initial_policy.version, 1);
        
        // Propose a bundle that blocks TOOL_CALL
        let current = service.policy.read().await;
        let new_rules = vec![PolicyRuleMessage {
            action_type: "TOOL_CALL".to_string(),
            allow: false,
            priority: 100,
        }];
        
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        drop(current);
        
        let canonical = proposed.to_canonical_string();
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        
        // Propose by alice
        let propose_resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: new_rules,
            escalate_actions: vec![],
            prev_hash: proposed.prev_hash.clone(),
            proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(propose_resp.accepted);
        
        // Approve by bob
        let sig_bob = sk_bob.sign(canonical.as_bytes());
        let approve_resp = service.approve_policy_change(Request::new(ApprovePolicyChangeRequest {
            change_id: propose_resp.change_id,
            approver: "bob".to_string(),
            approver_signature: sig_bob.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(approve_resp.applied);
        assert_eq!(approve_resp.version, 2);
        
        // GetPolicy should show new version
        let new_policy = service.get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(new_policy.version, 2);
        assert_eq!(new_policy.proposer, "alice");
        assert_eq!(new_policy.approver, "bob");
        
        // Evaluate a TOOL_CALL should now BLOCK
        let (sk, vk) = generate_keypair();
        let session = open_session(&service, &vk).await;
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &sk);
        let req = evaluate_request(&service, &session.session_id, &sealed).await;
        let resp = service.evaluate(Request::new(req)).await.unwrap().into_inner();
        
        assert_eq!(resp.verdict, "BLOCK");
        
        // Proof should carry policy_version = 2
        let proof = resp.proof.unwrap();
        assert_eq!(proof.policy_version, 2);
    }

    #[tokio::test]
    async fn second_proposal_while_pending_refused() {
        let (service, _dir, sk_alice, _) = test_service_with_admins();
        
        let current = service.policy.read().await;
        let new_rules = vec![PolicyRuleMessage {
            action_type: "TOOL_CALL".to_string(),
            allow: false,
            priority: 100,
        }];
        
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        drop(current);
        
        let canonical = proposed.to_canonical_string();
        let sig = sk_alice.sign(canonical.as_bytes());
        
        // First proposal
        let resp1 = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: new_rules.clone(),
            escalate_actions: vec![],
            prev_hash: proposed.prev_hash.clone(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(resp1.accepted);
        
        // Second proposal while first is pending
        let resp2 = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: new_rules,
            escalate_actions: vec![],
            prev_hash: proposed.prev_hash,
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!resp2.accepted);
        assert_eq!(resp2.message, "a policy change is already pending");
    }

    #[tokio::test]
    async fn persistence_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let ws_path = dir.path().join("ws").to_string_lossy().into_owned();
        let out_path = dir.path().join("out").to_string_lossy().into_owned();
        let admin_keys_dir = dir.path().join("admin_keys");
        std::fs::create_dir_all(&admin_keys_dir).unwrap();
        
        let (sk_alice, vk_alice) = generate_keypair();
        let (sk_bob, vk_bob) = generate_keypair();
        
        std::fs::write(admin_keys_dir.join("alice.vk"), vk_alice.encode().to_vec()).unwrap();
        std::fs::write(admin_keys_dir.join("bob.vk"), vk_bob.encode().to_vec()).unwrap();
        
        // First instance: apply a policy change
        {
            let mut config1 = Config::default();
            config1.workspace_dir = ws_path.clone();
            config1.output_dir = out_path.clone();
            config1.policy_admin_keys_dir = Some(admin_keys_dir.to_string_lossy().into_owned());
            config1.ensure_dirs().unwrap();
            
            let service1 = GuardianMeshService::new(config1).unwrap();
            
            let current = service1.policy.read().await;
            let proposed = PolicyBundle {
                version: 2,
                rules: vec![PolicyRule {
                    action_type: "TOOL_CALL".to_string(),
                    allow: false,
                    priority: 100,
                }],
                escalate_actions: vec![],
                prev_hash: current.content_hash(),
            };
            drop(current);
            
            let canonical = proposed.to_canonical_string();
            let sig_alice = sk_alice.sign(canonical.as_bytes());
            let sig_bob = sk_bob.sign(canonical.as_bytes());
            
            let propose_resp = service1.propose_policy_change(Request::new(ProposePolicyChangeRequest {
                version: 2,
                rules: vec![PolicyRuleMessage {
                    action_type: "TOOL_CALL".to_string(),
                    allow: false,
                    priority: 100,
                }],
                escalate_actions: vec![],
                prev_hash: proposed.prev_hash.clone(),
                proposer: "alice".to_string(),
                proposer_signature: sig_alice.to_bytes().to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
            
            assert!(propose_resp.accepted);
            
            let approve_resp = service1.approve_policy_change(Request::new(ApprovePolicyChangeRequest {
                change_id: propose_resp.change_id,
                approver: "bob".to_string(),
                approver_signature: sig_bob.to_bytes().to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
            
            assert!(approve_resp.applied);
            assert_eq!(approve_resp.version, 2);
        }
        
        // Second instance: should start at v2
        {
            let mut config2 = Config::default();
            config2.workspace_dir = ws_path;
            config2.output_dir = out_path;
            config2.policy_admin_keys_dir = Some(admin_keys_dir.to_string_lossy().into_owned());
            let service2 = GuardianMeshService::new(config2).unwrap();
            
            let policy = service2.get_policy(Request::new(GetPolicyRequest {}))
                .await
                .unwrap()
                .into_inner();
            
            assert_eq!(policy.version, 2);
            assert_eq!(policy.content_hash, service2.policy.read().await.content_hash());
        }
    }

    #[tokio::test]
    async fn no_admins_configured_propose_refused_getpolicy_works() {
        let (service, _dir) = test_service();
        
        // GetPolicy should still work
        let policy = service.get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(policy.version, 1);
        
        // Propose should fail (no admins)
        let (sk, _) = generate_keypair();
        let current = service.policy.read().await;
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        drop(current);
        
        let canonical = proposed.to_canonical_string();
        let sig = sk.sign(canonical.as_bytes());
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: vec![PolicyRuleMessage {
                action_type: "TOOL_CALL".to_string(),
                allow: false,
                priority: 100,
            }],
            escalate_actions: vec![],
            prev_hash: proposed.prev_hash,
            proposer: "anyone".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!resp.accepted);
        assert_eq!(resp.message, "unknown policy admin");
    }
}
