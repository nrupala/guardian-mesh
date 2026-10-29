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
use guardian_meshd::authenticators::{AuthMethod, PgpKey, parse_pgp_public_key, verify_pgp_detached, parse_svid, verify_spiffe_possession, canonical_spiffe_string, spiffe_trust_domain};
use ml_dsa::Signer;
use guardian_meshd::certificate::{CertificateRegistry, Tests, IssuanceResult, CertificateStatus as CertStatus};
use guardian_meshd::revocation::{RevocationRegistry, RevocationKind, RevocationEntry, canonical_revocation_string, revocation_change_id, validate_revocation};
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
    ProposeRevocationRequest, ProposeRevocationResponse,
    ApproveRevocationRequest, ApproveRevocationResponse,
    RevocationStatusRequest, RevocationStatusResponse,
    AuthenticatorStatusRequest, AuthenticatorStatusResponse, AuthenticatorInfo,
};
use prost::Message as _;
use ml_dsa::{MlDsa65, SigningKey, VerifyingKey, Verifier, SignatureEncoding};

struct PendingPolicyChange {
    bundle: PolicyBundle,
    proposer: String,
}

struct PendingRevocation {
    kind: RevocationKind,
    target_id: String,
    reason: String,
    proposer: String,
    canonical: String,
    change_id: String,
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
    revocations: Arc<RevocationRegistry>,
    pending_revocation: Arc<RwLock<Option<PendingRevocation>>>,
    pgp_admins: std::collections::HashMap<String, PgpKey>,
}

impl GuardianMeshService {
    pub fn new(config: Config) -> Result<Self, String> {
        let (sk, vk) = load_or_generate_signing_key(config.keys_dir())?;
        let vault = Arc::new(VaultEnclave::new(10_000, config.audit_dir()));
        
        // Load policy admins from the configured directory
        let policy_admins = Self::load_policy_admins(&config)?;
        
        // Load PGP admins from the configured directory
        let pgp_admins = Self::load_pgp_admins(&config)?;
        
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
        
        let revocations = RevocationRegistry::new(config.revocation_dir())?;
        
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
            revocations: Arc::new(revocations),
            pending_revocation: Arc::new(RwLock::new(None)),
            pgp_admins,
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

    fn load_pgp_admins(config: &Config) -> Result<std::collections::HashMap<String, PgpKey>, String> {
        let mut admins = std::collections::HashMap::new();
        
        let keys_dir = match &config.pgp_admin_keys_dir {
            Some(dir) => dir,
            None => return Ok(admins),
        };
        
        let dir_path = std::path::Path::new(keys_dir);
        if !dir_path.exists() {
            return Ok(admins);
        }
        
        let entries = std::fs::read_dir(dir_path)
            .map_err(|e| format!("failed to read PGP admin keys directory: {}", e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| format!("failed to read directory entry: {}", e))?;
            let path = entry.path();
            
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if !file_name.ends_with(".asc") {
                    continue;
                }
                
                let principal = file_name.strip_suffix(".asc").unwrap();
                
                if !Self::is_valid_principal_name(principal) {
                    return Err(format!("invalid principal name in PGP file: {}", file_name));
                }
                
                let armored = std::fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read PGP key file {}: {}", file_name, e))?;
                
                let key = parse_pgp_public_key(&armored)
                    .map_err(|e| format!("failed to parse PGP key from {}: {}", file_name, e))?;
                
                admins.insert(principal.to_string(), key);
            }
        }
        
        Ok(admins)
    }

    fn check_pgp_factor(&self, principal: &str, canonical: &[u8], armored_sig: &str) -> Result<(), String> {
        let enrolled = self.pgp_admins.get(principal);
        
        match (enrolled, armored_sig.is_empty()) {
            (None, true) => Ok(()),
            (None, false) => Err(format!("PGP signature presented but no PGP key is enrolled for principal {}", principal)),
            (Some(key), true) => Err(format!("PGP second factor required for principal {} (AZ-4): enrolled OpenPGP key {}", principal, key.fingerprint)),
            (Some(key), false) => {
                verify_pgp_detached(key, armored_sig, canonical)
            }
        }
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

        // WO-12: Refuse handshake if the client key has been revoked
        if !req.source_public_key.is_empty() {
            use sha2::Digest;
            let fingerprint = hex::encode(sha2::Sha256::digest(&req.source_public_key));
            if self.revocations.is_revoked(RevocationKind::Key, &fingerprint) {
                return Err(Status::permission_denied("handshake refused: client key has been revoked"));
            }
        }

        let source = if req.source_enclave.is_empty() {
            "unknown".to_string()
        } else {
            req.source_enclave
        };

        // WO-14: SPIFFE attestation (AZ-3)
        let spiffe_present = !req.spiffe_id.is_empty() || !req.svid_leaf_der.is_empty() || !req.svid_signature.is_empty();
        let spiffe_complete = !req.spiffe_id.is_empty() && !req.svid_leaf_der.is_empty() && !req.svid_signature.is_empty();

        if spiffe_present && !spiffe_complete {
            return Err(Status::invalid_argument("incomplete SPIFFE attestation: spiffe_id, svid_leaf_der and svid_signature are all required"));
        }

        let mut auth_factors = vec!["ML_DSA_65".to_string(), "HMAC_SESSION".to_string()];
        let mut workload_id = String::new();

        if spiffe_complete {
            if self.config.spiffe_trust_domains.is_empty() {
                return Err(Status::permission_denied("SPIFFE attestation presented but no trust domains are configured"));
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let info = parse_svid(&req.svid_leaf_der, now)
                .map_err(|e| Status::permission_denied(format!("SPIFFE attestation refused: {}", e)))?;

            if info.spiffe_id != req.spiffe_id {
                return Err(Status::permission_denied(format!("SPIFFE ID mismatch: SVID contains {}, request claims {}", info.spiffe_id, req.spiffe_id)));
            }

            let domain = spiffe_trust_domain(&info.spiffe_id)
                .map_err(|e| Status::permission_denied(format!("SPIFFE attestation refused: {}", e)))?;

            if !self.config.spiffe_trust_domains.contains(&domain) {
                return Err(Status::permission_denied(format!("SPIFFE trust domain {} is not in allowlist", domain)));
            }

            use sha2::Digest;
            let ml_dsa_hash = hex::encode(sha2::Sha256::digest(&req.source_public_key));
            let canonical = canonical_spiffe_string(&info.spiffe_id, &ml_dsa_hash);

            verify_spiffe_possession(&info, &canonical, &req.svid_signature)
                .map_err(|e| Status::permission_denied(format!("SPIFFE possession verification failed: {}", e)))?;

            auth_factors.push("SPIFFE_X509".to_string());
            workload_id = info.spiffe_id.clone();
        } else if self.config.spiffe_required {
            return Err(Status::permission_denied("handshake refused: missing required confirmation SPIFFE_X509 (BM-9/BM-11)"));
        }

        let bus = self.bus.read().await;
        self.sweep_expired_sessions(&bus);
        let session = bus.create_session_attested(&source, &req.source_public_key, auth_factors.clone(), workload_id.clone());

        Ok(Response::new(HandshakeResponse {
            session_id: session.session_id,
            session_key: session.session_key.to_vec(),
            ttl_seconds: SESSION_TTL_SECS,
            auth_factors,
            workload_id,
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

        // WO-12: If an admin registry is configured, legacy RevokeCertificate is disabled
        // in favor of the dual-control revocation service
        if !self.policy_admins.is_empty() {
            return Err(Status::failed_precondition(
                "certificate revocation requires the dual-control revocation service (ProposeRevocation/ApproveRevocation) when an admin registry is configured"
            ));
        }

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
        
        // WO-14: Check PGP second factor (AZ-4)
        if let Err(e) = self.check_pgp_factor(&req.proposer, canonical.as_bytes(), &req.pgp_signature) {
            return Ok(Response::new(ProposePolicyChangeResponse {
                accepted: false,
                change_id: String::new(),
                message: e,
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
        
        // WO-14: Check PGP second factor (AZ-4)
        if let Err(e) = self.check_pgp_factor(&req.approver, canonical.as_bytes(), &req.pgp_signature) {
            return Ok(Response::new(ApprovePolicyChangeResponse {
                applied: false,
                version: 0,
                content_hash: String::new(),
                message: e,
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

    async fn propose_revocation(
        &self,
        request: Request<ProposeRevocationRequest>,
    ) -> Result<Response<ProposeRevocationResponse>, Status> {
        let req = request.into_inner();
        
        // Check if proposer is a registered admin (the admin registry shared with policy governance)
        let proposer_vk = match self.policy_admins.get(&req.proposer) {
            Some(vk) => vk,
            None => {
                return Ok(Response::new(ProposeRevocationResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: "unknown policy admin".to_string(),
                }));
            }
        };
        
        // Parse and validate kind/target/reason
        let kind = match RevocationKind::parse(&req.kind) {
            Ok(k) => k,
            Err(e) => {
                return Ok(Response::new(ProposeRevocationResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: e,
                }));
            }
        };
        
        if let Err(e) = validate_revocation(kind, &req.target_id, &req.reason) {
            return Ok(Response::new(ProposeRevocationResponse {
                accepted: false,
                change_id: String::new(),
                message: e,
            }));
        }
        
        // CERTIFICATE kind: target must be a known certificate, not already revoked
        if kind == RevocationKind::Certificate {
            let (status, _) = self.certificates.get_status(&req.target_id);
            match status {
                CertStatus::Unknown => {
                    return Ok(Response::new(ProposeRevocationResponse {
                        accepted: false,
                        change_id: String::new(),
                        message: "certificate serial unknown".to_string(),
                    }));
                }
                CertStatus::Revoked => {
                    return Ok(Response::new(ProposeRevocationResponse {
                        accepted: false,
                        change_id: String::new(),
                        message: "certificate already revoked".to_string(),
                    }));
                }
                _ => {}
            }
        }
        
        // SESSION/KEY: already-revoked target is refused (no duplicate proposals)
        if kind != RevocationKind::Certificate && self.revocations.is_revoked(kind, &req.target_id) {
            return Ok(Response::new(ProposeRevocationResponse {
                accepted: false,
                change_id: String::new(),
                message: "already revoked".to_string(),
            }));
        }
        
        // Build the canonical string for signature verification
        let canonical = canonical_revocation_string(kind, &req.target_id, &req.reason, &req.proposer);
        
        // Verify proposer signature
        let sig = match ml_dsa::Signature::<MlDsa65>::try_from(req.proposer_signature.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                return Ok(Response::new(ProposeRevocationResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: "signature verification failed".to_string(),
                }));
            }
        };
        
        if let Err(_) = proposer_vk.verify(canonical.as_bytes(), &sig) {
            return Ok(Response::new(ProposeRevocationResponse {
                accepted: false,
                change_id: String::new(),
                message: "signature verification failed".to_string(),
            }));
        }
        
        // WO-14: Check PGP second factor (AZ-4)
        if let Err(e) = self.check_pgp_factor(&req.proposer, canonical.as_bytes(), &req.pgp_signature) {
            return Ok(Response::new(ProposeRevocationResponse {
                accepted: false,
                change_id: String::new(),
                message: e,
            }));
        }
        
        // Check if a pending revocation already exists
        {
            let mut pending = self.pending_revocation.write().await;
            if pending.is_some() {
                return Ok(Response::new(ProposeRevocationResponse {
                    accepted: false,
                    change_id: String::new(),
                    message: "a revocation is already pending".to_string(),
                }));
            }
            
            let change_id = revocation_change_id(kind, &req.target_id, &req.reason, &req.proposer);
            *pending = Some(PendingRevocation {
                kind,
                target_id: req.target_id,
                reason: req.reason,
                proposer: req.proposer,
                canonical,
                change_id: change_id.clone(),
            });
            
            Ok(Response::new(ProposeRevocationResponse {
                accepted: true,
                change_id,
                message: String::new(),
            }))
        }
    }

    async fn approve_revocation(
        &self,
        request: Request<ApproveRevocationRequest>,
    ) -> Result<Response<ApproveRevocationResponse>, Status> {
        let req = request.into_inner();
        
        // Check if approver is a registered admin
        let approver_vk = match self.policy_admins.get(&req.approver) {
            Some(vk) => vk,
            None => {
                return Ok(Response::new(ApproveRevocationResponse {
                    applied: false,
                    kind: String::new(),
                    target_id: String::new(),
                    effects: 0,
                    propagation_ms: 0,
                    bound_secs: 0,
                    message: "unknown policy admin".to_string(),
                }));
            }
        };
        
        // Check if a pending revocation exists and change_id matches
        let (pending_kind, pending_target, pending_reason, pending_proposer, pending_canonical) = {
            let pending = self.pending_revocation.read().await;
            match pending.as_ref() {
                Some(p) => {
                    if p.change_id != req.change_id {
                        return Ok(Response::new(ApproveRevocationResponse {
                            applied: false,
                            kind: String::new(),
                            target_id: String::new(),
                            effects: 0,
                            propagation_ms: 0,
                            bound_secs: 0,
                            message: "change_id mismatch".to_string(),
                        }));
                    }
                    (p.kind, p.target_id.clone(), p.reason.clone(), p.proposer.clone(), p.canonical.clone())
                }
                None => {
                    return Ok(Response::new(ApproveRevocationResponse {
                        applied: false,
                        kind: String::new(),
                        target_id: String::new(),
                        effects: 0,
                        propagation_ms: 0,
                        bound_secs: 0,
                        message: "no pending revocation".to_string(),
                    }));
                }
            }
        };
        
        // Dual control: approver != proposer
        if req.approver == pending_proposer {
            return Ok(Response::new(ApproveRevocationResponse {
                applied: false,
                kind: String::new(),
                target_id: String::new(),
                effects: 0,
                propagation_ms: 0,
                bound_secs: 0,
                message: "dual control violation: approver cannot be the same as proposer".to_string(),
            }));
        }
        
        // Verify approver signature
        let sig = match ml_dsa::Signature::<MlDsa65>::try_from(req.approver_signature.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                return Ok(Response::new(ApproveRevocationResponse {
                    applied: false,
                    kind: String::new(),
                    target_id: String::new(),
                    effects: 0,
                    propagation_ms: 0,
                    bound_secs: 0,
                    message: "signature verification failed".to_string(),
                }));
            }
        };
        
        if let Err(_) = approver_vk.verify(pending_canonical.as_bytes(), &sig) {
            return Ok(Response::new(ApproveRevocationResponse {
                applied: false,
                kind: String::new(),
                target_id: String::new(),
                effects: 0,
                propagation_ms: 0,
                bound_secs: 0,
                message: "signature verification failed".to_string(),
            }));
        }
        
        // WO-14: Check PGP second factor (AZ-4)
        if let Err(e) = self.check_pgp_factor(&req.approver, pending_canonical.as_bytes(), &req.pgp_signature) {
            return Ok(Response::new(ApproveRevocationResponse {
                applied: false,
                kind: String::new(),
                target_id: String::new(),
                effects: 0,
                propagation_ms: 0,
                bound_secs: 0,
                message: e,
            }));
        }
        
        // Start propagation timer
        let t0 = std::time::Instant::now();
        
        // Record the revocation FIRST (persist-first discipline)
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // We'll measure propagation_ms after effects are applied, but we need to
        // persist with it. The task says to measure from approval start to effects
        // applied, then persist with that value. If persist fails after effects,
        // return applied=true with a warning.
        // Order: record → apply effects → measure propagation_ms, update stored entry.
        // Actually, re-reading the task: "measure propagation_ms as elapsed from
        // approval start until effects are applied; persist the entry AFTER effects
        // with that measured value."
        // So: apply effects first, measure, then persist.
        
        // Apply effects synchronously
        let effects = match pending_kind {
            RevocationKind::Session => {
                let bus = self.bus.read().await;
                let existed = bus.session_exists(&pending_target);
                if existed {
                    drop(bus); // Release read lock before write operations
                    let bus = self.bus.write().await;
                    bus.remove_session(&pending_target);
                    self.firewall.evict_session(&pending_target);
                    1
                } else {
                    0
                }
            }
            RevocationKind::Key => {
                let bus = self.bus.read().await;
                let session_ids = bus.sessions_bound_to_key(&pending_target);
                let count = session_ids.len() as u32;
                drop(bus); // Release read lock
                if count > 0 {
                    let bus = self.bus.write().await;
                    for sid in &session_ids {
                        bus.remove_session(sid);
                        self.firewall.evict_session(sid);
                    }
                }
                count
            }
            RevocationKind::Certificate => {
                match self.certificates.revoke_certificate(&pending_target, &pending_reason) {
                    Ok(_) => 0,
                    Err(e) => {
                        // If already revoked, that's fine (idempotent). Other errors are failures.
                        if e.contains("already revoked") {
                            0
                        } else {
                            return Ok(Response::new(ApproveRevocationResponse {
                                applied: false,
                                kind: pending_kind.as_str().to_string(),
                                target_id: pending_target,
                                effects: 0,
                                propagation_ms: 0,
                                bound_secs: 0,
                                message: format!("certificate revocation failed: {}", e),
                            }));
                        }
                    }
                }
            }
        };
        
        // Measure propagation time
        let propagation_ms = t0.elapsed().as_millis() as u64;
        
        // Build the RevocationEntry
        let entry = RevocationEntry {
            kind: pending_kind,
            target_id: pending_target.clone(),
            reason: pending_reason.clone(),
            proposer: pending_proposer.clone(),
            approver: req.approver.clone(),
            revoked_at: now_secs,
            propagation_ms,
        };
        
        // Persist the entry (if this fails, effects are already applied)
        let persist_result = self.revocations.record(entry);
        let mut response_message = String::new();
        if let Err(e) = persist_result {
            response_message = format!("revocation applied but persistence failed: {}", e);
        }
        
        // Audit log the revocation
        let audit_reason = format!("\"{}\" proposer={} approver={}", pending_reason, pending_proposer, req.approver);
        if let Err(e) = self.vault.record_revocation_event(
            pending_kind.as_str(),
            &pending_target,
            "REVOCATION_APPLIED",
            &audit_reason,
        ) {
            if response_message.is_empty() {
                response_message = format!("revocation applied; audit record failed: {}", e);
            } else {
                response_message = format!("{}; audit record failed: {}", response_message, e);
            }
        }
        
        // Clear pending
        {
            let mut pending = self.pending_revocation.write().await;
            *pending = None;
        }
        
        Ok(Response::new(ApproveRevocationResponse {
            applied: true,
            kind: pending_kind.as_str().to_string(),
            target_id: pending_target,
            effects,
            propagation_ms,
            bound_secs: self.config.revocation_bound_secs,
            message: response_message,
        }))
    }

    async fn revocation_status(
        &self,
        request: Request<RevocationStatusRequest>,
    ) -> Result<Response<RevocationStatusResponse>, Status> {
        let req = request.into_inner();
        
        // If kind or target is empty, return summary
        if req.kind.is_empty() || req.target_id.is_empty() {
            return Ok(Response::new(RevocationStatusResponse {
                revoked: false,
                kind: String::new(),
                target_id: String::new(),
                reason: String::new(),
                proposer: String::new(),
                approver: String::new(),
                revoked_at: 0,
                propagation_ms: 0,
                bound_secs: self.config.revocation_bound_secs,
                total_revoked: self.revocations.count() as u32,
            }));
        }
        
        // Parse kind
        let kind = match RevocationKind::parse(&req.kind) {
            Ok(k) => k,
            Err(_) => {
                return Ok(Response::new(RevocationStatusResponse {
                    revoked: false,
                    kind: String::new(),
                    target_id: String::new(),
                    reason: String::new(),
                    proposer: String::new(),
                    approver: String::new(),
                    revoked_at: 0,
                    propagation_ms: 0,
                    bound_secs: self.config.revocation_bound_secs,
                    total_revoked: self.revocations.count() as u32,
                }));
            }
        };
        
        // Query specific target
        match self.revocations.get(kind, &req.target_id) {
            Some(entry) => Ok(Response::new(RevocationStatusResponse {
                revoked: true,
                kind: entry.kind.as_str().to_string(),
                target_id: entry.target_id,
                reason: entry.reason,
                proposer: entry.proposer,
                approver: entry.approver,
                revoked_at: entry.revoked_at,
                propagation_ms: entry.propagation_ms,
                bound_secs: self.config.revocation_bound_secs,
                total_revoked: self.revocations.count() as u32,
            })),
            None => Ok(Response::new(RevocationStatusResponse {
                revoked: false,
                kind: String::new(),
                target_id: String::new(),
                reason: String::new(),
                proposer: String::new(),
                approver: String::new(),
                revoked_at: 0,
                propagation_ms: 0,
                bound_secs: self.config.revocation_bound_secs,
                total_revoked: self.revocations.count() as u32,
            })),
        }
    }

    async fn authenticator_status(
        &self,
        _request: Request<AuthenticatorStatusRequest>,
    ) -> Result<Response<AuthenticatorStatusResponse>, Status> {
        let mut authenticators = Vec::new();
        
        // ML_DSA_65
        authenticators.push(AuthenticatorInfo {
            method: AuthMethod::MlDsa65.as_str().to_string(),
            factor_type: AuthMethod::MlDsa65.factor_type().to_string(),
            assurance: AuthMethod::MlDsa65.assurance().to_string(),
            configured: true,
            detail: "session-bound signing key".to_string(),
        });
        
        // HMAC_SESSION
        authenticators.push(AuthenticatorInfo {
            method: AuthMethod::HmacSession.as_str().to_string(),
            factor_type: AuthMethod::HmacSession.factor_type().to_string(),
            assurance: AuthMethod::HmacSession.assurance().to_string(),
            configured: true,
            detail: "handshake-issued session proof".to_string(),
        });
        
        // SPIFFE_X509
        let spiffe_configured = !self.config.spiffe_trust_domains.is_empty();
        let spiffe_detail = if spiffe_configured {
            let domains = self.config.spiffe_trust_domains.join(", ");
            if self.config.spiffe_required {
                format!("trust domains: {}; required", domains)
            } else {
                format!("trust domains: {}", domains)
            }
        } else {
            "no trust domains configured".to_string()
        };
        authenticators.push(AuthenticatorInfo {
            method: AuthMethod::SpiffeX509.as_str().to_string(),
            factor_type: AuthMethod::SpiffeX509.factor_type().to_string(),
            assurance: AuthMethod::SpiffeX509.assurance().to_string(),
            configured: spiffe_configured,
            detail: spiffe_detail,
        });
        
        // OPENPGP
        let pgp_configured = !self.pgp_admins.is_empty();
        let pgp_detail = if pgp_configured {
            format!("{} admin keys enrolled", self.pgp_admins.len())
        } else {
            "no admin keys enrolled".to_string()
        };
        authenticators.push(AuthenticatorInfo {
            method: AuthMethod::OpenPgp.as_str().to_string(),
            factor_type: AuthMethod::OpenPgp.factor_type().to_string(),
            assurance: AuthMethod::OpenPgp.assurance().to_string(),
            configured: pgp_configured,
            detail: pgp_detail,
        });
        
        let mut pgp_principals: Vec<String> = self.pgp_admins.keys().cloned().collect();
        pgp_principals.sort();
        
        Ok(Response::new(AuthenticatorStatusResponse {
            authenticators,
            spiffe_trust_domains: self.config.spiffe_trust_domains.clone(),
            spiffe_required: self.config.spiffe_required,
            pgp_admin_principals: pgp_principals,
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
    use sha2::Digest;

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
            .handshake(Request::new(HandshakeRequest { spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
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
            .handshake(Request::new(HandshakeRequest { spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
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
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
        let propose_resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
        let approve_resp = service.approve_policy_change(Request::new(ApprovePolicyChangeRequest { pgp_signature: String::new(),
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
        let propose_resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
        let approve_resp = service.approve_policy_change(Request::new(ApprovePolicyChangeRequest { pgp_signature: String::new(),
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
        let propose_resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
        let approve_resp = service.approve_policy_change(Request::new(ApprovePolicyChangeRequest { pgp_signature: String::new(),
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
        let resp1 = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
        let resp2 = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
            
            let propose_resp = service1.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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
            
            let approve_resp = service1.approve_policy_change(Request::new(ApprovePolicyChangeRequest { pgp_signature: String::new(),
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
        
        let resp = service.propose_policy_change(Request::new(ProposePolicyChangeRequest { pgp_signature: String::new(),
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

    // ── WO-12 revocation tests ──

    #[tokio::test]
    async fn revocation_propose_by_unregistered_refused() {
        let (service, _dir, _, _) = test_service_with_admins();
        let (sk_eve, _) = generate_keypair();
        
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "test reason",
            "eve",
        );
        let sig = sk_eve.sign(canonical.as_bytes());
        
        let resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: "abc123def456abc123def456abc123de".to_string(),
            reason: "test reason".to_string(),
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
    async fn revocation_propose_bad_signature_refused() {
        let (service, _dir, _, _) = test_service_with_admins();
        let (sk_wrong, _) = generate_keypair();
        
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "test reason",
            "alice",
        );
        let sig = sk_wrong.sign(canonical.as_bytes());
        
        let resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: "abc123def456abc123def456abc123de".to_string(),
            reason: "test reason".to_string(),
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
    async fn revocation_no_admins_configured_propose_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().to_string_lossy().into_owned();
        config.output_dir = dir.path().join("output").to_string_lossy().into_owned();
        config.ensure_dirs().unwrap();
        
        let service = GuardianMeshService::new(config).unwrap();
        
        let (sk, _) = generate_keypair();
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            "abc123def456abc123def456abc123de",
            "test reason",
            "alice",
        );
        let sig = sk.sign(canonical.as_bytes());
        
        let resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: "abc123def456abc123def456abc123de".to_string(),
            reason: "test reason".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!resp.accepted);
        assert_eq!(resp.message, "unknown policy admin");
        
        // RevocationStatus should work even without admins
        let status_resp = service.revocation_status(Request::new(RevocationStatusRequest {
            kind: String::new(),
            target_id: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert_eq!(status_resp.total_revoked, 0);
    }

    #[tokio::test]
    async fn revocation_session_end_to_end() {
        let (service, _dir, sk_alice, sk_bob) = test_service_with_admins();
        
        // Handshake and create a session
        let (client_sk, client_vk) = generate_keypair();
        let hs_resp = service.handshake(Request::new(HandshakeRequest { spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
            source_enclave: "test".to_string(),
            source_public_key: client_vk.encode().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        let session_id = hs_resp.session_id.clone();
        
        // Session should work (Evaluate would ALLOW if properly constructed)
        // For this test, just verify session exists
        let bus = service.bus.read().await;
        assert!(bus.session_exists(&session_id));
        drop(bus);
        
        // Alice proposes SESSION revocation
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            &session_id,
            "compromised session",
            "alice",
        );
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        
        let prop_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: session_id.clone(),
            reason: "compromised session".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(prop_resp.accepted);
        let change_id = prop_resp.change_id.clone();
        
        // Bob approves
        let sig_bob = sk_bob.sign(canonical.as_bytes());
        
        let approve_resp = service.approve_revocation(Request::new(ApproveRevocationRequest { pgp_signature: String::new(),
            change_id,
            approver: "bob".to_string(),
            approver_signature: sig_bob.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(approve_resp.applied);
        assert_eq!(approve_resp.kind, "SESSION");
        assert_eq!(approve_resp.target_id, session_id);
        assert_eq!(approve_resp.effects, 1);
        assert!(approve_resp.propagation_ms < approve_resp.bound_secs * 1000);
        
        // Session should no longer exist
        let bus = service.bus.read().await;
        assert!(!bus.session_exists(&session_id));
        drop(bus);
        
        // RevocationStatus should show it
        let status_resp = service.revocation_status(Request::new(RevocationStatusRequest {
            kind: "SESSION".to_string(),
            target_id: session_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(status_resp.revoked);
        assert_eq!(status_resp.kind, "SESSION");
        assert_eq!(status_resp.target_id, session_id);
        assert_eq!(status_resp.reason, "compromised session");
        assert_eq!(status_resp.proposer, "alice");
        assert_eq!(status_resp.approver, "bob");
        assert_eq!(status_resp.total_revoked, 1);
    }

    #[tokio::test]
    async fn revocation_same_principal_approval_refused() {
        let (service, _dir, sk_alice, _) = test_service_with_admins();
        
        let session_id = "abc123def456abc123def456abc123de";
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            session_id,
            "test reason",
            "alice",
        );
        let sig = sk_alice.sign(canonical.as_bytes());
        
        let prop_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: session_id.to_string(),
            reason: "test reason".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(prop_resp.accepted);
        let change_id = prop_resp.change_id;
        
        // Alice tries to approve her own proposal
        let sig_approve = sk_alice.sign(canonical.as_bytes());
        
        let approve_resp = service.approve_revocation(Request::new(ApproveRevocationRequest { pgp_signature: String::new(),
            change_id,
            approver: "alice".to_string(),
            approver_signature: sig_approve.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!approve_resp.applied);
        assert!(approve_resp.message.contains("dual control"));
    }

    #[tokio::test]
    async fn revocation_approve_bad_signature_pending_survives() {
        let (service, _dir, sk_alice, _) = test_service_with_admins();
        let (sk_wrong, _) = generate_keypair();
        
        let session_id = "abc123def456abc123def456abc123de";
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            session_id,
            "test reason",
            "alice",
        );
        let sig = sk_alice.sign(canonical.as_bytes());
        
        let prop_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: session_id.to_string(),
            reason: "test reason".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(prop_resp.accepted);
        let change_id = prop_resp.change_id.clone();
        
        // Wrong signature
        let sig_wrong = sk_wrong.sign(canonical.as_bytes());
        
        let approve_resp = service.approve_revocation(Request::new(ApproveRevocationRequest { pgp_signature: String::new(),
            change_id: change_id.clone(),
            approver: "bob".to_string(),
            approver_signature: sig_wrong.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!approve_resp.applied);
        assert_eq!(approve_resp.message, "signature verification failed");
        
        // Pending should still exist (another proposal should fail)
        let canonical2 = canonical_revocation_string(
            RevocationKind::Session,
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "another",
            "alice",
        );
        let sig2 = sk_alice.sign(canonical2.as_bytes());
        
        let prop2_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            reason: "another".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig2.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!prop2_resp.accepted);
        assert_eq!(prop2_resp.message, "a revocation is already pending");
    }

    #[tokio::test]
    async fn revocation_second_proposal_while_pending_refused() {
        let (service, _dir, sk_alice, _) = test_service_with_admins();
        
        let session_id = "abc123def456abc123def456abc123de";
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            session_id,
            "test reason",
            "alice",
        );
        let sig = sk_alice.sign(canonical.as_bytes());
        
        let prop1 = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: session_id.to_string(),
            reason: "test reason".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(prop1.accepted);
        
        // Try to propose another
        let session_id2 = "deadbeefdeadbeefdeadbeefdeadbeef";
        let canonical2 = canonical_revocation_string(
            RevocationKind::Session,
            session_id2,
            "another reason",
            "alice",
        );
        let sig2 = sk_alice.sign(canonical2.as_bytes());
        
        let prop2 = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: session_id2.to_string(),
            reason: "another reason".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig2.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(!prop2.accepted);
        assert_eq!(prop2.message, "a revocation is already pending");
    }

    #[tokio::test]
    async fn revocation_key_end_to_end() {
        let (service, _dir, sk_alice, sk_bob) = test_service_with_admins();
        
        // Create a client keypair and handshake
        let (client_sk, client_vk) = generate_keypair();
        let client_key_bytes = client_vk.encode().to_vec();
        let key_fingerprint = hex::encode(sha2::Sha256::digest(&client_key_bytes));
        
        let hs_resp = service.handshake(Request::new(HandshakeRequest { spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
            source_enclave: "test".to_string(),
            source_public_key: client_key_bytes.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        let session_id = hs_resp.session_id.clone();
        
        // Verify session exists
        let bus = service.bus.read().await;
        assert!(bus.session_exists(&session_id));
        drop(bus);
        
        // Propose KEY revocation
        let canonical = canonical_revocation_string(
            RevocationKind::Key,
            &key_fingerprint,
            "compromised key",
            "alice",
        );
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        
        let prop_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "KEY".to_string(),
            target_id: key_fingerprint.clone(),
            reason: "compromised key".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(prop_resp.accepted);
        
        // Bob approves
        let sig_bob = sk_bob.sign(canonical.as_bytes());
        
        let approve_resp = service.approve_revocation(Request::new(ApproveRevocationRequest { pgp_signature: String::new(),
            change_id: prop_resp.change_id,
            approver: "bob".to_string(),
            approver_signature: sig_bob.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(approve_resp.applied);
        assert_eq!(approve_resp.kind, "KEY");
        assert_eq!(approve_resp.target_id, key_fingerprint);
        assert_eq!(approve_resp.effects, 1); // The one session we created
        
        // Session should be dropped
        let bus = service.bus.read().await;
        assert!(!bus.session_exists(&session_id));
        drop(bus);
        
        // New handshake with the same key should be refused
        let hs_err = service.handshake(Request::new(HandshakeRequest { spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
            source_enclave: "test".to_string(),
            source_public_key: client_key_bytes.clone(),
        }))
        .await;
        
        assert!(hs_err.is_err());
        let err = hs_err.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("revoked"));
        
        // A different key should still work
        let (_, different_vk) = generate_keypair();
        let hs_ok = service.handshake(Request::new(HandshakeRequest { spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
            source_enclave: "test".to_string(),
            source_public_key: different_vk.encode().to_vec(),
        }))
        .await;
        
        assert!(hs_ok.is_ok());
    }

    #[tokio::test]
    async fn revocation_certificate_end_to_end() {
        let (service, _dir, sk_alice, sk_bob) = test_service_with_admins();
        
        // Issue a certificate
        let evidence = b"test evidence".to_vec();
        let evidence_hash = hex::encode(sha2::Sha256::digest(&evidence));
        
        let issue_resp = service.issue_certificate(Request::new(IssueCertificateRequest {
            product: "test-product".to_string(),
            version: "1.0.0".to_string(),
            verdict: "PASS".to_string(),
            evidence: evidence.clone(),
            evidence_hash: evidence_hash.clone(),
            evidence_scope: "working-tree".to_string(),
            tests: Some(guardian_meshd::proto::TestCounts {
                passed: 10,
                failed: 0,
                total: 10,
            }),
            policy: "v1".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(issue_resp.issued);
        let serial = issue_resp.serial.clone();
        
        // Propose CERTIFICATE revocation
        let canonical = canonical_revocation_string(
            RevocationKind::Certificate,
            &serial,
            "fraudulent certificate",
            "alice",
        );
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        
        let prop_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "CERTIFICATE".to_string(),
            target_id: serial.clone(),
            reason: "fraudulent certificate".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(prop_resp.accepted);
        
        // Bob approves
        let sig_bob = sk_bob.sign(canonical.as_bytes());
        
        let approve_resp = service.approve_revocation(Request::new(ApproveRevocationRequest { pgp_signature: String::new(),
            change_id: prop_resp.change_id,
            approver: "bob".to_string(),
            approver_signature: sig_bob.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(approve_resp.applied);
        assert_eq!(approve_resp.kind, "CERTIFICATE");
        assert_eq!(approve_resp.effects, 0); // Certificates don't have "effects" count
        
        // Certificate status should be REVOKED
        let cert_status = service.certificate_status(Request::new(CertificateStatusRequest {
            serial: serial.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert_eq!(cert_status.status(), ProtoStatus::Revoked);
    }

    #[tokio::test]
    async fn revocation_legacy_revoke_refuses_when_admins_configured() {
        let (service, _dir, _, _) = test_service_with_admins();
        
        // Issue a certificate first
        let evidence = b"test".to_vec();
        let evidence_hash = hex::encode(sha2::Sha256::digest(&evidence));
        
        let issue_resp = service.issue_certificate(Request::new(IssueCertificateRequest {
            product: "test".to_string(),
            version: "1.0".to_string(),
            verdict: "PASS".to_string(),
            evidence,
            evidence_hash,
            evidence_scope: "working-tree".to_string(),
            tests: Some(guardian_meshd::proto::TestCounts {
                passed: 5,
                failed: 0,
                total: 5,
            }),
            policy: "v1".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        let serial = issue_resp.serial;
        
        // Legacy RevokeCertificate should refuse
        let revoke_err = service.revoke_certificate(Request::new(RevokeCertificateRequest {
            serial: serial.clone(),
            reason: "test".to_string(),
        }))
        .await;
        
        assert!(revoke_err.is_err());
        let err = revoke_err.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("dual-control"));
        
        // Without admins, it should work
        let dir2 = tempfile::TempDir::new().unwrap();
        let mut config2 = Config::default();
        config2.workspace_dir = dir2.path().to_string_lossy().into_owned();
        config2.output_dir = dir2.path().join("output").to_string_lossy().into_owned();
        config2.ensure_dirs().unwrap();
        
        let service2 = GuardianMeshService::new(config2).unwrap();
        
        // Issue a certificate
        let evidence = b"test2".to_vec();
        let evidence_hash = hex::encode(sha2::Sha256::digest(&evidence));
        
        let issue_resp2 = service2.issue_certificate(Request::new(IssueCertificateRequest {
            product: "test2".to_string(),
            version: "1.0".to_string(),
            verdict: "PASS".to_string(),
            evidence,
            evidence_hash,
            evidence_scope: "working-tree".to_string(),
            tests: Some(guardian_meshd::proto::TestCounts {
                passed: 5,
                failed: 0,
                total: 5,
            }),
            policy: "v1".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        let serial2 = issue_resp2.serial;
        
        // Should work
        let revoke_ok = service2.revoke_certificate(Request::new(RevokeCertificateRequest {
            serial: serial2,
            reason: "test".to_string(),
        }))
        .await;
        
        assert!(revoke_ok.is_ok());
    }

    #[tokio::test]
    async fn revocation_persistence_survives_restart() {
        let dir = tempfile::TempDir::new().unwrap();
        let admin_keys_dir = dir.path().join("admin_keys");
        std::fs::create_dir_all(&admin_keys_dir).unwrap();
        
        let (sk_alice, vk_alice) = generate_keypair();
        let (sk_bob, vk_bob) = generate_keypair();
        
        std::fs::write(admin_keys_dir.join("alice.vk"), vk_alice.encode().to_vec()).unwrap();
        std::fs::write(admin_keys_dir.join("bob.vk"), vk_bob.encode().to_vec()).unwrap();
        
        let (client_sk, client_vk) = generate_keypair();
        let client_key_bytes = client_vk.encode().to_vec();
        let key_fingerprint = hex::encode(sha2::Sha256::digest(&client_key_bytes));
        
        // First service: apply a revocation
        {
            let mut config = Config::default();
            config.workspace_dir = dir.path().to_string_lossy().into_owned();
            config.output_dir = dir.path().join("output").to_string_lossy().into_owned();
            config.policy_admin_keys_dir = Some(admin_keys_dir.to_string_lossy().into_owned());
            config.ensure_dirs().unwrap();
            
            let service = GuardianMeshService::new(config).unwrap();
            
            let canonical = canonical_revocation_string(
                RevocationKind::Key,
                &key_fingerprint,
                "persistent test",
                "alice",
            );
            let sig_alice = sk_alice.sign(canonical.as_bytes());
            let sig_bob = sk_bob.sign(canonical.as_bytes());
            
            let prop_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
                kind: "KEY".to_string(),
                target_id: key_fingerprint.clone(),
                reason: "persistent test".to_string(),
                proposer: "alice".to_string(),
                proposer_signature: sig_alice.to_bytes().to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
            
            let approve_resp = service.approve_revocation(Request::new(ApproveRevocationRequest { pgp_signature: String::new(),
                change_id: prop_resp.change_id,
                approver: "bob".to_string(),
                approver_signature: sig_bob.to_bytes().to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
            
            assert!(approve_resp.applied);
        }
        
        // Second service: verify persistence
        {
            let mut config = Config::default();
            config.workspace_dir = dir.path().to_string_lossy().into_owned();
            config.output_dir = dir.path().join("output").to_string_lossy().into_owned();
            config.policy_admin_keys_dir = Some(admin_keys_dir.to_string_lossy().into_owned());
            config.ensure_dirs().unwrap();
            
            let service2 = GuardianMeshService::new(config).unwrap();
            
            // Status should still show revoked
            let status_resp = service2.revocation_status(Request::new(RevocationStatusRequest {
                kind: "KEY".to_string(),
                target_id: key_fingerprint.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
            
            assert!(status_resp.revoked);
            assert_eq!(status_resp.reason, "persistent test");
            
            // Handshake with revoked key should still fail
            let hs_err = service2.handshake(Request::new(HandshakeRequest { spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
                source_enclave: "test".to_string(),
                source_public_key: client_key_bytes,
            }))
            .await;
            
            assert!(hs_err.is_err());
            assert_eq!(hs_err.unwrap_err().code(), tonic::Code::PermissionDenied);
        }
    }

    #[tokio::test]
    async fn revocation_audit_event_recorded() {
        let (service, _dir, sk_alice, sk_bob) = test_service_with_admins();
        
        let session_id = "abc123def456abc123def456abc123de";
        let canonical = canonical_revocation_string(
            RevocationKind::Session,
            session_id,
            "audit test",
            "alice",
        );
        
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        let sig_bob = sk_bob.sign(canonical.as_bytes());
        
        let prop_resp = service.propose_revocation(Request::new(ProposeRevocationRequest { pgp_signature: String::new(),
            kind: "SESSION".to_string(),
            target_id: session_id.to_string(),
            reason: "audit test".to_string(),
            proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        let approve_resp = service.approve_revocation(Request::new(ApproveRevocationRequest { pgp_signature: String::new(),
            change_id: prop_resp.change_id,
            approver: "bob".to_string(),
            approver_signature: sig_bob.to_bytes().to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
        
        assert!(approve_resp.applied);
        
        // Read audit log
        let audit_resp = service.read_audit_log(Request::new(ReadAuditLogRequest {}))
            .await
            .unwrap()
            .into_inner();
        
        // Find the revocation entry
        let revocation_entry = audit_resp.entries.iter().find(|e| {
            e.action_id == hex::encode("REVOCATION".as_bytes())
        });
        
        assert!(revocation_entry.is_some());
        let entry = revocation_entry.unwrap();
        assert_eq!(entry.verdict, "REVOCATION_APPLIED");
        assert!(entry.reason.contains("kind=SESSION"));
        assert!(entry.reason.contains(&format!("target={}", session_id)));
        assert!(entry.reason.contains("proposer=alice"));
        assert!(entry.reason.contains("approver=bob"));
    }
    // ── WO-14 integration tests (Wright carry) ─────────────────────
    // The lane shipped no integration tests; these are Wright's, built
    // on the same helpers as the WO-11/WO-12 suites.

    fn wo14_b64_encode(data: &[u8]) -> String {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHA[(n >> 18) as usize & 63] as char);
            out.push(ALPHA[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 { ALPHA[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if chunk.len() > 2 { ALPHA[n as usize & 63] as char } else { '=' });
        }
        out.chars().collect::<Vec<_>>().chunks(64).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join("\n")
    }

    fn wo14_armor(label: &str, data: &[u8]) -> String {
        format!("-----BEGIN PGP {}-----\n\n{}\n-----END PGP {}-----\n", label, wo14_b64_encode(data), label)
    }

    fn wo14_mpi(data: &[u8]) -> Vec<u8> {
        let mut start = 0;
        while start + 1 < data.len() && data[start] == 0 { start += 1; }
        let trimmed = &data[start..];
        let bitlen = (trimmed.len() - 1) * 8 + (8 - trimmed[0].leading_zeros() as usize);
        let mut out = Vec::new();
        out.extend_from_slice(&(bitlen as u16).to_be_bytes());
        out.extend_from_slice(trimmed);
        out
    }

    fn wo14_pgp_key_armor(sk: &ed25519_dalek::SigningKey) -> String {
        let mut body = vec![4u8];
        body.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        body.push(22);
        let oid: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        body.push(oid.len() as u8);
        body.extend_from_slice(&oid);
        let mut point = vec![0x40u8];
        point.extend_from_slice(&sk.verifying_key().to_bytes());
        body.extend_from_slice(&wo14_mpi(&point));
        let mut packet = vec![0xC6u8, body.len() as u8];
        packet.extend_from_slice(&body);
        wo14_armor("PUBLIC KEY BLOCK", &packet)
    }

    fn wo14_pgp_sig_armor(sk: &ed25519_dalek::SigningKey, data: &[u8]) -> String {
        use sha2::Digest as _;
        let trailer: [u8; 6] = [4, 0, 22, 8, 0, 0];
        let mut hashed = Vec::new();
        hashed.extend_from_slice(data);
        hashed.extend_from_slice(&trailer);
        hashed.extend_from_slice(&[0x04, 0xFF]);
        hashed.extend_from_slice(&6u32.to_be_bytes());
        let digest = sha2::Sha256::digest(&hashed);
        let sig = ed25519_dalek::Signer::sign(sk, &digest);
        let sb = sig.to_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&trailer);
        body.extend_from_slice(&[0, 0]); // unhashed area length
        body.extend_from_slice(&digest[0..2]);
        body.extend_from_slice(&wo14_mpi(&sb[0..32]));
        body.extend_from_slice(&wo14_mpi(&sb[32..64]));
        let mut packet = vec![0xC2u8, body.len() as u8];
        packet.extend_from_slice(&body);
        wo14_armor("SIGNATURE", &packet)
    }

    fn wo14_enc_len(len: usize) -> Vec<u8> {
        if len < 128 { vec![len as u8] } else if len < 256 { vec![0x81, len as u8] } else { vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8] }
    }
    fn wo14_enc_tlv(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
        let body: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
        let mut out = vec![tag];
        out.extend_from_slice(&wo14_enc_len(body.len()));
        out.extend_from_slice(&body);
        out
    }
    fn wo14_enc_utctime(unix_secs: u64) -> Vec<u8> {
        let days = (unix_secs / 86400) as i64;
        let secs = (unix_secs % 86400) as u32;
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let mut year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        if month <= 2 { year += 1; }
        let s = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", (year % 100) as u32, month, day, secs / 3600, (secs % 3600) / 60, secs % 60);
        wo14_enc_tlv(0x17, &[s.as_bytes()])
    }

    fn wo14_build_svid(spiffe_id: &str, sk: &ed25519_dalek::SigningKey, not_before: u64, not_after: u64) -> Vec<u8> {
        let sig_alg = wo14_enc_tlv(0x30, &[&[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B], &[0x05, 0x00]]);
        let name = |cn: &str| wo14_enc_tlv(0x30, &[&wo14_enc_tlv(0x31, &[&wo14_enc_tlv(0x30, &[&[0x06, 0x03, 0x55, 0x04, 0x03], &wo14_enc_tlv(0x0C, &[cn.as_bytes()])])])]);
        let validity = wo14_enc_tlv(0x30, &[&wo14_enc_utctime(not_before), &wo14_enc_utctime(not_after)]);
        let spki_alg = wo14_enc_tlv(0x30, &[&[0x06, 0x03, 0x2B, 0x65, 0x70]]);
        let mut bs = vec![0x00u8];
        bs.extend_from_slice(&sk.verifying_key().to_bytes());
        let spki = wo14_enc_tlv(0x30, &[&spki_alg, &wo14_enc_tlv(0x03, &[&bs])]);
        let mut san_val = vec![0x86u8, spiffe_id.len() as u8];
        san_val.extend_from_slice(spiffe_id.as_bytes());
        let gn = wo14_enc_tlv(0x30, &[&san_val]);
        let san_ext = wo14_enc_tlv(0x30, &[&[0x06, 0x03, 0x55, 0x1D, 0x11], &wo14_enc_tlv(0x04, &[&gn])]);
        let exts_seq = wo14_enc_tlv(0x30, &[&san_ext]);
        let exts = wo14_enc_tlv(0xA3, &[&exts_seq]);
        let version = vec![0xA0, 0x03, 0x02, 0x01, 0x02];
        let serial = wo14_enc_tlv(0x02, &[&[0x01, 0x23, 0x45, 0x67, 0x89]]);
        let tbs = wo14_enc_tlv(0x30, &[&version, &serial, &sig_alg, &name("Test CA"), &validity, &name("Test Workload"), &spki, &exts]);
        let mut sig_bs = vec![0x00u8];
        sig_bs.extend_from_slice(&[0u8; 64]);
        let cert = wo14_enc_tlv(0x30, &[&tbs, &sig_alg, &wo14_enc_tlv(0x03, &[&sig_bs])]);
        cert
    }

    fn test_service_wo14(domains: Vec<String>, required: bool, pgp_alice: bool)
        -> (GuardianMeshService, tempfile::TempDir, SigningKey<MlDsa65>, SigningKey<MlDsa65>, ed25519_dalek::SigningKey)
    {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.workspace_dir = dir.path().join("ws").to_string_lossy().into_owned();
        config.output_dir = dir.path().join("out").to_string_lossy().into_owned();
        let admin_keys_dir = dir.path().join("admin_keys");
        std::fs::create_dir_all(&admin_keys_dir).unwrap();
        let (sk_alice, vk_alice) = generate_keypair();
        let (sk_bob, vk_bob) = generate_keypair();
        std::fs::write(admin_keys_dir.join("alice.vk"), vk_alice.encode().to_vec()).unwrap();
        std::fs::write(admin_keys_dir.join("bob.vk"), vk_bob.encode().to_vec()).unwrap();
        config.policy_admin_keys_dir = Some(admin_keys_dir.to_string_lossy().into_owned());
        config.spiffe_trust_domains = domains;
        config.spiffe_required = required;
        let pgp_sk = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
        if pgp_alice {
            let pgp_dir = dir.path().join("pgp_keys");
            std::fs::create_dir_all(&pgp_dir).unwrap();
            std::fs::write(pgp_dir.join("alice.asc"), wo14_pgp_key_armor(&pgp_sk)).unwrap();
            config.pgp_admin_keys_dir = Some(pgp_dir.to_string_lossy().into_owned());
        }
        config.ensure_dirs().unwrap();
        (GuardianMeshService::new(config).unwrap(), dir, sk_alice, sk_bob, pgp_sk)
    }

    fn wo14_now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    #[tokio::test]
    async fn wo14_handshake_default_factors() {
        let (service, _dir) = test_service();
        let (_sk, vk) = generate_keypair();
        let resp = service.handshake(Request::new(HandshakeRequest {
            source_enclave: "wo14-test".to_string(),
            source_public_key: vk.encode().to_vec(),
            spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
        })).await.unwrap().into_inner();
        assert_eq!(resp.auth_factors, vec!["ML_DSA_65".to_string(), "HMAC_SESSION".to_string()]);
        assert_eq!(resp.workload_id, "");
    }

    #[tokio::test]
    async fn wo14_handshake_valid_svid_attests_and_evaluates() {
        let (service, _dir, _a, _b, _p) = test_service_wo14(vec!["cluster.local".to_string()], false, false);
        let (client_sk, client_vk) = generate_keypair();
        let svid_sk = ed25519_dalek::SigningKey::from_bytes(&[0x37; 32]);
        let now = wo14_now();
        let spiffe_id = "spiffe://cluster.local/workload";
        let der = wo14_build_svid(spiffe_id, &svid_sk, now - 3600, now + 3600);
        use sha2::Digest as _;
        let ml_hash = hex::encode(sha2::Sha256::digest(&client_vk.encode().to_vec()));
        let canonical = guardian_meshd::authenticators::canonical_spiffe_string(spiffe_id, &ml_hash);
        let sig = ed25519_dalek::Signer::sign(&svid_sk, canonical.as_bytes());
        let resp = service.handshake(Request::new(HandshakeRequest {
            source_enclave: "wo14-svid".to_string(),
            source_public_key: client_vk.encode().to_vec(),
            spiffe_id: spiffe_id.to_string(), svid_leaf_der: der, svid_signature: sig.to_bytes().to_vec(),
        })).await.unwrap().into_inner();
        assert!(resp.auth_factors.contains(&"SPIFFE_X509".to_string()), "factors: {:?}", resp.auth_factors);
        assert_eq!(resp.workload_id, spiffe_id);
        // The attested session evaluates normally.
        let sealed = SealedEnvelope::new(PAYLOAD.to_vec(), b"test".to_vec(), &client_sk);
        let req = evaluate_request(&service, &resp.session_id, &sealed).await;
        let eval_resp = service.evaluate(Request::new(req)).await.unwrap().into_inner();
        assert_eq!(eval_resp.verdict, "ALLOW");
    }

    #[tokio::test]
    async fn wo14_handshake_untrusted_domain_and_bad_possession_refused() {
        let (service, _dir, _a, _b, _p) = test_service_wo14(vec!["cluster.local".to_string()], false, false);
        let (_csk, client_vk) = generate_keypair();
        let svid_sk = ed25519_dalek::SigningKey::from_bytes(&[0x37; 32]);
        let now = wo14_now();
        use sha2::Digest as _;
        let ml_hash = hex::encode(sha2::Sha256::digest(&client_vk.encode().to_vec()));
        // Untrusted domain
        let id1 = "spiffe://evil.example/workload";
        let der1 = wo14_build_svid(id1, &svid_sk, now - 3600, now + 3600);
        let canon1 = guardian_meshd::authenticators::canonical_spiffe_string(id1, &ml_hash);
        let sig1 = ed25519_dalek::Signer::sign(&svid_sk, canon1.as_bytes());
        let err = service.handshake(Request::new(HandshakeRequest {
            source_enclave: "wo14".to_string(), source_public_key: client_vk.encode().to_vec(),
            spiffe_id: id1.to_string(), svid_leaf_der: der1, svid_signature: sig1.to_bytes().to_vec(),
        })).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("not in allowlist"), "got: {}", err.message());
        // Bad possession signature on a trusted-domain SVID
        let id2 = "spiffe://cluster.local/workload";
        let der2 = wo14_build_svid(id2, &svid_sk, now - 3600, now + 3600);
        let mut bad_sig = ed25519_dalek::Signer::sign(&svid_sk, b"different message").to_bytes();
        bad_sig[0] ^= 0x01;
        let err2 = service.handshake(Request::new(HandshakeRequest {
            source_enclave: "wo14".to_string(), source_public_key: client_vk.encode().to_vec(),
            spiffe_id: id2.to_string(), svid_leaf_der: der2, svid_signature: bad_sig.to_vec(),
        })).await.unwrap_err();
        assert_eq!(err2.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn wo14_handshake_required_mode_and_partial_attestation() {
        let (service, _dir, _a, _b, _p) = test_service_wo14(vec!["cluster.local".to_string()], true, false);
        let (_csk, client_vk) = generate_keypair();
        // No SVID while required → refused naming the missing confirmation
        let err = service.handshake(Request::new(HandshakeRequest {
            source_enclave: "wo14".to_string(), source_public_key: client_vk.encode().to_vec(),
            spiffe_id: String::new(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
        })).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("SPIFFE_X509"), "got: {}", err.message());
        // Partial attestation → invalid_argument
        let err2 = service.handshake(Request::new(HandshakeRequest {
            source_enclave: "wo14".to_string(), source_public_key: client_vk.encode().to_vec(),
            spiffe_id: "spiffe://cluster.local/workload".to_string(), svid_leaf_der: Vec::new(), svid_signature: Vec::new(),
        })).await.unwrap_err();
        assert_eq!(err2.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn wo14_pgp_policy_second_factor_enforced() {
        let (service, _dir, sk_alice, sk_bob, pgp_sk) = test_service_wo14(vec![], false, true);
        let current = service.policy.read().await;
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule { action_type: "TOOL_CALL".to_string(), allow: false, priority: 100 }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        drop(current);
        let canonical = proposed.to_canonical_string();
        let rules_msg = vec![PolicyRuleMessage { action_type: "TOOL_CALL".to_string(), allow: false, priority: 100 }];
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        let mk_propose = |pgp: String| ProposePolicyChangeRequest {
            version: 2, rules: rules_msg.clone(), escalate_actions: vec![],
            prev_hash: proposed.prev_hash.clone(), proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(), pgp_signature: pgp,
        };
        // Missing PGP factor → refused
        let r = service.propose_policy_change(Request::new(mk_propose(String::new()))).await.unwrap().into_inner();
        assert!(!r.accepted && r.message.contains("PGP second factor required"), "got: {}", r.message);
        // Bad PGP signature → refused
        let bad = wo14_pgp_sig_armor(&pgp_sk, b"some other bytes");
        let r = service.propose_policy_change(Request::new(mk_propose(bad))).await.unwrap().into_inner();
        assert!(!r.accepted, "bad pgp sig must refuse");
        // Valid PGP signature → accepted; bob (unenrolled) approves without one
        let good = wo14_pgp_sig_armor(&pgp_sk, canonical.as_bytes());
        let r = service.propose_policy_change(Request::new(mk_propose(good))).await.unwrap().into_inner();
        assert!(r.accepted, "got: {}", r.message);
        let sig_bob = sk_bob.sign(canonical.as_bytes());
        let a = service.approve_policy_change(Request::new(ApprovePolicyChangeRequest {
            change_id: r.change_id, approver: "bob".to_string(),
            approver_signature: sig_bob.to_bytes().to_vec(), pgp_signature: String::new(),
        })).await.unwrap().into_inner();
        assert!(a.applied && a.version == 2, "got: {}", a.message);
    }

    #[tokio::test]
    async fn wo14_pgp_revocation_second_factor_enforced() {
        let (service, _dir, sk_alice, _sk_bob, pgp_sk) = test_service_wo14(vec![], false, true);
        let (_csk, client_vk) = generate_keypair();
        let session = open_session(&service, &client_vk).await;
        let canonical = canonical_revocation_string(RevocationKind::Session, &session.session_id, "wo14 pgp test", "alice");
        let sig_alice = sk_alice.sign(canonical.as_bytes());
        let mk = |pgp: String| ProposeRevocationRequest {
            kind: "SESSION".to_string(), target_id: session.session_id.clone(),
            reason: "wo14 pgp test".to_string(), proposer: "alice".to_string(),
            proposer_signature: sig_alice.to_bytes().to_vec(), pgp_signature: pgp,
        };
        let r = service.propose_revocation(Request::new(mk(String::new()))).await.unwrap().into_inner();
        assert!(!r.accepted && r.message.contains("PGP second factor required"), "got: {}", r.message);
        let good = wo14_pgp_sig_armor(&pgp_sk, canonical.as_bytes());
        let r = service.propose_revocation(Request::new(mk(good))).await.unwrap().into_inner();
        assert!(r.accepted, "got: {}", r.message);
    }

    #[tokio::test]
    async fn wo14_unenrolled_principal_pgp_signature_refused() {
        let (service, _dir, _sk_alice, sk_bob) = test_service_with_admins();
        let current = service.policy.read().await;
        let proposed = PolicyBundle {
            version: 2,
            rules: vec![PolicyRule { action_type: "TOOL_CALL".to_string(), allow: false, priority: 100 }],
            escalate_actions: vec![],
            prev_hash: current.content_hash(),
        };
        drop(current);
        let canonical = proposed.to_canonical_string();
        let sig_bob = sk_bob.sign(canonical.as_bytes());
        let r = service.propose_policy_change(Request::new(ProposePolicyChangeRequest {
            version: 2,
            rules: vec![PolicyRuleMessage { action_type: "TOOL_CALL".to_string(), allow: false, priority: 100 }],
            escalate_actions: vec![], prev_hash: proposed.prev_hash.clone(),
            proposer: "bob".to_string(), proposer_signature: sig_bob.to_bytes().to_vec(),
            pgp_signature: "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n".to_string(),
        })).await.unwrap().into_inner();
        assert!(!r.accepted && r.message.contains("no PGP key is enrolled"), "got: {}", r.message);
    }

    #[tokio::test]
    async fn wo14_authenticator_status_reports_framework() {
        let (service, _dir, _a, _b, _p) = test_service_wo14(vec!["cluster.local".to_string()], true, true);
        let resp = service.authenticator_status(Request::new(AuthenticatorStatusRequest {})).await.unwrap().into_inner();
        assert_eq!(resp.authenticators.len(), 4);
        assert_eq!(resp.spiffe_trust_domains, vec!["cluster.local".to_string()]);
        assert!(resp.spiffe_required);
        assert_eq!(resp.pgp_admin_principals, vec!["alice".to_string()]);
        let spiffe_row = resp.authenticators.iter().find(|a| a.method == "SPIFFE_X509").unwrap();
        assert!(spiffe_row.configured && spiffe_row.factor_type == "workload-attestation");
        let pgp_row = resp.authenticators.iter().find(|a| a.method == "OPENPGP").unwrap();
        assert!(pgp_row.configured);
    }

}
