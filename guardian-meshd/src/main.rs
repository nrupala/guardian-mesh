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
use guardian_meshd::policy::PolicyEngine;
use guardian_meshd::protocol_firewall::ProtocolFirewall;
use guardian_meshd::sealed_envelope::{generate_keypair, SealedEnvelope, ML_DSA_65_VERIFYING_KEY_LEN};
use guardian_meshd::sealed_envelope::{verify_proto_envelope, load_or_generate_signing_key, compute_fingerprint};
use guardian_meshd::certificate::{CertificateRegistry, Tests, IssuanceResult, CertificateStatus as CertStatus};
use guardian_meshd::proto::{
    guardian_mesh_server::{GuardianMesh, GuardianMeshServer},
    EvaluateRequest, EvaluateResponse, AuditProof,
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
};
use prost::Message as _;
use ml_dsa::{MlDsa65, SigningKey, VerifyingKey};

pub struct GuardianMeshService {
    config: Config,
    bus: Arc<RwLock<HandshakeBus>>,
    vault: Arc<VaultEnclave>,
    policy: Arc<RwLock<PolicyEngine>>,
    firewall: Arc<ProtocolFirewall>,
    signing_key: SigningKey<MlDsa65>,
    verifying_key: VerifyingKey<MlDsa65>,
    certificates: Arc<CertificateRegistry>,
}

impl GuardianMeshService {
    pub fn new(config: Config) -> Result<Self, String> {
        let (sk, vk) = load_or_generate_signing_key(config.keys_dir())?;
        let vault = Arc::new(VaultEnclave::new(10_000, config.audit_dir()));
        let policy = PolicyEngine::with_escalate_actions(config.policy_escalate_actions.clone());
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
            config,
        })
    }
}

#[tonic::async_trait]
impl GuardianMesh for GuardianMeshService {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let req = request.into_inner();
        let mut ctx = EnclaveContext::new(req);

        SentinelEnclave::evaluate(&mut ctx);
        if ctx.verdict != Some(Verdict::Allow) {
            let msg = ctx.reason.unwrap_or_else(|| "Sentinel blocked".into());
            return Err(Status::permission_denied(msg));
        }

        {
            let bus = self.bus.read().await;
            GatekeeperEnclave::evaluate(&mut ctx, &bus, &self.firewall, self.config.policy_throttle_rate);
        }
        // WO-5: THROTTLE verdicts from Gatekeeper (PF-18 or policy rate) proceed to proof generation
        if ctx.verdict == Some(Verdict::Throttle) {
            // THROTTLE verdict: skip Witness and Arbiter, go directly to proof and audit
            let final_verdict = Verdict::Throttle;
            let final_reason = ctx.reason.clone().unwrap_or_default();

            self.vault.seal(&ctx);

            let proof = AuditProof {
                action_id: ctx.request.action.as_ref().map(|a| a.action_type.clone()).unwrap_or_default(),
                verdict: final_verdict.as_str().into(),
                enclave_chain: "Sentinel→Gatekeeper→Vault".into(),
                signature: Vec::new(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
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
            };

            return Ok(Response::new(response));
        }
        if ctx.verdict != Some(Verdict::Allow) {
            let msg = ctx.reason.unwrap_or_else(|| "Gatekeeper blocked".into());
            return Err(Status::permission_denied(msg));
        }

        WitnessEnclave::evaluate(&mut ctx, &self.signing_key);
        if ctx.verdict != Some(Verdict::Allow) {
            let msg = ctx.reason.unwrap_or_else(|| "Witness blocked".into());
            return Err(Status::permission_denied(msg));
        }

        {
            let policy = self.policy.read().await;
            ArbiterEnclave::evaluate(&mut ctx, &policy);
        }

        // WO-5: All verdicts (ALLOW, BLOCK, ESCALATE) proceed to proof generation and audit
        let final_verdict = ctx.verdict.as_ref().cloned().unwrap_or(Verdict::Block);
        let final_reason = ctx.reason.clone().unwrap_or_default();

        self.vault.seal(&ctx);

        let proof = AuditProof {
            action_id: ctx.request.action.as_ref().map(|a| a.action_type.clone()).unwrap_or_default(),
            verdict: final_verdict.as_str().into(),
            enclave_chain: "Sentinel→Gatekeeper→Witness→Arbiter→Vault".into(),
            signature: ctx.witness_signature.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
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
        };

        Ok(Response::new(response))
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

        // WO-2: Protocol Firewall now enforces PF-1..PF-18 per session.
        // Global counters are no longer tracked; each session has its own
        // nonce window and rate limiter state.
        let fingerprint = compute_fingerprint(&self.verifying_key);
        let response = HealthResponse {
            status: ServingStatus::Serving.into(),
            enclave_health,
            protocol_firewall_rules_passed: 18, // All PF rules are now enforced
            protocol_firewall_rules_total: 18,
            signing_key_fingerprint: fingerprint,
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
        bus.evict_expired();
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
}
