// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: AGPL-3.0-or-later

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
use guardian_meshd::sealed_envelope::verify_proto_envelope;
use guardian_meshd::proto::{
    guardian_mesh_server::{GuardianMesh, GuardianMeshServer},
    EvaluateRequest, EvaluateResponse, AuditProof,
    VerifyProofRequest, VerifyProofResponse,
    HealthRequest, HealthResponse,
    HandshakeRequest, HandshakeResponse,
    SealedEnvelope as ProtoSealedEnvelope,
    health_response::ServingStatus,
};
use prost::Message as _;
use ml_dsa::{MlDsa65, SigningKey, VerifyingKey};

pub struct GuardianMeshService {
    #[allow(dead_code)]
    config: Config,
    bus: Arc<RwLock<HandshakeBus>>,
    vault: Arc<RwLock<VaultEnclave>>,
    policy: Arc<RwLock<PolicyEngine>>,
    firewall: Arc<ProtocolFirewall>,
    signing_key: SigningKey<MlDsa65>,
    verifying_key: VerifyingKey<MlDsa65>,
}

impl GuardianMeshService {
    pub fn new(config: Config) -> Self {
        let (sk, vk) = generate_keypair();
        let vault = VaultEnclave::new(10_000, config.audit_dir());
        Self {
            bus: Arc::new(RwLock::new(HandshakeBus::new(&config.handshake_secret))),
            vault: Arc::new(RwLock::new(vault)),
            policy: Arc::new(RwLock::new(PolicyEngine::new())),
            firewall: Arc::new(ProtocolFirewall::new()),
            signing_key: sk,
            verifying_key: vk,
            config,
        }
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
            GatekeeperEnclave::evaluate(&mut ctx, &bus, &self.firewall);
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

        let final_verdict = ctx.verdict.as_ref().cloned().unwrap_or(Verdict::Block);
        let final_reason = ctx.reason.clone().unwrap_or_default();

        {
            let vault = self.vault.write().await;
            vault.seal(&ctx);
        }

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
        let response = HealthResponse {
            status: ServingStatus::Serving.into(),
            enclave_health,
            protocol_firewall_rules_passed: 18, // All PF rules are now enforced
            protocol_firewall_rules_total: 18,
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

        let service = GuardianMeshService::new(config);

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
        (GuardianMeshService::new(config), dir)
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
}
