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
use guardian_meshd::sealed_envelope::{generate_keypair, SealedEnvelope};
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
            GatekeeperEnclave::evaluate(&mut ctx, &bus);
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
        let pf_passed = ProtocolFirewall::passed_count();
        let pf_total = ProtocolFirewall::total_count();

        let mut enclave_health = std::collections::HashMap::new();
        enclave_health.insert("sentinel".into(), "ok".into());
        enclave_health.insert("gatekeeper".into(), "ok".into());
        enclave_health.insert("witness".into(), "ok".into());
        enclave_health.insert("arbiter".into(), "ok".into());
        enclave_health.insert("vault".into(), "ok".into());

        let response = HealthResponse {
            status: ServingStatus::Serving.into(),
            enclave_health,
            protocol_firewall_rules_passed: pf_passed,
            protocol_firewall_rules_total: pf_total,
        };

        Ok(Response::new(response))
    }

    async fn handshake(
        &self,
        request: Request<HandshakeRequest>,
    ) -> Result<Response<HandshakeResponse>, Status> {
        let req = request.into_inner();
        let source = if req.source_enclave.is_empty() {
            "unknown".to_string()
        } else {
            req.source_enclave
        };

        let bus = self.bus.read().await;
        bus.evict_expired();
        let session = bus.create_session_full(&source);

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
