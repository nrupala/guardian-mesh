// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

// gm - Guardian Mesh operator CLI (WO-18 profile 3 / CC-4).
//
// This is an ordinary client of the running daemon: it opens a handshake
// session, seals an ActionDescriptor, calls Evaluate/Simulate, verifies
// saved proofs and reads the audit log. It holds no policy authority.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use guardian_meshd::config::Config;
use guardian_meshd::proto::guardian_mesh_client::GuardianMeshClient;
use guardian_meshd::proto::{
    ActionDescriptor, EvaluateRequest, FirewalledRequest, HandshakeRequest, HealthRequest,
    ReadAuditLogRequest, SealedEnvelope as ProtoSealedEnvelope, VerifyProofRequest,
};
use guardian_meshd::sealed_envelope::SealedEnvelope;
use hmac::{Hmac, KeyInit, Mac};
use ml_dsa::{Keypair, MlDsa65, SigningKey};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use tonic::Request;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:50051";
type HmacSha256 = Hmac<Sha256>;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args).await {
        Ok(code) => std::process::exit(code),
        Err(CliError::Help(text)) => {
            println!("{text}");
            std::process::exit(0);
        }
        Err(err) => {
            let code = err.code();
            eprintln!("gm: {}", err.message());
            if matches!(&err, CliError::Usage(_)) {
                eprintln!("Run `gm --help` for usage.");
            }
            std::process::exit(code);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliError {
    Help(String),
    Usage(String),
    Runtime(String),
}

impl CliError {
    fn help(text: impl Into<String>) -> Self {
        Self::Help(text.into())
    }

    fn usage(msg: impl Into<String>) -> Self {
        Self::Usage(msg.into())
    }

    fn runtime(msg: impl Into<String>) -> Self {
        Self::Runtime(msg.into())
    }

    fn code(&self) -> i32 {
        match self {
            Self::Help(_) => 0,
            Self::Usage(_) | Self::Runtime(_) => 2,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Help(text) | Self::Usage(text) | Self::Runtime(text) => text,
        }
    }
}

async fn run(args: Vec<String>) -> Result<i32, CliError> {
    let mut i = 0;
    let mut pre_endpoint: Option<String> = None;

    while i < args.len() {
        match args[i].as_str() {
            "--endpoint" => {
                pre_endpoint = Some(next_value(&args, &mut i, "--endpoint")?);
                i += 1;
            }
            "--help" | "-h" => return Err(CliError::help(global_help())),
            _ => break,
        }
    }

    if i >= args.len() {
        return Err(CliError::usage("missing subcommand"));
    }

    let subcommand = args[i].clone();
    let rest = &args[i + 1..];

    match subcommand.as_str() {
        "health" => cmd_health(rest, pre_endpoint).await,
        "handshake" => cmd_handshake(rest, pre_endpoint).await,
        "evaluate" => cmd_evaluate(rest, pre_endpoint).await,
        "verify" => cmd_verify(rest, pre_endpoint).await,
        "audit" => cmd_audit(rest, pre_endpoint).await,
        "doctor" => cmd_doctor(rest, pre_endpoint),
        other => Err(CliError::usage(format!("unknown subcommand: {other}"))),
    }
}

fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, CliError> {
    *i += 1;
    match args.get(*i) {
        Some(value) => Ok(value.clone()),
        None => Err(CliError::usage(format!("{flag} requires a value"))),
    }
}

#[derive(Debug)]
struct HealthArgs {
    endpoint: Option<String>,
}

fn parse_health_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<HealthArgs, CliError> {
    let mut parsed = HealthArgs {
        endpoint: pre_endpoint,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--endpoint" => {
                parsed.endpoint = Some(next_value(args, &mut i, "--endpoint")?);
            }
            "--help" | "-h" => return Err(CliError::help(health_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(parsed)
}

#[derive(Debug)]
struct HandshakeArgs {
    tenant_id: Option<String>,
    session_file: PathBuf,
    endpoint: Option<String>,
}

fn parse_handshake_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<HandshakeArgs, CliError> {
    let mut tenant_id = None;
    let mut session_file = default_session_path();
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tenant" => tenant_id = Some(next_value(args, &mut i, "--tenant")?),
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(handshake_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(HandshakeArgs {
        tenant_id,
        session_file,
        endpoint,
    })
}

#[derive(Debug)]
struct EvaluateArgs {
    action_type: String,
    context: String,
    target: String,
    metadata: BTreeMap<String, String>,
    simulate: bool,
    session_file: PathBuf,
    proof_out: Option<PathBuf>,
    endpoint: Option<String>,
}

fn parse_evaluate_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<EvaluateArgs, CliError> {
    let mut action_type = None;
    let mut context = None;
    let mut target = None;
    let mut metadata = BTreeMap::new();
    let mut simulate = false;
    let mut session_file = default_session_path();
    let mut proof_out = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--action-type" => action_type = Some(next_value(args, &mut i, "--action-type")?),
            "--context" => context = Some(next_value(args, &mut i, "--context")?),
            "--target" => target = Some(next_value(args, &mut i, "--target")?),
            "--metadata" => {
                let raw = next_value(args, &mut i, "--metadata")?;
                match raw.split_once('=') {
                    Some((key, value)) if !key.is_empty() => {
                        metadata.insert(key.to_string(), value.to_string());
                    }
                    _ => {
                        return Err(CliError::usage(format!(
                            "bad --metadata form: '{raw}' (expected key=value)"
                        )))
                    }
                }
            }
            "--simulate" => simulate = true,
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--proof-out" => {
                proof_out = Some(PathBuf::from(next_value(args, &mut i, "--proof-out")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(evaluate_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }

    let action_type = action_type.ok_or_else(|| CliError::usage("--action-type is required"))?;
    let context = context.ok_or_else(|| CliError::usage("--context is required"))?;
    let target = target.ok_or_else(|| CliError::usage("--target is required"))?;

    Ok(EvaluateArgs {
        action_type,
        context,
        target,
        metadata,
        simulate,
        session_file,
        proof_out,
        endpoint,
    })
}

#[derive(Debug)]
struct VerifyArgs {
    proof_file: Option<PathBuf>,
    session_file: PathBuf,
    endpoint: Option<String>,
}

fn parse_verify_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<VerifyArgs, CliError> {
    let mut proof_file = None;
    let mut session_file = default_session_path();
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--proof-file" => {
                proof_file = Some(PathBuf::from(next_value(args, &mut i, "--proof-file")?))
            }
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(verify_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(VerifyArgs {
        proof_file,
        session_file,
        endpoint,
    })
}

#[derive(Debug)]
struct AuditArgs {
    limit: Option<usize>,
    session_file: PathBuf,
    endpoint: Option<String>,
}

fn parse_audit_args(args: &[String], pre_endpoint: Option<String>) -> Result<AuditArgs, CliError> {
    let mut limit = None;
    let mut session_file = default_session_path();
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" => {
                let raw = next_value(args, &mut i, "--limit")?;
                let parsed = raw.parse::<usize>().map_err(|_| {
                    CliError::usage(format!(
                        "--limit must be a non-negative integer, got '{raw}'"
                    ))
                })?;
                limit = Some(parsed);
            }
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(audit_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(AuditArgs {
        limit,
        session_file,
        endpoint,
    })
}

fn parse_doctor_args(
    args: &[String],
    _pre_endpoint: Option<String>,
) -> Result<(), CliError> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--endpoint" => {
                next_value(args, &mut i, "--endpoint")?;
            }
            "--help" | "-h" => return Err(CliError::help(doctor_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(())
}

fn cmd_doctor(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    parse_doctor_args(args, pre_endpoint)?;

    let config = Config::default();
    let findings = config.posture_findings();
    println!("posture: {}", config.posture.as_str());

    let mut blocking = 0usize;
    for finding in &findings {
        let severity = if finding.blocking {
            blocking += 1;
            "BLOCKING"
        } else {
            "warning"
        };
        println!("{} {}: {}", severity, finding.setting, finding.message);
    }

    let warnings = findings.len() - blocking;
    if blocking > 0 {
        println!("doctor: FAIL — {} blocking finding(s)", blocking);
        Ok(2)
    } else {
        println!(
            "doctor: OK — no blocking findings ({} warning(s))",
            warnings
        );
        Ok(0)
    }
}

async fn cmd_health(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let parsed = parse_health_args(args, pre_endpoint)?;
    let endpoint = resolve_endpoint(parsed.endpoint, None);
    let mut client = connect(&endpoint).await?;

    let health = client
        .health(Request::new(HealthRequest {}))
        .await
        .map_err(|e| CliError::runtime(format!("health RPC failed: {e}")))?
        .into_inner();

    let status_name = match health.status {
        0 => "UNKNOWN",
        1 => "SERVING",
        2 => "NOT_SERVING",
        3 => "DEGRADED",
        _ => "UNRECOGNIZED",
    };
    let healthy = matches!(status_name, "SERVING" | "DEGRADED");

    let out = json!({
        "status": status_name,
        "enclave_health": health.enclave_health,
        "protocol_firewall_rules_passed": health.protocol_firewall_rules_passed,
        "protocol_firewall_rules_total": health.protocol_firewall_rules_total,
        "signing_key_fingerprint": health.signing_key_fingerprint,
        "protocol_firewall_rule_counters": health.protocol_firewall_rule_counters,
        "build_version": health.build_version,
        "build_commit": health.build_commit,
        "binary_sha256": health.binary_sha256,
        "node_id": health.node_id,
        "degraded": health.degraded,
        "degraded_trigger": health.degraded_trigger,
        "degraded_safe_actions": health.degraded_safe_actions,
        "degraded_since_unix": health.degraded_since_unix,
    });
    print_json(&out);
    Ok(if healthy { 0 } else { 1 })
}

async fn cmd_handshake(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let parsed = parse_handshake_args(args, pre_endpoint)?;
    let endpoint = resolve_endpoint(parsed.endpoint, None);

    let mut seed_bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut seed_bytes)
        .map_err(|_| CliError::runtime("failed to generate session seed"))?;
    let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice())
        .map_err(|_| CliError::runtime("generated seed was not 32 bytes"))?;
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let verifying_key = signing_key.verifying_key();
    let encoded_verifying_key = verifying_key.encode();
    let encoded_bytes: &[u8] = encoded_verifying_key.as_ref();
    let verifying_key_bytes: Vec<u8> = encoded_bytes.to_vec();

    let mut client = connect(&endpoint).await?;
    let handshake = client
        .handshake(Request::new(HandshakeRequest {
            source_enclave: "gm-cli".to_string(),
            source_public_key: verifying_key_bytes,
            spiffe_id: String::new(),
            svid_leaf_der: Vec::new(),
            svid_signature: Vec::new(),
            tenant_id: parsed.tenant_id.unwrap_or_default(),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("handshake RPC failed: {e}")))?
        .into_inner();

    let session = SessionFile {
        endpoint: endpoint.clone(),
        session_id: handshake.session_id,
        session_key: hex::encode(&handshake.session_key),
        signing_seed: hex::encode(seed_bytes),
        tenant_id: handshake.tenant_id,
        created_unix: now_unix(),
        ttl_seconds: handshake.ttl_seconds,
    };
    save_session(&parsed.session_file, &session)?;

    let out = json!({
        "session_id": session.session_id,
        "ttl_seconds": session.ttl_seconds,
        "tenant_id": session.tenant_id,
        "session_file": parsed.session_file.display().to_string(),
    });
    print_json(&out);
    Ok(0)
}

async fn cmd_evaluate(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let parsed = parse_evaluate_args(args, pre_endpoint)?;
    let session = load_required_session(&parsed.session_file)?;
    ensure_session_fresh(&session)?;
    let endpoint = resolve_endpoint(parsed.endpoint.clone(), Some(&session));

    let seed_bytes = hex::decode(&session.signing_seed).map_err(|_| {
        CliError::runtime(format!(
            "session file {} has an invalid signing seed; run `gm handshake` again",
            parsed.session_file.display()
        ))
    })?;
    let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice()).map_err(|_| {
        CliError::runtime(format!(
            "session file {} has a signing seed that is not 32 bytes; run `gm handshake` again",
            parsed.session_file.display()
        ))
    })?;
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);

    let payload = build_payload(
        &parsed.action_type,
        &parsed.context,
        &parsed.target,
        &parsed.metadata,
    );
    let sealed = SealedEnvelope::new(
        payload.clone(),
        b"guardian_mesh.ActionDescriptor".to_vec(),
        &signing_key,
    );
    let envelope = proto_from_sealed(&sealed);

    let session_key = hex::decode(&session.session_key).map_err(|_| {
        CliError::runtime(format!(
            "session file {} has an invalid session key; run `gm handshake` again",
            parsed.session_file.display()
        ))
    })?;
    let mut mac = HmacSha256::new_from_slice(&session_key)
        .map_err(|e| CliError::runtime(format!("failed to initialise HMAC: {e}")))?;
    mac.update(&payload);
    let hmac_tag = mac.finalize().into_bytes().to_vec();

    let request = EvaluateRequest {
        firewalled: Some(FirewalledRequest {
            envelope: Some(envelope),
            source_enclave: "gm-cli".to_string(),
            handshake_session: session.session_id.clone(),
            hmac_tag,
        }),
        action: Some(ActionDescriptor {
            action_type: parsed.action_type.clone(),
            context: parsed.context.clone(),
            target: parsed.target.clone(),
            metadata: parsed.metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }),
    };

    let mut client = connect(&endpoint).await?;
    let response = if parsed.simulate {
        client.simulate(Request::new(request)).await
    } else {
        client.evaluate(Request::new(request)).await
    }
    .map_err(|e| {
        let operation = if parsed.simulate { "simulate" } else { "evaluate" };
        CliError::runtime(format!("{operation} RPC failed: {e}"))
    })?
    .into_inner();

    let proof_envelope = response.proof_envelope.as_ref().ok_or_else(|| {
        CliError::runtime("evaluate response did not include a proof envelope")
    })?;
    let proof_path = parsed
        .proof_out
        .clone()
        .unwrap_or_else(|| default_proof_path(&parsed.session_file));
    save_proof(&proof_path, proof_envelope)?;

    let proof = match response.proof.as_ref() {
        Some(proof) => json!({
            "action_id": proof.action_id.clone(),
            "verdict": proof.verdict.clone(),
            "timestamp": proof.timestamp,
            "policy_version": proof.policy_version,
            "issuing_node": proof.issuing_node.clone(),
        }),
        None => Value::Null,
    };
    let reasons: Vec<Value> = response
        .reasons
        .iter()
        .map(|reason| {
            json!({
                "rule_id": reason.rule_id.clone(),
                "detail": reason.detail.clone(),
                "remediation": reason.remediation.clone(),
            })
        })
        .collect();

    let out = json!({
        "verdict": response.verdict.clone(),
        "reason": response.reason.clone(),
        "containment_stage": response.containment_stage.clone(),
        "simulation": response.simulation,
        "reasons": reasons,
        "proof": proof,
    });
    print_json(&out);
    Ok(0)
}

async fn cmd_verify(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let parsed = parse_verify_args(args, pre_endpoint)?;
    let session = load_session_optional(&parsed.session_file)?;
    let endpoint = resolve_endpoint(parsed.endpoint, session.as_ref());
    let proof_path = parsed
        .proof_file
        .unwrap_or_else(|| default_proof_path(&parsed.session_file));

    let proof_file = load_proof(&proof_path)?;
    let envelope = proto_from_proof_file(&proof_file)?;

    let mut client = connect(&endpoint).await?;
    let response = client
        .verify_proof(Request::new(VerifyProofRequest {
            proof_envelope: Some(envelope),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("verify proof RPC failed: {e}")))?
        .into_inner();

    let proof = match response.proof.as_ref() {
        Some(proof) => audit_proof_json(proof),
        None => Value::Null,
    };
    let out = json!({
        "valid": response.valid,
        "reason": response.reason.clone(),
        "proof": proof,
    });
    print_json(&out);
    Ok(if response.valid { 0 } else { 1 })
}

async fn cmd_audit(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let parsed = parse_audit_args(args, pre_endpoint)?;
    let session = load_session_optional(&parsed.session_file)?;
    let endpoint = resolve_endpoint(parsed.endpoint, session.as_ref());

    let mut client = connect(&endpoint).await?;
    let response = client
        .read_audit_log(Request::new(ReadAuditLogRequest {}))
        .await
        .map_err(|e| CliError::runtime(format!("read audit log RPC failed: {e}")))?
        .into_inner();

    let limit = parsed.limit.unwrap_or(usize::MAX);
    let entries: Vec<Value> = response
        .entries
        .iter()
        .take(limit)
        .map(|entry| {
            json!({
                "sequence": entry.sequence,
                "timestamp": entry.timestamp,
                "action_id": entry.action_id.clone(),
                "verdict": entry.verdict.clone(),
                "enclave_chain": entry.enclave_chain.clone(),
                "chain_hash": entry.chain_hash.clone(),
                "reason": entry.reason.clone(),
            })
        })
        .collect();

    let verification = match response.verification.as_ref() {
        Some(status) => json!({
            "verified": status.verified,
            "entries_checked": status.entries_checked,
            "first_break_position": status.first_break_position,
            "status_message": status.status_message.clone(),
        }),
        None => Value::Null,
    };

    let out = json!({
        "entries": entries,
        "verification": verification,
    });
    print_json(&out);
    Ok(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SessionFile {
    endpoint: String,
    session_id: String,
    session_key: String,
    signing_seed: String,
    tenant_id: String,
    created_unix: u64,
    ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProofFile {
    payload: String,
    payload_type: String,
    crc32c: String,
    ml_dsa_65_signature: String,
    timestamp: String,
    nonce: String,
}

fn default_session_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".guardian-mesh").join("gm-session.json")
}

fn default_proof_path(session_file: &Path) -> PathBuf {
    match session_file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("gm-proof.json"),
        _ => PathBuf::from("gm-proof.json"),
    }
}

fn resolve_endpoint(flag: Option<String>, session: Option<&SessionFile>) -> String {
    if let Some(endpoint) = flag {
        if !endpoint.is_empty() {
            return endpoint;
        }
    }
    if let Ok(endpoint) = std::env::var("GM_ENDPOINT") {
        if !endpoint.is_empty() {
            return endpoint;
        }
    }
    if let Some(session) = session {
        if !session.endpoint.is_empty() {
            return session.endpoint.clone();
        }
    }
    DEFAULT_ENDPOINT.to_string()
}

async fn connect(
    endpoint: &str,
) -> Result<GuardianMeshClient<tonic::transport::Channel>, CliError> {
    GuardianMeshClient::connect(endpoint.to_string())
        .await
        .map_err(|e| CliError::runtime(format!("connection to {endpoint} failed: {e}")))
}

fn print_json(value: &Value) {
    println!(
        "{}",
        serde_json::to_string(value).expect("JSON serialization cannot fail")
    );
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ensure_session_fresh(session: &SessionFile) -> Result<(), CliError> {
    if session.ttl_seconds == 0 {
        return Ok(());
    }
    let expires = session.created_unix.saturating_add(session.ttl_seconds);
    if now_unix() >= expires {
        return Err(CliError::runtime(format!(
            "session expired at unix {expires} (created {} + ttl {}s); run `gm handshake` again",
            session.created_unix, session.ttl_seconds
        )));
    }
    Ok(())
}

fn build_payload(
    action_type: &str,
    context: &str,
    target: &str,
    metadata: &BTreeMap<String, String>,
) -> Vec<u8> {
    let descriptor = json!({
        "actionType": action_type,
        "context": context,
        "target": target,
        "metadata": metadata,
    });
    serde_json::to_vec(&descriptor).expect("ActionDescriptor payload serializes")
}

fn proto_from_sealed(sealed: &SealedEnvelope) -> ProtoSealedEnvelope {
    ProtoSealedEnvelope {
        payload: sealed.payload.clone(),
        payload_type: sealed.payload_type.clone(),
        crc32c: sealed.crc32c_digest,
        ml_dsa_65_signature: sealed.ml_dsa_65_signature.clone(),
        timestamp: sealed.timestamp,
        nonce: sealed.nonce.to_vec(),
    }
}

fn proof_file_from_proto(envelope: &ProtoSealedEnvelope) -> ProofFile {
    ProofFile {
        payload: hex::encode(&envelope.payload),
        payload_type: hex::encode(&envelope.payload_type),
        crc32c: format!("{:08x}", envelope.crc32c),
        ml_dsa_65_signature: hex::encode(&envelope.ml_dsa_65_signature),
        timestamp: format!("{:016x}", envelope.timestamp),
        nonce: hex::encode(&envelope.nonce),
    }
}

fn proto_from_proof_file(proof: &ProofFile) -> Result<ProtoSealedEnvelope, CliError> {
    Ok(ProtoSealedEnvelope {
        payload: decode_hex_field(&proof.payload, "payload")?,
        payload_type: decode_hex_field(&proof.payload_type, "payload_type")?,
        crc32c: parse_u32_hex_field(&proof.crc32c, "crc32c")?,
        ml_dsa_65_signature: decode_hex_field(&proof.ml_dsa_65_signature, "ml_dsa_65_signature")?,
        timestamp: parse_u64_hex_field(&proof.timestamp, "timestamp")?,
        nonce: decode_hex_field(&proof.nonce, "nonce")?,
    })
}

fn decode_hex_field(value: &str, field: &str) -> Result<Vec<u8>, CliError> {
    hex::decode(value)
        .map_err(|e| CliError::runtime(format!("proof file field {field} is not valid hex: {e}")))
}

fn parse_u32_hex_field(value: &str, field: &str) -> Result<u32, CliError> {
    u32::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|e| {
        CliError::runtime(format!(
            "proof file field {field} is not valid 32-bit hex: {e}"
        ))
    })
}

fn parse_u64_hex_field(value: &str, field: &str) -> Result<u64, CliError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|e| {
        CliError::runtime(format!(
            "proof file field {field} is not valid 64-bit hex: {e}"
        ))
    })
}

fn save_session(path: &Path, session: &SessionFile) -> Result<(), CliError> {
    write_json(path, session, true)
}

fn save_proof(path: &Path, envelope: &ProtoSealedEnvelope) -> Result<(), CliError> {
    let proof = proof_file_from_proto(envelope);
    write_json(path, &proof, false)
}

fn write_json<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                CliError::runtime(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }

    let bytes = serde_json::to_vec_pretty(value).map_err(|e| {
        CliError::runtime(format!("failed to serialize JSON for {}: {e}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|e| CliError::runtime(format!("failed to write {}: {e}", path.display())))?;

    if private {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, permissions).map_err(|e| {
                CliError::runtime(format!(
                    "failed to set 0600 permissions on {}: {e}",
                    path.display()
                ))
            })?;
        }
    }

    Ok(())
}

fn load_required_session(path: &Path) -> Result<SessionFile, CliError> {
    match load_session_optional(path)? {
        Some(session) => Ok(session),
        None => Err(CliError::runtime(format!(
            "session file not found: {}. Run `gm handshake` first to open a session.",
            path.display()
        ))),
    }
}

fn load_session_optional(path: &Path) -> Result<Option<SessionFile>, CliError> {
    match fs::read(path) {
        Ok(bytes) => {
            let session = serde_json::from_slice(&bytes).map_err(|e| {
                CliError::runtime(format!("invalid session file {}: {e}", path.display()))
            })?;
            Ok(Some(session))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::runtime(format!(
            "cannot read session file {}: {e}",
            path.display()
        ))),
    }
}

fn load_proof(path: &Path) -> Result<ProofFile, CliError> {
    let bytes = fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "proof file not found: {}. Run `gm evaluate` first or pass --proof-file.",
                path.display()
            ))
        } else {
            CliError::runtime(format!("cannot read proof file {}: {e}", path.display()))
        }
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| CliError::runtime(format!("invalid proof file {}: {e}", path.display())))
}

fn audit_proof_json(proof: &guardian_meshd::proto::AuditProof) -> Value {
    json!({
        "action_id": proof.action_id.clone(),
        "verdict": proof.verdict.clone(),
        "enclave_chain": proof.enclave_chain.clone(),
        "signature": hex::encode(&proof.signature),
        "timestamp": proof.timestamp,
        "simulation": proof.simulation,
        "rule_ids": proof.rule_ids.clone(),
        "policy_version": proof.policy_version,
        "issuing_node": proof.issuing_node.clone(),
        "merkle_root": hex::encode(&proof.merkle_root),
    })
}

fn global_help() -> String {
    r#"gm: Guardian Mesh operator CLI (WO-18 profile 3 / CC-4)

USAGE:
  gm <subcommand> [options]

SUBCOMMANDS:
  health      Read daemon health and build identity
  handshake   Open a session and write a session file
  evaluate    Evaluate or simulate an action
  verify      Verify a saved proof envelope
  audit       Read and verify the audit log
  doctor      Scan the local configuration environment for insecure settings

GLOBAL OPTIONS:
  --endpoint <url>   Daemon gRPC endpoint (default http://127.0.0.1:50051;
                     GM_ENDPOINT is used when the flag is absent)
  --help             Show help for a subcommand

All daemon subcommands print JSON on stdout; doctor prints plain lines.
Errors go to stderr. Exit codes: 0 success/verdict, 1 invalid proof or
unhealthy daemon, 2 usage/transport/session error or doctor blocking findings."#
        .to_string()
}

fn health_help() -> String {
    r#"gm health: read daemon health

USAGE:
  gm health [--endpoint <url>]

Prints the full HealthResponse as JSON, including status (as its name),
build identity, signing-key fingerprint, node_id, degraded fields and
protocol-firewall counters. Exits 0 for SERVING or DEGRADED, 1 otherwise.

OPTIONS:
  --endpoint <url>   Daemon gRPC endpoint (default http://127.0.0.1:50051;
                     GM_ENDPOINT is used when the flag is absent)
  --help             Show this help"#
        .to_string()
}

fn handshake_help() -> String {
    r#"gm handshake: open a handshake session

USAGE:
  gm handshake [--tenant <id>] [--session-file <path>] [--endpoint <url>]

Generates a 32-byte seed, derives the ML-DSA-65 session keypair, calls
Handshake with source_enclave "gm-cli", and writes a session file. On Unix
the session file is mode 0600. Prints only session_id, ttl_seconds,
tenant_id and the session-file path; the session key and seed are never
printed.

OPTIONS:
  --tenant <id>        Tenant id to request (empty = daemon default)
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json)
  --endpoint <url>     Daemon gRPC endpoint (default http://127.0.0.1:50051;
                       GM_ENDPOINT is used when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn evaluate_help() -> String {
    r#"gm evaluate: evaluate or simulate an action

USAGE:
  gm evaluate --action-type <T> --context <c> --target <t>
              [--metadata k=v]... [--simulate] [--session-file <path>]
              [--proof-out <path>] [--endpoint <url>]

Loads the session file, rebuilds the signing key from its seed, seals the
ActionDescriptor payload, computes the session HMAC and calls Evaluate (or
Simulate with --simulate). Prints verdict, reason, containment_stage,
simulation, reasons and the proof summary as JSON. Saves the returned proof
envelope to the proof file (default: gm-proof.json beside the session file).

Exit 0 for any verdict that arrives in a response, including BLOCK. Exit 2
for usage, session, transport or gRPC errors (including a real Evaluate
block delivered by the daemon as a permission-denied RPC error); use
--simulate to receive such blocks as a verdict in JSON.

OPTIONS:
  --action-type <T>    Action type (e.g. TOOL_CALL)
  --context <c>        Action context
  --target <t>         Action target
  --metadata k=v       Metadata entry; repeatable, exactly one '=' per value
  --simulate           Call Simulate instead of Evaluate (dry run)
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json)
  --proof-out <p>      Proof file path (default gm-proof.json beside the session file)
  --endpoint <url>     Daemon gRPC endpoint (default from session file, then
                       http://127.0.0.1:50051; GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn verify_help() -> String {
    r#"gm verify: verify a saved proof envelope

USAGE:
  gm verify [--proof-file <path>] [--session-file <path>] [--endpoint <url>]

Loads a proof file, rebuilds the proto envelope and calls VerifyProof.
Prints valid, reason and proof as JSON. Exits 0 iff the daemon reports
the proof valid, 1 iff it reports invalid, 2 on usage/transport errors.

OPTIONS:
  --proof-file <p>     Proof file path (default gm-proof.json beside the session file)
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json;
                       used for its endpoint, or pass --endpoint)
  --endpoint <url>     Daemon gRPC endpoint (default from session file, then
                       http://127.0.0.1:50051; GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn audit_help() -> String {
    r#"gm audit: read and verify the audit log

USAGE:
  gm audit [--limit <n>] [--session-file <path>] [--endpoint <url>]

Calls ReadAuditLog and prints entries plus chain verification status as
JSON. --limit truncates the PRINTED entries client-side after the daemon
has returned and verified the full log; it does not ask the daemon to
limit the audit read.

OPTIONS:
  --limit <n>          Print at most n entries (client-side truncation)
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json;
                       used for its endpoint, or pass --endpoint)
  --endpoint <url>     Daemon gRPC endpoint (default from session file, then
                       http://127.0.0.1:50051; GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn doctor_help() -> String {
    r#"gm doctor: scan the local configuration environment

USAGE:
  gm doctor [--endpoint <url>]

Reads the local environment only and contacts no daemon. Builds the same
configuration the daemon reads at startup and prints:
  posture: production|demo
  BLOCKING <setting>: <message>   (blocks daemon startup)
  warning <setting>: <message>    (insecure or notable, does not block)
  doctor: FAIL — N blocking finding(s)
  doctor: OK — no blocking findings (M warning(s))

In production posture (the default) the built-in default handshake secret is
a blocking finding: the daemon refuses to start with it. Demo posture permits
the default secret for local demonstration only, and the doctor still names it.

Exit codes: 0 when there are no blocking findings, 2 when any blocking finding
is present (a normal result, not a usage error).

OPTIONS:
  --endpoint <url>   Accepted and ignored; doctor contacts no daemon
  --help             Show this help"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::new();
        metadata.insert("b".to_string(), "2".to_string());
        metadata.insert("a".to_string(), "1".to_string());
        metadata
    }

    #[test]
    fn payload_has_exact_field_set_and_metadata_map() {
        let payload = build_payload("TOOL_CALL", "ctx", "target", &sample_metadata());
        let value: Value = serde_json::from_slice(&payload).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(object.len(), 4);
        for field in ["actionType", "context", "target", "metadata"] {
            assert!(object.contains_key(field), "missing field {field}");
        }
        assert_eq!(value["actionType"], json!("TOOL_CALL"));
        assert_eq!(value["context"], json!("ctx"));
        assert_eq!(value["target"], json!("target"));
        assert_eq!(value["metadata"], json!({"a": "1", "b": "2"}));
    }

    #[test]
    fn session_file_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gm-session.json");
        let session = SessionFile {
            endpoint: "http://127.0.0.1:50051".to_string(),
            session_id: "session-123".to_string(),
            session_key: "00112233445566778899aabbccddeeff".to_string(),
            signing_seed: "ffeeddccbbaa99887766554433221100".to_string(),
            tenant_id: "default".to_string(),
            created_unix: 1_700_000_000,
            ttl_seconds: 300,
        };

        save_session(&path, &session).unwrap();
        let loaded = load_session_optional(&path).unwrap().unwrap();
        assert_eq!(loaded, session);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn proof_file_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gm-proof.json");
        let envelope = ProtoSealedEnvelope {
            payload: b"payload bytes".to_vec(),
            payload_type: b"guardian_mesh.AuditProof".to_vec(),
            crc32c: 0xdead_beef,
            ml_dsa_65_signature: vec![1, 2, 3, 4, 5],
            timestamp: 0x0123_4567_89ab_cdef,
            nonce: (0u8..32).collect(),
        };

        save_proof(&path, &envelope).unwrap();
        let loaded = load_proof(&path).unwrap();
        assert_eq!(loaded.crc32c, "deadbeef");
        assert_eq!(loaded.timestamp, "0123456789abcdef");

        let rebuilt = proto_from_proof_file(&loaded).unwrap();
        assert_eq!(rebuilt, envelope);
    }

    #[test]
    fn evaluate_rejects_missing_required_flag() {
        let args = vec!["--action-type".to_string(), "TOOL_CALL".to_string()];
        let error = parse_evaluate_args(&args, None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(error, CliError::Usage(_)));
    }

    #[test]
    fn evaluate_rejects_bad_metadata_form() {
        let args = [
            "--action-type",
            "TOOL_CALL",
            "--context",
            "ctx",
            "--target",
            "target",
            "--metadata",
            "novalue",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();

        let error = parse_evaluate_args(&args, None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(error, CliError::Usage(_)));
    }

    #[test]
    fn evaluate_rejects_unknown_flag() {
        let args = ["--nope".to_string()];
        let error = parse_evaluate_args(&args, None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(error, CliError::Usage(_)));
    }
}
