// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

// gm-mcp - Guardian Mesh stdio MCP server (WO-18 profile 4 / CC-5).
//
// This is an ordinary client of the running daemon: it exposes the four MCP
// tools over the stdio JSON-RPC transport, opens a handshake session lazily,
// seals an ActionDescriptor, calls Evaluate/Simulate, verifies saved proofs and
// reads the audit log. It holds no policy authority.
//
// What this is NOT: it is not a new verdict capability, it does not cluster,
// it is not TEE attestation, it does not anchor proofs externally, and it is
// NOT forced routing (CM-4). An agent framework must choose to call the tools.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use guardian_meshd::proto::guardian_mesh_client::GuardianMeshClient;
use guardian_meshd::proto::{
    ActionDescriptor, AuditProof, EvaluateRequest, EvaluateResponse, FirewalledRequest,
    HandshakeRequest, HealthRequest, ReadAuditLogRequest, SealedEnvelope as ProtoSealedEnvelope,
    VerifyProofRequest,
};
use guardian_meshd::sealed_envelope::SealedEnvelope;
use hmac::{Hmac, KeyInit, Mac};
use ml_dsa::{Keypair, MlDsa65, SigningKey};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:50051";
const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("gm-mcp: failed to start tokio runtime: {error}");
            std::process::exit(1);
        }
    };
    let config = Config::from_env();
    let mut session: Option<Session> = None;

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                eprintln!("gm-mcp: stdin read error: {error}");
                break;
            }
        }

        let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r');
        if trimmed.trim().is_empty() {
            continue;
        }

        if let Some(response) = handle_line(trimmed, &runtime, &config, &mut session) {
            match serde_json::to_string(&response) {
                Ok(text) => {
                    if writeln!(writer, "{text}").is_err() {
                        break;
                    }
                    if writer.flush().is_err() {
                        break;
                    }
                }
                Err(error) => eprintln!("gm-mcp: failed to serialize response: {error}"),
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    endpoint: String,
    tenant: String,
}

impl Config {
    fn from_env() -> Self {
        let endpoint = std::env::var("GM_ENDPOINT")
            .ok()
            .filter(|endpoint| !endpoint.is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let tenant = std::env::var("GM_TENANT").unwrap_or_default();
        Self { endpoint, tenant }
    }
}

#[derive(Debug, Clone)]
struct Session {
    session_id: String,
    session_key: Vec<u8>,
    signing_seed: [u8; 32],
    created_unix: u64,
    ttl_seconds: u64,
}

#[derive(Debug, PartialEq)]
enum Classified {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    Invalid {
        id: Value,
        reason: String,
    },
}

fn classify_request(message: &Value) -> Classified {
    let Some(object) = message.as_object() else {
        return Classified::Invalid {
            id: Value::Null,
            reason: "request must be a JSON object".to_string(),
        };
    };

    let id = object.get("id").cloned();
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string);
    let params = object.get("params").cloned().unwrap_or(Value::Null);

    match (id, method) {
        (Some(id), Some(method)) => Classified::Request {
            id,
            method,
            params,
        },
        (None, Some(method)) => Classified::Notification { method, params },
        (Some(id), None) => Classified::Invalid {
            id,
            reason: "missing method".to_string(),
        },
        (None, None) => Classified::Notification {
            method: String::new(),
            params,
        },
    }
}

fn handle_line(
    line: &str,
    runtime: &tokio::runtime::Runtime,
    config: &Config,
    session: &mut Option<Session>,
) -> Option<Value> {
    let message: Value = match serde_json::from_str(line) {
        Ok(message) => message,
        Err(_) => return Some(error_response(Value::Null, -32700, "Parse error")),
    };

    match classify_request(&message) {
        Classified::Notification { .. } => None,
        Classified::Invalid { id, reason } => Some(error_response(id, -32600, &reason)),
        Classified::Request {
            id,
            method,
            params,
        } => Some(dispatch(id, &method, &params, runtime, config, session)),
    }
}

fn dispatch(
    id: Value,
    method: &str,
    params: &Value,
    runtime: &tokio::runtime::Runtime,
    config: &Config,
    session: &mut Option<Session>,
) -> Value {
    match method {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(Value::as_str);
            let negotiated = negotiate_protocol(requested);
            success_response(
                id,
                json!({
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "guardian-mesh",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }),
            )
        }
        "ping" => success_response(id, json!({})),
        "tools/list" => success_response(id, json!({"tools": tool_definitions()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let result = runtime.block_on(call_tool(name, &arguments, config, session));
            success_response(id, result)
        }
        other => error_response(id, -32601, &format!("Method not found: {other}")),
    }
}

fn negotiate_protocol(requested: Option<&str>) -> &'static str {
    match requested {
        Some(version) => SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .copied()
            .find(|supported| *supported == version)
            .unwrap_or(DEFAULT_PROTOCOL_VERSION),
        None => DEFAULT_PROTOCOL_VERSION,
    }
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "guardian_health",
            "description": "Read the Guardian Mesh daemon health response: status, build identity, node id, degraded fields, enclave health and protocol-firewall counters.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        {
            "name": "guardian_evaluate",
            "description": "Evaluate or simulate an action through the Guardian Mesh daemon. Returns the verdict and a proof envelope that can be passed to guardian_verify. On any daemon or transport failure no verdict is issued and the caller MUST treat the action as BLOCK.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action_type": {"type": "string", "description": "Action type, for example TOOL_CALL"},
                    "context": {"type": "string", "description": "Action context"},
                    "target": {"type": "string", "description": "Action target"},
                    "metadata": {
                        "type": "object",
                        "description": "Optional string-to-string metadata",
                        "additionalProperties": {"type": "string"},
                    },
                    "simulate": {"type": "boolean", "description": "Call Simulate instead of Evaluate", "default": false},
                },
                "required": ["action_type", "context", "target"],
            },
        },
        {
            "name": "guardian_verify",
            "description": "Verify a proof envelope previously returned by guardian_evaluate.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "proof": {
                        "type": "object",
                        "description": "Proof envelope in the guardian-mesh proof-file JSON shape (all hex fields)",
                        "properties": {
                            "payload": {"type": "string"},
                            "payload_type": {"type": "string"},
                            "crc32c": {"type": "string"},
                            "ml_dsa_65_signature": {"type": "string"},
                            "timestamp": {"type": "string"},
                            "nonce": {"type": "string"},
                        },
                        "required": ["payload", "payload_type", "crc32c", "ml_dsa_65_signature", "timestamp", "nonce"],
                    },
                },
                "required": ["proof"],
            },
        },
        {
            "name": "guardian_audit",
            "description": "Read the Guardian Mesh audit log and its chain verification status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 0, "description": "Print at most this many entries (client-side truncation)"},
                },
                "required": [],
            },
        },
    ])
}

#[derive(Debug)]
struct EvaluateInput {
    action_type: String,
    context: String,
    target: String,
    metadata: BTreeMap<String, String>,
    simulate: bool,
}

enum ToolCall {
    Health,
    Evaluate(EvaluateInput),
    Verify(ProtoSealedEnvelope),
    Audit { limit: Option<usize> },
}

fn validate_tool_call(name: &str, arguments: &Value) -> Result<ToolCall, String> {
    let object = match arguments {
        Value::Object(object) => object,
        _ => return Err("arguments must be an object".to_string()),
    };

    match name {
        "guardian_health" => Ok(ToolCall::Health),
        "guardian_evaluate" => {
            let action_type = required_string(object, "action_type")?;
            let context = required_string(object, "context")?;
            let target = required_string(object, "target")?;
            let metadata = optional_metadata(object)?;
            let simulate = optional_bool(object, "simulate")?.unwrap_or(false);
            Ok(ToolCall::Evaluate(EvaluateInput {
                action_type,
                context,
                target,
                metadata,
                simulate,
            }))
        }
        "guardian_verify" => match object.get("proof") {
            Some(proof) => Ok(ToolCall::Verify(proto_from_proof_value(proof)?)),
            None => Err("missing required field: proof".to_string()),
        },
        "guardian_audit" => Ok(ToolCall::Audit {
            limit: optional_limit(object)?,
        }),
        other => Err(format!("unknown tool: {other}")),
    }
}

fn string_field<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(value.as_str()),
        Some(_) => Err(format!("field {field} must be a string")),
        None => Err(format!("missing required field: {field}")),
    }
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, String> {
    string_field(object, field).map(str::to_string)
}

fn optional_metadata(object: &Map<String, Value>) -> Result<BTreeMap<String, String>, String> {
    let mut metadata = BTreeMap::new();
    match object.get("metadata") {
        None => {}
        Some(Value::Object(map)) => {
            for (key, value) in map {
                match value {
                    Value::String(value) => {
                        metadata.insert(key.clone(), value.clone());
                    }
                    _ => return Err(format!("field metadata.{key} must be a string")),
                }
            }
        }
        Some(_) => return Err("field metadata must be an object of string values".to_string()),
    }
    Ok(metadata)
}

fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>, String> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!("field {field} must be a boolean")),
    }
}

fn optional_limit(object: &Map<String, Value>) -> Result<Option<usize>, String> {
    match object.get("limit") {
        None => Ok(None),
        Some(Value::Number(number)) => {
            let raw = number
                .as_u64()
                .ok_or_else(|| "field limit must be a non-negative integer".to_string())?;
            let limit =
                usize::try_from(raw).map_err(|_| "field limit is too large".to_string())?;
            Ok(Some(limit))
        }
        Some(_) => Err("field limit must be a non-negative integer".to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProofFile {
    payload: String,
    payload_type: String,
    crc32c: String,
    ml_dsa_65_signature: String,
    timestamp: String,
    nonce: String,
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

fn proto_from_proof_value(value: &Value) -> Result<ProtoSealedEnvelope, String> {
    let object = match value {
        Value::Object(object) => object,
        _ => return Err("field proof must be an object".to_string()),
    };

    Ok(ProtoSealedEnvelope {
        payload: decode_hex_field(string_field(object, "payload")?, "payload")?,
        payload_type: decode_hex_field(string_field(object, "payload_type")?, "payload_type")?,
        crc32c: parse_u32_hex_field(string_field(object, "crc32c")?, "crc32c")?,
        ml_dsa_65_signature: decode_hex_field(
            string_field(object, "ml_dsa_65_signature")?,
            "ml_dsa_65_signature",
        )?,
        timestamp: parse_u64_hex_field(string_field(object, "timestamp")?, "timestamp")?,
        nonce: decode_hex_field(string_field(object, "nonce")?, "nonce")?,
    })
}

fn decode_hex_field(value: &str, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| format!("proof field {field} is not valid hex: {error}"))
}

fn parse_u32_hex_field(value: &str, field: &str) -> Result<u32, String> {
    u32::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|error| {
        format!("proof field {field} is not valid 32-bit hex: {error}")
    })
}

fn parse_u64_hex_field(value: &str, field: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|error| {
        format!("proof field {field} is not valid 64-bit hex: {error}")
    })
}

fn tool_ok(payload: Value) -> Value {
    tool_result(payload, false)
}

fn tool_error(payload: Value) -> Value {
    tool_result(payload, true)
}

fn tool_result(payload: Value, is_error: bool) -> Value {
    let text =
        serde_json::to_string(&payload).unwrap_or_else(|_| "{\"error\":\"serialization failed\"}".to_string());
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    })
}

async fn call_tool(
    name: &str,
    arguments: &Value,
    config: &Config,
    session: &mut Option<Session>,
) -> Value {
    let call = match validate_tool_call(name, arguments) {
        Ok(call) => call,
        Err(message) => return tool_error(json!({"error": message})),
    };

    match call {
        ToolCall::Health => match do_health(config).await {
            Ok(payload) => tool_ok(payload),
            Err(message) => tool_error(json!({"error": message})),
        },
        ToolCall::Evaluate(input) => match do_evaluate(config, &input, session).await {
            Ok(payload) => tool_ok(payload),
            Err(message) => tool_error(json!({
                "error": format!(
                    "{message}; NO verdict was issued and the caller MUST treat the action as BLOCK"
                ),
                "fail_closed": true,
                "must_treat_as": "BLOCK",
            })),
        },
        ToolCall::Verify(envelope) => match do_verify(config, &envelope).await {
            Ok(payload) => tool_ok(payload),
            Err(message) => tool_error(json!({"error": message})),
        },
        ToolCall::Audit { limit } => match do_audit(config, limit).await {
            Ok(payload) => tool_ok(payload),
            Err(message) => tool_error(json!({"error": message})),
        },
    }
}

async fn connect(endpoint: &str) -> Result<GuardianMeshClient<Channel>, String> {
    GuardianMeshClient::connect(endpoint.to_string())
        .await
        .map_err(|error| format!("connection to {endpoint} failed: {error}"))
}

async fn do_health(config: &Config) -> Result<Value, String> {
    let mut client = connect(&config.endpoint).await?;
    let health = client
        .health(Request::new(HealthRequest {}))
        .await
        .map_err(|error| format!("health RPC failed: {error}"))?
        .into_inner();

    let status_name = match health.status {
        0 => "UNKNOWN",
        1 => "SERVING",
        2 => "NOT_SERVING",
        3 => "DEGRADED",
        _ => "UNRECOGNIZED",
    };

    Ok(json!({
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
    }))
}

async fn do_evaluate(
    config: &Config,
    input: &EvaluateInput,
    session: &mut Option<Session>,
) -> Result<Value, String> {
    let mut client = connect(&config.endpoint).await?;
    ensure_session(&mut client, config, session).await?;

    let mut current = session
        .as_ref()
        .cloned()
        .ok_or_else(|| "session was not established".to_string())?;
    let mut result = send_evaluate(&mut client, input, &current).await;

    if let Err(status) = &result {
        if is_session_error(status) {
            current = handshake(&mut client, &config.tenant).await?;
            *session = Some(current.clone());
            result = send_evaluate(&mut client, input, &current).await;
        }
    }

    let response = result.map_err(|status| {
        format!(
            "{} RPC failed: {status}",
            if input.simulate { "simulate" } else { "evaluate" }
        )
    })?;

    let proof_envelope = response
        .proof_envelope
        .as_ref()
        .ok_or_else(|| "evaluate response did not include a proof envelope".to_string())?;

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
    let proof_envelope_json =
        serde_json::to_value(proof_file_from_proto(proof_envelope)).unwrap_or(Value::Null);

    Ok(json!({
        "verdict": response.verdict.clone(),
        "reason": response.reason.clone(),
        "containment_stage": response.containment_stage.clone(),
        "simulation": response.simulation,
        "reasons": reasons,
        "proof": proof,
        "proof_envelope": proof_envelope_json,
    }))
}

async fn do_verify(config: &Config, envelope: &ProtoSealedEnvelope) -> Result<Value, String> {
    let mut client = connect(&config.endpoint).await?;
    let response = client
        .verify_proof(Request::new(VerifyProofRequest {
            proof_envelope: Some(envelope.clone()),
        }))
        .await
        .map_err(|error| format!("verify proof RPC failed: {error}"))?
        .into_inner();

    let proof = match response.proof.as_ref() {
        Some(proof) => audit_proof_json(proof),
        None => Value::Null,
    };

    Ok(json!({
        "valid": response.valid,
        "reason": response.reason.clone(),
        "proof": proof,
    }))
}

async fn do_audit(config: &Config, limit: Option<usize>) -> Result<Value, String> {
    let mut client = connect(&config.endpoint).await?;
    let response = client
        .read_audit_log(Request::new(ReadAuditLogRequest {}))
        .await
        .map_err(|error| format!("read audit log RPC failed: {error}"))?
        .into_inner();

    let limit = limit.unwrap_or(usize::MAX);
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

    Ok(json!({
        "entries": entries,
        "verification": verification,
    }))
}

async fn ensure_session(
    client: &mut GuardianMeshClient<Channel>,
    config: &Config,
    session: &mut Option<Session>,
) -> Result<(), String> {
    let needs_handshake = match session.as_ref() {
        None => true,
        Some(session) => session_expired(session),
    };

    if needs_handshake {
        *session = Some(handshake(client, &config.tenant).await?);
    }

    Ok(())
}

async fn handshake(
    client: &mut GuardianMeshClient<Channel>,
    tenant: &str,
) -> Result<Session, String> {
    let mut seed_bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut seed_bytes)
        .map_err(|_| "failed to generate session seed".to_string())?;
    let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice())
        .map_err(|_| "generated seed was not 32 bytes".to_string())?;
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
    let verifying_key = signing_key.verifying_key();
    let encoded_verifying_key = verifying_key.encode();
    let encoded_bytes: &[u8] = encoded_verifying_key.as_ref();
    let verifying_key_bytes: Vec<u8> = encoded_bytes.to_vec();

    let response = client
        .handshake(Request::new(HandshakeRequest {
            source_enclave: "gm-mcp".to_string(),
            source_public_key: verifying_key_bytes,
            spiffe_id: String::new(),
            svid_leaf_der: Vec::new(),
            svid_signature: Vec::new(),
            tenant_id: tenant.to_string(),
        }))
        .await
        .map_err(|error| format!("handshake RPC failed: {error}"))?
        .into_inner();

    Ok(Session {
        session_id: response.session_id,
        session_key: response.session_key,
        signing_seed: seed_bytes,
        created_unix: now_unix(),
        ttl_seconds: response.ttl_seconds,
    })
}

async fn send_evaluate(
    client: &mut GuardianMeshClient<Channel>,
    input: &EvaluateInput,
    session: &Session,
) -> Result<EvaluateResponse, Status> {
    let request = build_evaluate_request(input, session).map_err(|error| Status::internal(error))?;

    if input.simulate {
        client
            .simulate(Request::new(request))
            .await
            .map(|response| response.into_inner())
    } else {
        client
            .evaluate(Request::new(request))
            .await
            .map(|response| response.into_inner())
    }
}

fn build_evaluate_request(
    input: &EvaluateInput,
    session: &Session,
) -> Result<EvaluateRequest, String> {
    let seed = ml_dsa::Seed::try_from(session.signing_seed.as_slice())
        .map_err(|_| "session signing seed is not 32 bytes".to_string())?;
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);

    let payload = build_payload(
        &input.action_type,
        &input.context,
        &input.target,
        &input.metadata,
    );
    let sealed = SealedEnvelope::new(
        payload.clone(),
        b"guardian_mesh.ActionDescriptor".to_vec(),
        &signing_key,
    );
    let envelope = proto_from_sealed(&sealed);

    let mut mac = HmacSha256::new_from_slice(&session.session_key)
        .map_err(|error| format!("failed to initialise HMAC: {error}"))?;
    mac.update(&payload);
    let hmac_tag = mac.finalize().into_bytes().to_vec();

    Ok(EvaluateRequest {
        firewalled: Some(FirewalledRequest {
            envelope: Some(envelope),
            source_enclave: "gm-mcp".to_string(),
            handshake_session: session.session_id.clone(),
            hmac_tag,
        }),
        action: Some(ActionDescriptor {
            action_type: input.action_type.clone(),
            context: input.context.clone(),
            target: input.target.clone(),
            metadata: input
                .metadata
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }),
    })
}

fn is_session_error(status: &Status) -> bool {
    matches!(
        status.code(),
        Code::Unauthenticated | Code::PermissionDenied
    ) && status.message().to_ascii_lowercase().contains("session")
}

fn session_expired(session: &Session) -> bool {
    if session.ttl_seconds == 0 {
        return false;
    }
    let expires = session.created_unix.saturating_add(session.ttl_seconds);
    now_unix() >= expires
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

fn audit_proof_json(proof: &AuditProof) -> Value {
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            tenant: String::new(),
        }
    }

    fn handle(line: &str) -> Value {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut session = None;
        handle_line(line, &runtime, &test_config(), &mut session).expect("expected a response")
    }

    #[test]
    fn initialize_echoes_supported_protocol_version() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        );
        assert_eq!(response["result"]["protocolVersion"], json!("2025-06-18"));
        assert_eq!(
            response["result"]["serverInfo"]["name"],
            json!("guardian-mesh")
        );
        assert_eq!(
            response["result"]["serverInfo"]["version"],
            json!(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(response["result"]["capabilities"], json!({"tools": {}}));
    }

    #[test]
    fn initialize_falls_back_for_unsupported_version() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
        );
        assert_eq!(response["result"]["protocolVersion"], json!("2024-11-05"));
    }

    #[test]
    fn tools_list_returns_exactly_four_tools_with_schemas() {
        let response = handle(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let tools = response["result"]["tools"]
            .as_array()
            .expect("tools should be an array");
        let mut names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "guardian_audit",
                "guardian_evaluate",
                "guardian_health",
                "guardian_verify"
            ]
        );

        for tool in tools {
            let schema = &tool["inputSchema"];
            assert_eq!(schema["type"], json!("object"));
            assert!(
                schema["properties"].is_object(),
                "missing properties for {}",
                tool["name"]
            );
            assert!(
                schema["required"].is_array(),
                "missing required for {}",
                tool["name"]
            );
        }
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let response = handle(r#"{"jsonrpc":"2.0","id":9,"method":"no/such/method"}"#);
        assert_eq!(response["error"]["code"], json!(-32601));
    }

    #[test]
    fn malformed_line_returns_parse_error_and_server_continues() {
        let response = handle("{not json");
        assert_eq!(response["error"]["code"], json!(-32700));
        assert!(response["id"].is_null());

        let response = handle(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#);
        assert_eq!(response["result"], json!({}));
    }

    #[test]
    fn missing_method_returns_invalid_request() {
        let response = handle(r#"{"jsonrpc":"2.0","id":4}"#);
        assert_eq!(response["error"]["code"], json!(-32600));
    }

    #[test]
    fn notification_gets_no_response() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut session = None;
        let response = handle_line(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &runtime,
            &test_config(),
            &mut session,
        );
        assert!(response.is_none());
    }

    #[test]
    fn evaluate_missing_action_type_is_tool_error_naming_field() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"guardian_evaluate","arguments":{"context":"chat","target":"shell"}}}"#,
        );
        let result = &response["result"];
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("action_type"), "text was {text}");
    }

    #[test]
    fn verify_bad_hex_is_tool_error_naming_field() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"guardian_verify","arguments":{"proof":{"payload":"zz","payload_type":"00","crc32c":"00000000","ml_dsa_65_signature":"00","timestamp":"0000000000000000","nonce":"00"}}}}"#,
        );
        let result = &response["result"];
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("payload"), "text was {text}");
    }

    #[test]
    fn unknown_tool_is_tool_error_naming_tool() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"guardian_nope","arguments":{}}}"#,
        );
        let result = &response["result"];
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("guardian_nope"), "text was {text}");
    }

    #[test]
    fn proof_file_shape_round_trip() {
        let envelope = ProtoSealedEnvelope {
            payload: b"payload bytes".to_vec(),
            payload_type: b"guardian_mesh.ActionDescriptor".to_vec(),
            crc32c: 0xdead_beef,
            ml_dsa_65_signature: vec![1, 2, 3, 4, 5],
            timestamp: 0x0123_4567_89ab_cdef,
            nonce: (0u8..32).collect(),
        };

        let value = serde_json::to_value(proof_file_from_proto(&envelope)).unwrap();
        assert_eq!(value["crc32c"], json!("deadbeef"));
        assert_eq!(value["timestamp"], json!("0123456789abcdef"));

        let rebuilt = proto_from_proof_value(&value).unwrap();
        assert_eq!(rebuilt, envelope);
    }
}
