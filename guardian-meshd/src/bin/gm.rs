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
    ActionDescriptor, CertificateStatusRequest, EvaluateRequest, FirewalledRequest,
    HandshakeRequest, HealthRequest, IssueCertificateRequest, ReadAuditLogRequest,
    RevokeCertificateRequest, SealedEnvelope as ProtoSealedEnvelope, TestCounts,
    VerifyProofRequest,
};
use guardian_meshd::sealed_envelope::SealedEnvelope;
use hmac::{Hmac, KeyInit, Mac};
use ml_dsa::{Keypair, MlDsa65, SigningKey};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
        "certificate" => cmd_certificate(rest, pre_endpoint).await,
        "publish" => cmd_publish(rest, pre_endpoint).await,
        "conduit" => cmd_conduit(rest, pre_endpoint).await,
        "repo" => cmd_repo(rest, pre_endpoint).await,
        "nightly" => cmd_nightly(rest, pre_endpoint).await,
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

#[derive(Debug)]
enum CertificateAction {
    Issue(CertificateIssueArgs),
    Status(CertificateStatusArgs),
    Verify(CertificateVerifyArgs),
    Revoke(CertificateRevokeArgs),
}

#[derive(Debug)]
struct CertificateIssueArgs {
    product: String,
    version: String,
    verdict: String,
    evidence_file: PathBuf,
    evidence_scope: String,
    tests_passed: u32,
    tests_failed: u32,
    policy: String,
    cert_out: PathBuf,
    endpoint: Option<String>,
}

#[derive(Debug)]
struct CertificateStatusArgs {
    serial: String,
    endpoint: Option<String>,
}

#[derive(Debug)]
struct CertificateVerifyArgs {
    cert_file: PathBuf,
    endpoint: Option<String>,
}

#[derive(Debug)]
struct CertificateRevokeArgs {
    serial: String,
    reason: String,
    endpoint: Option<String>,
}

fn parse_certificate_action(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<CertificateAction, CliError> {
    let action = match args.first() {
        Some(action) => action.as_str(),
        None => {
            return Err(CliError::usage(
                "certificate requires an action: issue, status, verify or revoke",
            ))
        }
    };
    let rest = &args[1..];
    match action {
        "issue" => Ok(CertificateAction::Issue(parse_certificate_issue_args(
            rest,
            pre_endpoint,
        )?)),
        "status" => Ok(CertificateAction::Status(parse_certificate_status_args(
            rest,
            pre_endpoint,
        )?)),
        "verify" => Ok(CertificateAction::Verify(parse_certificate_verify_args(
            rest,
            pre_endpoint,
        )?)),
        "revoke" => Ok(CertificateAction::Revoke(parse_certificate_revoke_args(
            rest,
            pre_endpoint,
        )?)),
        "--help" | "-h" => Err(CliError::help(print_certificate_usage())),
        other => Err(CliError::usage(format!(
            "unknown certificate action: {other} (expected issue, status, verify or revoke)"
        ))),
    }
}

fn parse_certificate_issue_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<CertificateIssueArgs, CliError> {
    let mut product = None;
    let mut version = None;
    let mut verdict = None;
    let mut evidence_file = None;
    let mut evidence_scope = None;
    let mut tests_passed = None;
    let mut tests_failed = None;
    let mut policy = None;
    let mut cert_out = PathBuf::from("gm-certificate.json");
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--product" => product = Some(next_value(args, &mut i, "--product")?),
            "--version" => version = Some(next_value(args, &mut i, "--version")?),
            "--verdict" => verdict = Some(next_value(args, &mut i, "--verdict")?),
            "--evidence-file" => {
                evidence_file = Some(PathBuf::from(next_value(args, &mut i, "--evidence-file")?))
            }
            "--evidence-scope" => {
                evidence_scope = Some(next_value(args, &mut i, "--evidence-scope")?)
            }
            "--tests-passed" => {
                let raw = next_value(args, &mut i, "--tests-passed")?;
                tests_passed = Some(raw.parse::<u32>().map_err(|_| {
                    CliError::usage(format!(
                        "--tests-passed must be a non-negative integer, got '{raw}'"
                    ))
                })?);
            }
            "--tests-failed" => {
                let raw = next_value(args, &mut i, "--tests-failed")?;
                tests_failed = Some(raw.parse::<u32>().map_err(|_| {
                    CliError::usage(format!(
                        "--tests-failed must be a non-negative integer, got '{raw}'"
                    ))
                })?);
            }
            "--policy" => policy = Some(next_value(args, &mut i, "--policy")?),
            "--cert-out" => {
                cert_out = PathBuf::from(next_value(args, &mut i, "--cert-out")?)
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(print_certificate_usage())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }

    Ok(CertificateIssueArgs {
        product: product.ok_or_else(|| CliError::usage("--product is required"))?,
        version: version.ok_or_else(|| CliError::usage("--version is required"))?,
        verdict: verdict.ok_or_else(|| CliError::usage("--verdict is required"))?,
        evidence_file: evidence_file
            .ok_or_else(|| CliError::usage("--evidence-file is required"))?,
        evidence_scope: evidence_scope
            .ok_or_else(|| CliError::usage("--evidence-scope is required"))?,
        tests_passed: tests_passed
            .ok_or_else(|| CliError::usage("--tests-passed is required"))?,
        tests_failed: tests_failed
            .ok_or_else(|| CliError::usage("--tests-failed is required"))?,
        policy: policy.ok_or_else(|| CliError::usage("--policy is required"))?,
        cert_out,
        endpoint,
    })
}

fn parse_certificate_status_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<CertificateStatusArgs, CliError> {
    let mut serial = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--serial" => serial = Some(next_value(args, &mut i, "--serial")?),
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(print_certificate_usage())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(CertificateStatusArgs {
        serial: serial.ok_or_else(|| CliError::usage("--serial is required"))?,
        endpoint,
    })
}

fn parse_certificate_verify_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<CertificateVerifyArgs, CliError> {
    let mut cert_file = PathBuf::from("gm-certificate.json");
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cert-file" => {
                cert_file = PathBuf::from(next_value(args, &mut i, "--cert-file")?)
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(print_certificate_usage())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(CertificateVerifyArgs {
        cert_file,
        endpoint,
    })
}

fn parse_certificate_revoke_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<CertificateRevokeArgs, CliError> {
    let mut serial = None;
    let mut reason = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--serial" => serial = Some(next_value(args, &mut i, "--serial")?),
            "--reason" => reason = Some(next_value(args, &mut i, "--reason")?),
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(print_certificate_usage())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(CertificateRevokeArgs {
        serial: serial.ok_or_else(|| CliError::usage("--serial is required"))?,
        reason: reason.ok_or_else(|| CliError::usage("--reason is required"))?,
        endpoint,
    })
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

async fn cmd_certificate(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<i32, CliError> {
    let action = match parse_certificate_action(args, pre_endpoint) {
        Ok(action) => action,
        Err(CliError::Usage(message)) => {
            return Err(CliError::usage(format!(
                "{message}\n\n{}",
                print_certificate_usage()
            )))
        }
        Err(error) => return Err(error),
    };
    match action {
        CertificateAction::Issue(parsed) => cmd_certificate_issue(parsed).await,
        CertificateAction::Status(parsed) => cmd_certificate_status(parsed).await,
        CertificateAction::Verify(parsed) => cmd_certificate_verify(parsed).await,
        CertificateAction::Revoke(parsed) => cmd_certificate_revoke(parsed).await,
    }
}

async fn cmd_certificate_issue(parsed: CertificateIssueArgs) -> Result<i32, CliError> {
    let evidence = fs::read(&parsed.evidence_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "evidence file not found: {}",
                parsed.evidence_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read evidence file {}: {e}",
                parsed.evidence_file.display()
            ))
        }
    })?;
    let evidence_hash = sha256_hex(&evidence);
    let total = parsed
        .tests_passed
        .checked_add(parsed.tests_failed)
        .ok_or_else(|| CliError::runtime("test counts overflow u32"))?;
    let endpoint = resolve_endpoint(parsed.endpoint.clone(), None);
    let mut client = connect(&endpoint).await?;

    let response = client
        .issue_certificate(Request::new(IssueCertificateRequest {
            product: parsed.product.clone(),
            version: parsed.version.clone(),
            verdict: parsed.verdict.clone(),
            evidence,
            evidence_hash: evidence_hash.clone(),
            evidence_scope: parsed.evidence_scope.clone(),
            tests: Some(TestCounts {
                passed: parsed.tests_passed,
                failed: parsed.tests_failed,
                total,
            }),
            policy: parsed.policy.clone(),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("issue certificate RPC failed: {e}")))?
        .into_inner();

    if response.issued {
        let certificate = response.certificate.as_ref().ok_or_else(|| {
            CliError::runtime("issue certificate response did not include a certificate envelope")
        })?;
        save_proof(&parsed.cert_out, certificate)?;
        let out = json!({
            "issued": true,
            "serial": response.serial.clone(),
            "fingerprint": response.fingerprint.clone(),
            "product": parsed.product.clone(),
            "version": parsed.version.clone(),
            "verdict": parsed.verdict.clone(),
            "evidence_hash": evidence_hash,
            "cert_file": parsed.cert_out.display().to_string(),
        });
        print_json(&out);
        Ok(0)
    } else {
        let out = json!({
            "issued": false,
            "reason": response.refusal_reason.clone(),
        });
        print_json(&out);
        Ok(1)
    }
}

async fn cmd_certificate_status(parsed: CertificateStatusArgs) -> Result<i32, CliError> {
    let endpoint = resolve_endpoint(parsed.endpoint.clone(), None);
    let mut client = connect(&endpoint).await?;
    let response = client
        .certificate_status(Request::new(CertificateStatusRequest {
            serial: parsed.serial.clone(),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("certificate status RPC failed: {e}")))?
        .into_inner();

    let status = certificate_status_name(response.status);
    let body = match response.body.as_ref() {
        Some(body) => {
            let tests = match body.tests.as_ref() {
                Some(tests) => json!({
                    "passed": tests.passed,
                    "failed": tests.failed,
                    "total": tests.total,
                }),
                None => Value::Null,
            };
            json!({
                "schema": body.schema.clone(),
                "schema_version": body.schema_version,
                "serial": body.serial.clone(),
                "issuer": body.issuer.clone(),
                "product": body.product.clone(),
                "version": body.version.clone(),
                "verdict": body.verdict.clone(),
                "evidence_hash": body.evidence_hash.clone(),
                "evidence_scope": body.evidence_scope.clone(),
                "tests": tests,
                "policy": body.policy.clone(),
                "pf_outcomes": non_empty_string(&body.pf_outcomes),
                "issued_at": body.issued_at,
                "supersedes": non_empty_string(&body.supersedes),
                "fingerprint": body.fingerprint.clone(),
            })
        }
        None => Value::Null,
    };

    let out = json!({
        "serial": parsed.serial.clone(),
        "status": status,
        "body": body,
    });
    print_json(&out);
    Ok(0)
}

async fn cmd_certificate_verify(parsed: CertificateVerifyArgs) -> Result<i32, CliError> {
    let proof_file = load_proof(&parsed.cert_file)?;
    let envelope = proto_from_proof_file(&proof_file)?;
    let endpoint = resolve_endpoint(parsed.endpoint.clone(), None);
    let mut client = connect(&endpoint).await?;
    let response = client
        .verify_proof(Request::new(VerifyProofRequest {
            proof_envelope: Some(envelope),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("verify proof RPC failed: {e}")))?
        .into_inner();

    let out = json!({
        "valid": response.valid,
        "reason": response.reason.clone(),
    });
    print_json(&out);
    Ok(if response.valid { 0 } else { 1 })
}

async fn cmd_certificate_revoke(parsed: CertificateRevokeArgs) -> Result<i32, CliError> {
    let endpoint = resolve_endpoint(parsed.endpoint.clone(), None);
    let mut client = connect(&endpoint).await?;
    let response = client
        .revoke_certificate(Request::new(RevokeCertificateRequest {
            serial: parsed.serial.clone(),
            reason: parsed.reason.clone(),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("revoke certificate RPC failed: {e}")))?
        .into_inner();

    let out = json!({
        "revoked": response.revoked,
        "message": response.message.clone(),
        "serial": parsed.serial.clone(),
    });
    print_json(&out);
    Ok(if response.revoked { 0 } else { 1 })
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn certificate_status_name(status: i32) -> &'static str {
    match status {
        0 => "UNKNOWN",
        1 => "ACTIVE",
        2 => "SUPERSEDED",
        3 => "REVOKED",
        _ => "UNKNOWN",
    }
}

fn non_empty_string(value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(value.to_string())
    }
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
  certificate Issue, inspect, verify or revoke a release certificate
  publish     Check a publish action before posting and verify its receipt
  conduit     Check a Conduit tool call before dispatch and verify its receipt
  repo        Check a fleet-repo release before merge/release and verify its receipt
  nightly     Check a nightly build-lane action before it proceeds and verify its receipt

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

fn print_certificate_usage() -> String {
    r#"gm certificate: release-evidence certificates (WO-37 / v0.28.0)

USAGE:
  gm certificate issue  --product <p> --version <v> --verdict "<verdict>"
                        --evidence-file <path>
                        --evidence-scope <working-tree|full-history>
                        --tests-passed <n> --tests-failed <n>
                        --policy <policy> [--cert-out <path>]
                        [--endpoint <url>]
  gm certificate status --serial <serial> [--endpoint <url>]
  gm certificate verify [--cert-file <path>] [--endpoint <url>]
  gm certificate revoke --serial <serial> --reason "<reason>"
                        [--endpoint <url>]

ACTIONS:
  issue    Present a gate evidence pack. The CLI reads the evidence file and
           computes its SHA-256 itself; the operator never types a hash. Calls
           IssueCertificate and writes the sealed certificate to --cert-out
           (default gm-certificate.json in the current directory).
  status   Call CertificateStatus and print the lifecycle state and body.
  verify   Load a certificate file and call VerifyProof.
  revoke   Call RevokeCertificate with a reason.

Certificate RPCs need no session and no handshake.

OUTPUT:
  issue   {"issued": true, "serial": ..., "fingerprint": ..., "product": ...,
           "version": ..., "verdict": ..., "evidence_hash": ...,
           "cert_file": ...}; on refusal {"issued": false, "reason": ...}.
  status  {"serial": ..., "status": "UNKNOWN|ACTIVE|SUPERSEDED|REVOKED",
           "body": ...}
  verify  {"valid": <bool>, "reason": ...}
  revoke  {"revoked": <bool>, "message": ..., "serial": ...}

EXIT CODES:
  0  issue: certificate issued; status: the daemon answered (UNKNOWN
     included); verify: proof valid; revoke: revoked.
  1  issue: refused (for example a BLOCKED verdict); verify: proof invalid;
     revoke: the daemon answered revoked=false.
  2  usage, evidence-file, certificate-file, transport or gRPC error.

The certificate certifies the binding of the presenter's declarations to the
evidence hash under the daemon's signature, not the truth of the declarations.

OPTIONS:
  --product <p>           Product name
  --version <v>           Product version
  --verdict <v>           Gate verdict (PASS, PASS WITH FINDINGS, BLOCKED)
  --evidence-file <path>  Gate evidence pack; its hash is computed from the file
  --evidence-scope <s>    working-tree | full-history
  --tests-passed <n>      Tests that passed (u32)
  --tests-failed <n>      Tests that failed (u32)
  --policy <p>            Gate version/policy string
  --cert-out <path>       Certificate file to write (default gm-certificate.json)
  --cert-file <path>      Certificate file to verify (default gm-certificate.json)
  --serial <s>            Certificate serial
  --reason <r>            Revocation reason
  --endpoint <url>        Daemon gRPC endpoint (default http://127.0.0.1:50051;
                          GM_ENDPOINT is used when the flag is absent)
  --help                  Show this help"#
        .to_string()
}

#[derive(Debug)]
enum PublishAction {
    Check(PublishCheckArgs),
    Verify(PublishVerifyArgs),
}

#[derive(Debug, Clone)]
struct PublishCheckArgs {
    content_file: PathBuf,
    destination: String,
    channel: String,
    session_file: PathBuf,
    proof_out: Option<PathBuf>,
    receipt_out: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone)]
struct PublishVerifyArgs {
    receipt_file: PathBuf,
    proof_file: Option<PathBuf>,
    content_file: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PublishReceipt {
    receipt_version: u32,
    kind: String,
    content_sha256: String,
    content_bytes: u64,
    destination: String,
    channel: String,
    verdict: String,
    reason: String,
    simulation: bool,
    proof: Value,
    proof_file: String,
}

fn default_publish_proof_path(session_file: &Path) -> PathBuf {
    match session_file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("gm-publish-proof.json"),
        _ => PathBuf::from("gm-publish-proof.json"),
    }
}

fn publish_check_exit(verdict: &str) -> i32 {
    match verdict {
        "ALLOW" => 0,
        _ => 1,
    }
}

fn parse_publish_action(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<PublishAction, CliError> {
    let action = match args.first() {
        Some(action) => action.as_str(),
        None => {
            return Err(CliError::usage(
                "publish requires an action: check or verify",
            ))
        }
    };
    let rest = &args[1..];
    match action {
        "check" => Ok(PublishAction::Check(parse_publish_check_args(
            rest,
            pre_endpoint,
        )?)),
        "verify" => Ok(PublishAction::Verify(parse_publish_verify_args(
            rest,
            pre_endpoint,
        )?)),
        "--help" | "-h" => Err(CliError::help(publish_help())),
        other => Err(CliError::usage(format!(
            "unknown publish action: {other} (expected check or verify)"
        ))),
    }
}

fn parse_publish_check_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<PublishCheckArgs, CliError> {
    let mut content_file = None;
    let mut destination = None;
    let mut channel = "blog".to_string();
    let mut session_file = default_session_path();
    let mut proof_out = None;
    let mut receipt_out = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--content-file" => {
                content_file = Some(PathBuf::from(next_value(args, &mut i, "--content-file")?))
            }
            "--destination" => destination = Some(next_value(args, &mut i, "--destination")?),
            "--channel" => channel = next_value(args, &mut i, "--channel")?,
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--proof-out" => {
                proof_out = Some(PathBuf::from(next_value(args, &mut i, "--proof-out")?))
            }
            "--receipt-out" => {
                receipt_out = Some(PathBuf::from(next_value(args, &mut i, "--receipt-out")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(publish_check_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(PublishCheckArgs {
        content_file: content_file.ok_or_else(|| CliError::usage("--content-file is required"))?,
        destination: destination.ok_or_else(|| CliError::usage("--destination is required"))?,
        channel,
        session_file,
        proof_out,
        receipt_out,
        endpoint,
    })
}

fn parse_publish_verify_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<PublishVerifyArgs, CliError> {
    let mut receipt_file = PathBuf::from("gm-publish-receipt.json");
    let mut proof_file = None;
    let mut content_file = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--receipt-file" => {
                receipt_file = PathBuf::from(next_value(args, &mut i, "--receipt-file")?)
            }
            "--proof-file" => {
                proof_file = Some(PathBuf::from(next_value(args, &mut i, "--proof-file")?))
            }
            "--content-file" => {
                content_file = Some(PathBuf::from(next_value(args, &mut i, "--content-file")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(publish_verify_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(PublishVerifyArgs {
        receipt_file,
        proof_file,
        content_file,
        endpoint,
    })
}

async fn cmd_publish(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let action = match parse_publish_action(args, pre_endpoint) {
        Ok(action) => action,
        Err(CliError::Usage(message)) => {
            return Err(CliError::usage(format!(
                "{message}\n\n{}",
                publish_help()
            )))
        }
        Err(error) => return Err(error),
    };
    match action {
        PublishAction::Check(parsed) => cmd_publish_check(parsed).await,
        PublishAction::Verify(parsed) => cmd_publish_verify(parsed).await,
    }
}

async fn cmd_publish_check(parsed: PublishCheckArgs) -> Result<i32, CliError> {
    let content = fs::read(&parsed.content_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "content file not found: {}",
                parsed.content_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read content file {}: {e}",
                parsed.content_file.display()
            ))
        }
    })?;
    let content_sha256 = sha256_hex(&content);
    let content_bytes = content.len() as u64;

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

    let mut metadata = BTreeMap::new();
    metadata.insert("channel".to_string(), parsed.channel.clone());
    metadata.insert("content_bytes".to_string(), content_bytes.to_string());
    metadata.insert("content_sha256".to_string(), content_sha256.clone());
    metadata.insert("kind".to_string(), "publish".to_string());

    let payload = build_payload(
        "PUBLISH",
        &format!("publishing:{}", parsed.channel),
        &parsed.destination,
        &metadata,
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
            action_type: "PUBLISH".to_string(),
            context: format!("publishing:{}", parsed.channel),
            target: parsed.destination.clone(),
            metadata: metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }),
    };

    let mut client = connect(&endpoint).await?;
    let response = client
        .evaluate(Request::new(request))
        .await
        .map_err(|e| CliError::runtime(format!("evaluate RPC failed: {e}")))?
        .into_inner();

    let proof_envelope = response.proof_envelope.as_ref().ok_or_else(|| {
        CliError::runtime("evaluate response did not include a proof envelope")
    })?;
    let proof_path = parsed
        .proof_out
        .clone()
        .unwrap_or_else(|| default_publish_proof_path(&parsed.session_file));
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
    let receipt_path = parsed
        .receipt_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("gm-publish-receipt.json"));
    let receipt = PublishReceipt {
        receipt_version: 1,
        kind: "publish".to_string(),
        content_sha256: content_sha256.clone(),
        content_bytes,
        destination: parsed.destination.clone(),
        channel: parsed.channel.clone(),
        verdict: response.verdict.clone(),
        reason: response.reason.clone(),
        simulation: false,
        proof: proof.clone(),
        proof_file: proof_path.display().to_string(),
    };
    write_json(&receipt_path, &receipt, false)?;

    let mut out = serde_json::to_value(&receipt).map_err(|e| {
        CliError::runtime(format!("failed to serialize publish receipt: {e}"))
    })?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "receipt_file".to_string(),
            Value::String(receipt_path.display().to_string()),
        );
    }
    print_json(&out);
    Ok(publish_check_exit(&response.verdict))
}

async fn cmd_publish_verify(parsed: PublishVerifyArgs) -> Result<i32, CliError> {
    let bytes = fs::read(&parsed.receipt_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "receipt file not found: {}",
                parsed.receipt_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read receipt file {}: {e}",
                parsed.receipt_file.display()
            ))
        }
    })?;
    let receipt_value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::runtime(format!(
            "invalid receipt file {}: {e}",
            parsed.receipt_file.display()
        ))
    })?;
    let content_sha256 = receipt_value
        .get("content_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing content_sha256 field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let receipt_proof_file = receipt_value
        .get("proof_file")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing proof_file field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let verdict = receipt_value
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let proof_path = parsed
        .proof_file
        .unwrap_or_else(|| PathBuf::from(receipt_proof_file));
    let proof_file = load_proof(&proof_path)?;
    let envelope = proto_from_proof_file(&proof_file)?;

    let endpoint = resolve_endpoint(parsed.endpoint, None);
    let mut client = connect(&endpoint).await?;
    let response = client
        .verify_proof(Request::new(VerifyProofRequest {
            proof_envelope: Some(envelope),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("verify proof RPC failed: {e}")))?
        .into_inner();

    let content_hash_matches: Value = if let Some(path) = parsed.content_file.as_ref() {
        let cbytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CliError::runtime(format!("content file not found: {}", path.display()))
            } else {
                CliError::runtime(format!("cannot read content file {}: {e}", path.display()))
            }
        })?;
        let recomputed = sha256_hex(&cbytes);
        Value::Bool(recomputed == content_sha256)
    } else {
        Value::Null
    };

    let out = json!({
        "valid": response.valid,
        "reason": response.reason.clone(),
        "verdict": verdict,
        "content_hash_matches": content_hash_matches,
        "content_sha256": content_sha256,
    });
    print_json(&out);
    let hash_bad = matches!(content_hash_matches, Value::Bool(false));
    Ok(if response.valid && !hash_bad { 0 } else { 1 })
}

fn publish_help() -> String {
    r#"gm publish: publishing-pipeline touchpoint (WO-37 / v0.29.0)

USAGE:
  gm publish <action> [options]

ACTIONS:
  check    Check a publish action before posting and write a receipt
  verify   Re-check a saved publish proof and receipt content hash

Exit 0 is the only outcome under which the publisher may post; exit 1 and
exit 2 both mean do not post.

Run `gm publish check --help` or `gm publish verify --help` for details."#
        .to_string()
}

fn publish_check_help() -> String {
    r#"gm publish check: evaluate a publish action before posting

USAGE:
  gm publish check --content-file <path> --destination <dest>
                   [--channel <name>] [--session-file <path>]
                   [--proof-out <path>] [--receipt-out <path>]
                   [--endpoint <url>]

Reads the content file, computes its SHA-256 itself, and calls a real
Evaluate (never Simulate) for action_type PUBLISH with
context "publishing:<channel>", the destination as target, and metadata
carrying channel, content_bytes, content_sha256 and kind="publish".
Saves the sealed proof and a receipt pairing the proof with the content
hash, destination and channel. This command does not post anything.

Defaults: --channel blog, --proof-out gm-publish-proof.json beside the
session file, --receipt-out gm-publish-receipt.json in the current
directory.

EXIT CODES:
  0  verdict ALLOW: the receipt was written and the publisher may post.
  1  a verdict response arrived and verdict is not ALLOW (BLOCK/THROTTLE/
     ESCALATE): the receipt is still written naming the verdict; do not post.
  2  usage, session, transport or RPC error (including a pre-proof block
     delivered as a permission-denied RPC error): nothing is written; do not
     post.

Exit 0 is the only outcome under which the publisher may post; exit 1 and
exit 2 both mean do not post.

OPTIONS:
  --content-file <p>   Content file to be posted (required)
  --destination <d>    Publish destination (required)
  --channel <name>     Channel name (default blog)
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json)
  --proof-out <p>      Proof file path (default gm-publish-proof.json beside session)
  --receipt-out <p>    Receipt file path (default gm-publish-receipt.json)
  --endpoint <url>     Daemon gRPC endpoint (default from session file, then
                       http://127.0.0.1:50051; GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn publish_verify_help() -> String {
    r#"gm publish verify: verify a publish proof and receipt content hash

USAGE:
  gm publish verify [--receipt-file <path>] [--proof-file <path>]
                    [--content-file <path>] [--endpoint <url>]

Loads the receipt and proof, calls VerifyProof, and optionally recomputes
the SHA-256 of --content-file and compares it to the receipt. This checks
the proof with the daemon and the receipt's content-hash pairing by
recomputation; it does not require a session.

EXIT CODES:
  0  proof valid and content_hash_matches is not false.
  1  proof invalid or content hash mismatch.
  2  usage, transport, missing/malformed receipt or proof.

OPTIONS:
  --receipt-file <p>   Receipt file (default gm-publish-receipt.json)
  --proof-file <p>     Proof file (default: receipt's proof_file)
  --content-file <p>   Artifact to hash-compare against the receipt
  --endpoint <url>     Daemon gRPC endpoint (default http://127.0.0.1:50051;
                       GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}


#[derive(Debug)]
enum ConduitAction {
    Check(ConduitCheckArgs),
    Verify(ConduitVerifyArgs),
}

#[derive(Debug, Clone)]
struct ConduitCheckArgs {
    tool: String,
    tenant: String,
    args_file: PathBuf,
    provider: Option<String>,
    session_file: PathBuf,
    proof_out: Option<PathBuf>,
    receipt_out: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone)]
struct ConduitVerifyArgs {
    receipt_file: PathBuf,
    proof_file: Option<PathBuf>,
    args_file: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ConduitReceipt {
    receipt_version: u32,
    kind: String,
    tenant: String,
    tool: String,
    provider: Option<String>,
    args_sha256: String,
    args_bytes: u64,
    verdict: String,
    reason: String,
    simulation: bool,
    proof: Value,
    proof_file: String,
}

fn default_conduit_proof_path(session_file: &Path) -> PathBuf {
    match session_file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("gm-conduit-proof.json"),
        _ => PathBuf::from("gm-conduit-proof.json"),
    }
}

fn conduit_check_exit(verdict: &str) -> i32 {
    match verdict {
        "ALLOW" => 0,
        _ => 1,
    }
}

fn parse_conduit_action(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<ConduitAction, CliError> {
    let action = match args.first() {
        Some(action) => action.as_str(),
        None => {
            return Err(CliError::usage(
                "conduit requires an action: check or verify",
            ))
        }
    };
    let rest = &args[1..];
    match action {
        "check" => Ok(ConduitAction::Check(parse_conduit_check_args(
            rest,
            pre_endpoint,
        )?)),
        "verify" => Ok(ConduitAction::Verify(parse_conduit_verify_args(
            rest,
            pre_endpoint,
        )?)),
        "--help" | "-h" => Err(CliError::help(conduit_help())),
        other => Err(CliError::usage(format!(
            "unknown conduit action: {other} (expected check or verify)"
        ))),
    }
}

fn parse_conduit_check_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<ConduitCheckArgs, CliError> {
    let mut tool = None;
    let mut tenant = None;
    let mut args_file = None;
    let mut provider = None;
    let mut session_file = default_session_path();
    let mut proof_out = None;
    let mut receipt_out = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tool" => tool = Some(next_value(args, &mut i, "--tool")?),
            "--tenant" => tenant = Some(next_value(args, &mut i, "--tenant")?),
            "--args-file" => {
                args_file = Some(PathBuf::from(next_value(args, &mut i, "--args-file")?))
            }
            "--provider" => provider = Some(next_value(args, &mut i, "--provider")?),
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--proof-out" => {
                proof_out = Some(PathBuf::from(next_value(args, &mut i, "--proof-out")?))
            }
            "--receipt-out" => {
                receipt_out = Some(PathBuf::from(next_value(args, &mut i, "--receipt-out")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(conduit_check_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(ConduitCheckArgs {
        tool: tool.ok_or_else(|| CliError::usage("--tool is required"))?,
        tenant: tenant.ok_or_else(|| CliError::usage("--tenant is required"))?,
        args_file: args_file.ok_or_else(|| CliError::usage("--args-file is required"))?,
        provider,
        session_file,
        proof_out,
        receipt_out,
        endpoint,
    })
}

fn parse_conduit_verify_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<ConduitVerifyArgs, CliError> {
    let mut receipt_file = PathBuf::from("gm-conduit-receipt.json");
    let mut proof_file = None;
    let mut args_file = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--receipt-file" => {
                receipt_file = PathBuf::from(next_value(args, &mut i, "--receipt-file")?)
            }
            "--proof-file" => {
                proof_file = Some(PathBuf::from(next_value(args, &mut i, "--proof-file")?))
            }
            "--args-file" => {
                args_file = Some(PathBuf::from(next_value(args, &mut i, "--args-file")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(conduit_verify_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(ConduitVerifyArgs {
        receipt_file,
        proof_file,
        args_file,
        endpoint,
    })
}

async fn cmd_conduit(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let action = match parse_conduit_action(args, pre_endpoint) {
        Ok(action) => action,
        Err(CliError::Usage(message)) => {
            return Err(CliError::usage(format!(
                "{message}\n\n{}",
                conduit_help()
            )))
        }
        Err(error) => return Err(error),
    };
    match action {
        ConduitAction::Check(parsed) => cmd_conduit_check(parsed).await,
        ConduitAction::Verify(parsed) => cmd_conduit_verify(parsed).await,
    }
}

async fn cmd_conduit_check(parsed: ConduitCheckArgs) -> Result<i32, CliError> {
    let args_bytes_read = fs::read(&parsed.args_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "args file not found: {}",
                parsed.args_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read args file {}: {e}",
                parsed.args_file.display()
            ))
        }
    })?;
    let args_sha256 = sha256_hex(&args_bytes_read);
    let args_bytes = args_bytes_read.len() as u64;

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

    let mut metadata = BTreeMap::new();
    metadata.insert("args_bytes".to_string(), args_bytes.to_string());
    metadata.insert("args_sha256".to_string(), args_sha256.clone());
    metadata.insert("kind".to_string(), "conduit".to_string());
    metadata.insert("tenant".to_string(), parsed.tenant.clone());
    metadata.insert("tool".to_string(), parsed.tool.clone());
    if let Some(provider) = parsed.provider.as_ref() {
        metadata.insert("provider".to_string(), provider.clone());
    }

    let context = format!("conduit:{}", parsed.tenant);
    let payload = build_payload("TOOL_CALL", &context, &parsed.tool, &metadata);
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
            action_type: "TOOL_CALL".to_string(),
            context: context.clone(),
            target: parsed.tool.clone(),
            metadata: metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }),
    };

    let mut client = connect(&endpoint).await?;
    let response = client
        .evaluate(Request::new(request))
        .await
        .map_err(|e| CliError::runtime(format!("evaluate RPC failed: {e}")))?
        .into_inner();

    let proof_envelope = response.proof_envelope.as_ref().ok_or_else(|| {
        CliError::runtime("evaluate response did not include a proof envelope")
    })?;
    let proof_path = parsed
        .proof_out
        .clone()
        .unwrap_or_else(|| default_conduit_proof_path(&parsed.session_file));
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
    let receipt_path = parsed
        .receipt_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("gm-conduit-receipt.json"));
    let receipt = ConduitReceipt {
        receipt_version: 1,
        kind: "conduit".to_string(),
        tenant: parsed.tenant.clone(),
        tool: parsed.tool.clone(),
        provider: parsed.provider.clone(),
        args_sha256: args_sha256.clone(),
        args_bytes,
        verdict: response.verdict.clone(),
        reason: response.reason.clone(),
        simulation: false,
        proof: proof.clone(),
        proof_file: proof_path.display().to_string(),
    };
    write_json(&receipt_path, &receipt, false)?;

    let mut out = serde_json::to_value(&receipt).map_err(|e| {
        CliError::runtime(format!("failed to serialize conduit receipt: {e}"))
    })?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "receipt_file".to_string(),
            Value::String(receipt_path.display().to_string()),
        );
    }
    print_json(&out);
    Ok(conduit_check_exit(&response.verdict))
}

async fn cmd_conduit_verify(parsed: ConduitVerifyArgs) -> Result<i32, CliError> {
    let bytes = fs::read(&parsed.receipt_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "receipt file not found: {}",
                parsed.receipt_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read receipt file {}: {e}",
                parsed.receipt_file.display()
            ))
        }
    })?;
    let receipt_value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::runtime(format!(
            "invalid receipt file {}: {e}",
            parsed.receipt_file.display()
        ))
    })?;
    let args_sha256 = receipt_value
        .get("args_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing args_sha256 field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let receipt_proof_file = receipt_value
        .get("proof_file")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing proof_file field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let verdict = receipt_value
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let proof_path = parsed
        .proof_file
        .unwrap_or_else(|| PathBuf::from(receipt_proof_file));
    let proof_file = load_proof(&proof_path)?;
    let envelope = proto_from_proof_file(&proof_file)?;

    let endpoint = resolve_endpoint(parsed.endpoint, None);
    let mut client = connect(&endpoint).await?;
    let response = client
        .verify_proof(Request::new(VerifyProofRequest {
            proof_envelope: Some(envelope),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("verify proof RPC failed: {e}")))?
        .into_inner();

    let args_hash_matches: Value = if let Some(path) = parsed.args_file.as_ref() {
        let abytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CliError::runtime(format!("args file not found: {}", path.display()))
            } else {
                CliError::runtime(format!("cannot read args file {}: {e}", path.display()))
            }
        })?;
        let recomputed = sha256_hex(&abytes);
        Value::Bool(recomputed == args_sha256)
    } else {
        Value::Null
    };

    let out = json!({
        "valid": response.valid,
        "reason": response.reason.clone(),
        "verdict": verdict,
        "args_hash_matches": args_hash_matches,
        "args_sha256": args_sha256,
    });
    print_json(&out);
    let hash_bad = matches!(args_hash_matches, Value::Bool(false));
    Ok(if response.valid && !hash_bad { 0 } else { 1 })
}

fn conduit_help() -> String {
    r#"gm conduit: Conduit tool-call touchpoint (WO-37 / v0.30.0)

USAGE:
  gm conduit <action> [options]

ACTIONS:
  check    Check a Conduit tool call before dispatch and write a receipt
  verify   Re-check a saved conduit proof and receipt args hash

Exit 0 is the only outcome under which the caller may dispatch the tool call;
exit 1 and exit 2 both mean do not dispatch.

Run `gm conduit check --help` or `gm conduit verify --help` for details."#
        .to_string()
}

fn conduit_check_help() -> String {
    r#"gm conduit check: evaluate a Conduit tool call before dispatch

USAGE:
  gm conduit check --tool <name> --tenant <id> --args-file <path>
                   [--provider <name>] [--session-file <path>]
                   [--proof-out <path>] [--receipt-out <path>]
                   [--endpoint <url>]

Reads the args file, computes its SHA-256 itself, and calls a real Evaluate
(never Simulate) for action_type TOOL_CALL with context "conduit:<tenant>",
the tool as target, and metadata carrying kind="conduit", tenant, tool,
args_sha256, args_bytes and provider when given. The raw args are never
printed and never enter the receipt - only their hash does. Saves the sealed
proof and a receipt pairing the proof with the args hash, tenant and tool.
This command does not dispatch anything itself.

Defaults: --proof-out gm-conduit-proof.json beside the session file,
--receipt-out gm-conduit-receipt.json in the current directory.

EXIT CODES:
  0  verdict ALLOW: the receipt was written and the caller may dispatch the
     tool call; this is the only outcome under which it may do so.
  1  a verdict response arrived and verdict is not ALLOW (BLOCK/THROTTLE/
     ESCALATE): the receipt is still written naming the verdict; do not dispatch.
  2  usage, session, transport or RPC error (including a pre-proof block
     delivered as a permission-denied RPC error): nothing is written; do not
     dispatch.

OPTIONS:
  --tool <name>        Tool to be dispatched (required)
  --tenant <id>        Tenant id for the conduit context (required)
  --args-file <p>      Args file to be hashed (required; raw args never printed)
  --provider <name>    Optional provider name, recorded in metadata and receipt
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json)
  --proof-out <p>      Proof file path (default gm-conduit-proof.json beside session)
  --receipt-out <p>    Receipt file path (default gm-conduit-receipt.json)
  --endpoint <url>     Daemon gRPC endpoint (default from session file, then
                       http://127.0.0.1:50051; GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn conduit_verify_help() -> String {
    r#"gm conduit verify: verify a conduit proof and receipt args hash

USAGE:
  gm conduit verify [--receipt-file <path>] [--proof-file <path>]
                    [--args-file <path>] [--endpoint <url>]

Loads the receipt and proof, calls VerifyProof, and optionally recomputes
the SHA-256 of --args-file and compares it to the receipt. This checks the
proof with the daemon and the receipt's args-hash pairing by recomputation;
it does not require a session. The raw args are never printed.

EXIT CODES:
  0  proof valid and args_hash_matches is not false.
  1  proof invalid or args hash mismatch.
  2  usage, transport, missing/malformed receipt or proof.

OPTIONS:
  --receipt-file <p>   Receipt file (default gm-conduit-receipt.json)
  --proof-file <p>     Proof file (default: receipt's proof_file)
  --args-file <p>      Args file to hash-compare against the receipt
  --endpoint <url>     Daemon gRPC endpoint (default http://127.0.0.1:50051;
                       GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

#[derive(Debug)]
enum RepoAction {
    Check(RepoCheckArgs),
    Verify(RepoVerifyArgs),
}

#[derive(Debug, Clone)]
struct RepoCheckArgs {
    repo: String,
    commit: String,
    evidence_file: PathBuf,
    branch: Option<String>,
    session_file: PathBuf,
    proof_out: Option<PathBuf>,
    receipt_out: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone)]
struct RepoVerifyArgs {
    receipt_file: PathBuf,
    proof_file: Option<PathBuf>,
    evidence_file: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RepoReceipt {
    receipt_version: u32,
    kind: String,
    repo: String,
    commit: String,
    branch: Option<String>,
    evidence_sha256: String,
    evidence_bytes: u64,
    verdict: String,
    reason: String,
    simulation: bool,
    proof: Value,
    proof_file: String,
}

fn default_repo_proof_path(session_file: &Path) -> PathBuf {
    match session_file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("gm-repo-proof.json"),
        _ => PathBuf::from("gm-repo-proof.json"),
    }
}

fn repo_check_exit(verdict: &str) -> i32 {
    match verdict {
        "ALLOW" => 0,
        _ => 1,
    }
}

fn parse_repo_action(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<RepoAction, CliError> {
    let action = match args.first() {
        Some(action) => action.as_str(),
        None => {
            return Err(CliError::usage(
                "repo requires an action: check or verify",
            ))
        }
    };
    let rest = &args[1..];
    match action {
        "check" => Ok(RepoAction::Check(parse_repo_check_args(
            rest,
            pre_endpoint,
        )?)),
        "verify" => Ok(RepoAction::Verify(parse_repo_verify_args(
            rest,
            pre_endpoint,
        )?)),
        "--help" | "-h" => Err(CliError::help(repo_help())),
        other => Err(CliError::usage(format!(
            "unknown repo action: {other} (expected check or verify)"
        ))),
    }
}

fn parse_repo_check_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<RepoCheckArgs, CliError> {
    let mut repo = None;
    let mut commit = None;
    let mut evidence_file = None;
    let mut branch = None;
    let mut session_file = default_session_path();
    let mut proof_out = None;
    let mut receipt_out = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => repo = Some(next_value(args, &mut i, "--repo")?),
            "--commit" => commit = Some(next_value(args, &mut i, "--commit")?),
            "--evidence-file" => {
                evidence_file = Some(PathBuf::from(next_value(args, &mut i, "--evidence-file")?))
            }
            "--branch" => branch = Some(next_value(args, &mut i, "--branch")?),
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--proof-out" => {
                proof_out = Some(PathBuf::from(next_value(args, &mut i, "--proof-out")?))
            }
            "--receipt-out" => {
                receipt_out = Some(PathBuf::from(next_value(args, &mut i, "--receipt-out")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(repo_check_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(RepoCheckArgs {
        repo: repo.ok_or_else(|| CliError::usage("--repo is required"))?,
        commit: commit.ok_or_else(|| CliError::usage("--commit is required"))?,
        evidence_file: evidence_file
            .ok_or_else(|| CliError::usage("--evidence-file is required"))?,
        branch,
        session_file,
        proof_out,
        receipt_out,
        endpoint,
    })
}

fn parse_repo_verify_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<RepoVerifyArgs, CliError> {
    let mut receipt_file = PathBuf::from("gm-repo-receipt.json");
    let mut proof_file = None;
    let mut evidence_file = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--receipt-file" => {
                receipt_file = PathBuf::from(next_value(args, &mut i, "--receipt-file")?)
            }
            "--proof-file" => {
                proof_file = Some(PathBuf::from(next_value(args, &mut i, "--proof-file")?))
            }
            "--evidence-file" => {
                evidence_file = Some(PathBuf::from(next_value(args, &mut i, "--evidence-file")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(repo_verify_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(RepoVerifyArgs {
        receipt_file,
        proof_file,
        evidence_file,
        endpoint,
    })
}

async fn cmd_repo(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let action = match parse_repo_action(args, pre_endpoint) {
        Ok(action) => action,
        Err(CliError::Usage(message)) => {
            return Err(CliError::usage(format!("{message}\n\n{}", repo_help())))
        }
        Err(error) => return Err(error),
    };
    match action {
        RepoAction::Check(parsed) => cmd_repo_check(parsed).await,
        RepoAction::Verify(parsed) => cmd_repo_verify(parsed).await,
    }
}

async fn cmd_repo_check(parsed: RepoCheckArgs) -> Result<i32, CliError> {
    let evidence_bytes_read = fs::read(&parsed.evidence_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "evidence file not found: {}",
                parsed.evidence_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read evidence file {}: {e}",
                parsed.evidence_file.display()
            ))
        }
    })?;
    let evidence_sha256 = sha256_hex(&evidence_bytes_read);
    let evidence_bytes = evidence_bytes_read.len() as u64;

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

    let mut metadata = BTreeMap::new();
    metadata.insert("commit".to_string(), parsed.commit.clone());
    metadata.insert("evidence_bytes".to_string(), evidence_bytes.to_string());
    metadata.insert("evidence_sha256".to_string(), evidence_sha256.clone());
    metadata.insert("kind".to_string(), "repo".to_string());
    metadata.insert("repo".to_string(), parsed.repo.clone());
    if let Some(branch) = parsed.branch.as_ref() {
        metadata.insert("branch".to_string(), branch.clone());
    }

    let context = format!("repo:{}", parsed.repo);
    let payload = build_payload("REPO_RELEASE", &context, &parsed.repo, &metadata);
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
            action_type: "REPO_RELEASE".to_string(),
            context: context.clone(),
            target: parsed.repo.clone(),
            metadata: metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }),
    };

    let mut client = connect(&endpoint).await?;
    let response = client
        .evaluate(Request::new(request))
        .await
        .map_err(|e| CliError::runtime(format!("evaluate RPC failed: {e}")))?
        .into_inner();

    let proof_envelope = response.proof_envelope.as_ref().ok_or_else(|| {
        CliError::runtime("evaluate response did not include a proof envelope")
    })?;
    let proof_path = parsed
        .proof_out
        .clone()
        .unwrap_or_else(|| default_repo_proof_path(&parsed.session_file));
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
    let receipt_path = parsed
        .receipt_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("gm-repo-receipt.json"));
    let receipt = RepoReceipt {
        receipt_version: 1,
        kind: "repo".to_string(),
        repo: parsed.repo.clone(),
        commit: parsed.commit.clone(),
        branch: parsed.branch.clone(),
        evidence_sha256: evidence_sha256.clone(),
        evidence_bytes,
        verdict: response.verdict.clone(),
        reason: response.reason.clone(),
        simulation: false,
        proof: proof.clone(),
        proof_file: proof_path.display().to_string(),
    };
    write_json(&receipt_path, &receipt, false)?;

    let mut out = serde_json::to_value(&receipt).map_err(|e| {
        CliError::runtime(format!("failed to serialize repo receipt: {e}"))
    })?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "receipt_file".to_string(),
            Value::String(receipt_path.display().to_string()),
        );
    }
    print_json(&out);
    Ok(repo_check_exit(&response.verdict))
}

async fn cmd_repo_verify(parsed: RepoVerifyArgs) -> Result<i32, CliError> {
    let bytes = fs::read(&parsed.receipt_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "receipt file not found: {}",
                parsed.receipt_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read receipt file {}: {e}",
                parsed.receipt_file.display()
            ))
        }
    })?;
    let receipt_value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::runtime(format!(
            "invalid receipt file {}: {e}",
            parsed.receipt_file.display()
        ))
    })?;
    let evidence_sha256 = receipt_value
        .get("evidence_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing evidence_sha256 field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let receipt_proof_file = receipt_value
        .get("proof_file")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing proof_file field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let verdict = receipt_value
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let proof_path = parsed
        .proof_file
        .unwrap_or_else(|| PathBuf::from(receipt_proof_file));
    let proof_file = load_proof(&proof_path)?;
    let envelope = proto_from_proof_file(&proof_file)?;

    let endpoint = resolve_endpoint(parsed.endpoint, None);
    let mut client = connect(&endpoint).await?;
    let response = client
        .verify_proof(Request::new(VerifyProofRequest {
            proof_envelope: Some(envelope),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("verify proof RPC failed: {e}")))?
        .into_inner();

    let evidence_hash_matches: Value = if let Some(path) = parsed.evidence_file.as_ref() {
        let ebytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CliError::runtime(format!("evidence file not found: {}", path.display()))
            } else {
                CliError::runtime(format!("cannot read evidence file {}: {e}", path.display()))
            }
        })?;
        let recomputed = sha256_hex(&ebytes);
        Value::Bool(recomputed == evidence_sha256)
    } else {
        Value::Null
    };

    let out = json!({
        "valid": response.valid,
        "reason": response.reason.clone(),
        "verdict": verdict,
        "evidence_hash_matches": evidence_hash_matches,
        "evidence_sha256": evidence_sha256,
    });
    print_json(&out);
    let hash_bad = matches!(evidence_hash_matches, Value::Bool(false));
    Ok(if response.valid && !hash_bad { 0 } else { 1 })
}

fn repo_help() -> String {
    r#"gm repo: fleet-repo touchpoint (WO-37 / v0.31.0)

USAGE:
  gm repo <action> [options]

ACTIONS:
  check    Check a fleet-repo release before merge/release and write a receipt
  verify   Re-check a saved repo proof and receipt evidence hash

Exit 0 is the only outcome under which the caller may proceed with the
merge/release; exit 1 and exit 2 both mean do not proceed.

Run `gm repo check --help` or `gm repo verify --help` for details."#
        .to_string()
}

fn repo_check_help() -> String {
    r#"gm repo check: evaluate a fleet-repo release before merge/release

USAGE:
  gm repo check --repo <owner/name> --commit <sha> --evidence-file <path>
                [--branch <name>] [--session-file <path>]
                [--proof-out <path>] [--receipt-out <path>]
                [--endpoint <url>]

Reads the evidence file, computes its SHA-256 itself, and calls a real
Evaluate (never Simulate) for action_type REPO_RELEASE with context
"repo:<repo>", the repo as target, and metadata carrying kind="repo", repo,
commit, evidence_sha256, evidence_bytes and branch when given. This checks a
merge/release of the named repo at the named commit before it proceeds. Saves
the sealed proof and a receipt pairing the proof with the evidence hash, repo
and commit. This command does not merge, push or release anything itself.

Defaults: --proof-out gm-repo-proof.json beside the session file,
--receipt-out gm-repo-receipt.json in the current directory.

EXIT CODES:
  0  verdict ALLOW: the receipt was written and the caller may proceed with
     the merge/release; this is the only outcome under which it may do so.
  1  a verdict response arrived and verdict is not ALLOW (BLOCK/THROTTLE/
     ESCALATE): the receipt is still written naming the verdict; do not proceed.
  2  usage, session, transport or RPC error (including a pre-proof block
     delivered as a permission-denied RPC error): nothing is written; do not
     proceed.

OPTIONS:
  --repo <owner/name>  Repository to be released (required)
  --commit <sha>       Exact commit being released (required)
  --evidence-file <p>  Evidence file to be hashed (required)
  --branch <name>      Optional branch name, recorded in metadata and receipt
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json)
  --proof-out <p>      Proof file path (default gm-repo-proof.json beside session)
  --receipt-out <p>    Receipt file path (default gm-repo-receipt.json)
  --endpoint <url>     Daemon gRPC endpoint (default from session file, then
                       http://127.0.0.1:50051; GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn repo_verify_help() -> String {
    r#"gm repo verify: verify a repo proof and receipt evidence hash

USAGE:
  gm repo verify [--receipt-file <path>] [--proof-file <path>]
                 [--evidence-file <path>] [--endpoint <url>]

Loads the receipt and proof, calls VerifyProof, and optionally recomputes
the SHA-256 of --evidence-file and compares it to the receipt. This checks
the proof with the daemon and the receipt's evidence-hash pairing by
recomputation; it does not require a session.

EXIT CODES:
  0  proof valid and evidence_hash_matches is not false.
  1  proof invalid or evidence hash mismatch.
  2  usage, transport, missing/malformed receipt or proof.

OPTIONS:
  --receipt-file <p>   Receipt file (default gm-repo-receipt.json)
  --proof-file <p>     Proof file (default: receipt's proof_file)
  --evidence-file <p>  Evidence file to hash-compare against the receipt
  --endpoint <url>     Daemon gRPC endpoint (default http://127.0.0.1:50051;
                       GM_ENDPOINT when the flag is absent)
   --help               Show this help"#
        .to_string()
}

#[derive(Debug)]
enum NightlyAction {
    Check(NightlyCheckArgs),
    Verify(NightlyVerifyArgs),
}

#[derive(Debug, Clone)]
struct NightlyCheckArgs {
    work_order: String,
    run: Option<String>,
    evidence_file: PathBuf,
    session_file: PathBuf,
    proof_out: Option<PathBuf>,
    receipt_out: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone)]
struct NightlyVerifyArgs {
    receipt_file: PathBuf,
    proof_file: Option<PathBuf>,
    evidence_file: Option<PathBuf>,
    endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NightlyReceipt {
    receipt_version: u32,
    kind: String,
    work_order: String,
    run: Option<String>,
    evidence_sha256: String,
    evidence_bytes: u64,
    verdict: String,
    reason: String,
    simulation: bool,
    proof: Value,
    proof_file: String,
}

fn default_nightly_proof_path(session_file: &Path) -> PathBuf {
    match session_file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("gm-nightly-proof.json"),
        _ => PathBuf::from("gm-nightly-proof.json"),
    }
}

fn nightly_check_exit(verdict: &str) -> i32 {
    match verdict {
        "ALLOW" => 0,
        _ => 1,
    }
}

fn parse_nightly_action(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<NightlyAction, CliError> {
    let action = match args.first() {
        Some(action) => action.as_str(),
        None => {
            return Err(CliError::usage(
                "nightly requires an action: check or verify",
            ))
        }
    };
    let rest = &args[1..];
    match action {
        "check" => Ok(NightlyAction::Check(parse_nightly_check_args(
            rest,
            pre_endpoint,
        )?)),
        "verify" => Ok(NightlyAction::Verify(parse_nightly_verify_args(
            rest,
            pre_endpoint,
        )?)),
        "--help" | "-h" => Err(CliError::help(nightly_help())),
        other => Err(CliError::usage(format!(
            "unknown nightly action: {other} (expected check or verify)"
        ))),
    }
}

fn parse_nightly_check_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<NightlyCheckArgs, CliError> {
    let mut work_order = None;
    let mut run = None;
    let mut evidence_file = None;
    let mut session_file = default_session_path();
    let mut proof_out = None;
    let mut receipt_out = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--work-order" => work_order = Some(next_value(args, &mut i, "--work-order")?),
            "--run" => run = Some(next_value(args, &mut i, "--run")?),
            "--evidence-file" => {
                evidence_file = Some(PathBuf::from(next_value(args, &mut i, "--evidence-file")?))
            }
            "--session-file" => {
                session_file = PathBuf::from(next_value(args, &mut i, "--session-file")?)
            }
            "--proof-out" => {
                proof_out = Some(PathBuf::from(next_value(args, &mut i, "--proof-out")?))
            }
            "--receipt-out" => {
                receipt_out = Some(PathBuf::from(next_value(args, &mut i, "--receipt-out")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(nightly_check_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(NightlyCheckArgs {
        work_order: work_order.ok_or_else(|| CliError::usage("--work-order is required"))?,
        run,
        evidence_file: evidence_file
            .ok_or_else(|| CliError::usage("--evidence-file is required"))?,
        session_file,
        proof_out,
        receipt_out,
        endpoint,
    })
}

fn parse_nightly_verify_args(
    args: &[String],
    pre_endpoint: Option<String>,
) -> Result<NightlyVerifyArgs, CliError> {
    let mut receipt_file = PathBuf::from("gm-nightly-receipt.json");
    let mut proof_file = None;
    let mut evidence_file = None;
    let mut endpoint = pre_endpoint;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--receipt-file" => {
                receipt_file = PathBuf::from(next_value(args, &mut i, "--receipt-file")?)
            }
            "--proof-file" => {
                proof_file = Some(PathBuf::from(next_value(args, &mut i, "--proof-file")?))
            }
            "--evidence-file" => {
                evidence_file = Some(PathBuf::from(next_value(args, &mut i, "--evidence-file")?))
            }
            "--endpoint" => endpoint = Some(next_value(args, &mut i, "--endpoint")?),
            "--help" | "-h" => return Err(CliError::help(nightly_verify_help())),
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    Ok(NightlyVerifyArgs {
        receipt_file,
        proof_file,
        evidence_file,
        endpoint,
    })
}

async fn cmd_nightly(args: &[String], pre_endpoint: Option<String>) -> Result<i32, CliError> {
    let action = match parse_nightly_action(args, pre_endpoint) {
        Ok(action) => action,
        Err(CliError::Usage(message)) => {
            return Err(CliError::usage(format!("{message}\n\n{}", nightly_help())))
        }
        Err(error) => return Err(error),
    };
    match action {
        NightlyAction::Check(parsed) => cmd_nightly_check(parsed).await,
        NightlyAction::Verify(parsed) => cmd_nightly_verify(parsed).await,
    }
}

async fn cmd_nightly_check(parsed: NightlyCheckArgs) -> Result<i32, CliError> {
    let evidence_bytes_read = fs::read(&parsed.evidence_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "evidence file not found: {}",
                parsed.evidence_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read evidence file {}: {e}",
                parsed.evidence_file.display()
            ))
        }
    })?;
    let evidence_sha256 = sha256_hex(&evidence_bytes_read);
    let evidence_bytes = evidence_bytes_read.len() as u64;

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

    let mut metadata = BTreeMap::new();
    metadata.insert("evidence_bytes".to_string(), evidence_bytes.to_string());
    metadata.insert("evidence_sha256".to_string(), evidence_sha256.clone());
    metadata.insert("kind".to_string(), "nightly".to_string());
    metadata.insert("work_order".to_string(), parsed.work_order.clone());
    if let Some(run) = parsed.run.as_ref() {
        metadata.insert("run".to_string(), run.clone());
    }

    let context = format!("nightly:{}", parsed.work_order);
    let payload = build_payload("NIGHTLY_BUILD", &context, &parsed.work_order, &metadata);
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
            action_type: "NIGHTLY_BUILD".to_string(),
            context: context.clone(),
            target: parsed.work_order.clone(),
            metadata: metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }),
    };

    let mut client = connect(&endpoint).await?;
    let response = client
        .evaluate(Request::new(request))
        .await
        .map_err(|e| CliError::runtime(format!("evaluate RPC failed: {e}")))?
        .into_inner();

    let proof_envelope = response.proof_envelope.as_ref().ok_or_else(|| {
        CliError::runtime("evaluate response did not include a proof envelope")
    })?;
    let proof_path = parsed
        .proof_out
        .clone()
        .unwrap_or_else(|| default_nightly_proof_path(&parsed.session_file));
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
    let receipt_path = parsed
        .receipt_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("gm-nightly-receipt.json"));
    let receipt = NightlyReceipt {
        receipt_version: 1,
        kind: "nightly".to_string(),
        work_order: parsed.work_order.clone(),
        run: parsed.run.clone(),
        evidence_sha256: evidence_sha256.clone(),
        evidence_bytes,
        verdict: response.verdict.clone(),
        reason: response.reason.clone(),
        simulation: false,
        proof: proof.clone(),
        proof_file: proof_path.display().to_string(),
    };
    write_json(&receipt_path, &receipt, false)?;

    let mut out = serde_json::to_value(&receipt).map_err(|e| {
        CliError::runtime(format!("failed to serialize nightly receipt: {e}"))
    })?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "receipt_file".to_string(),
            Value::String(receipt_path.display().to_string()),
        );
    }
    print_json(&out);
    Ok(nightly_check_exit(&response.verdict))
}

async fn cmd_nightly_verify(parsed: NightlyVerifyArgs) -> Result<i32, CliError> {
    let bytes = fs::read(&parsed.receipt_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::runtime(format!(
                "receipt file not found: {}",
                parsed.receipt_file.display()
            ))
        } else {
            CliError::runtime(format!(
                "cannot read receipt file {}: {e}",
                parsed.receipt_file.display()
            ))
        }
    })?;
    let receipt_value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::runtime(format!(
            "invalid receipt file {}: {e}",
            parsed.receipt_file.display()
        ))
    })?;
    let evidence_sha256 = receipt_value
        .get("evidence_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing evidence_sha256 field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let receipt_proof_file = receipt_value
        .get("proof_file")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::runtime(format!(
                "receipt file {} missing proof_file field",
                parsed.receipt_file.display()
            ))
        })?
        .to_string();
    let verdict = receipt_value
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let proof_path = parsed
        .proof_file
        .unwrap_or_else(|| PathBuf::from(receipt_proof_file));
    let proof_file = load_proof(&proof_path)?;
    let envelope = proto_from_proof_file(&proof_file)?;

    let endpoint = resolve_endpoint(parsed.endpoint, None);
    let mut client = connect(&endpoint).await?;
    let response = client
        .verify_proof(Request::new(VerifyProofRequest {
            proof_envelope: Some(envelope),
        }))
        .await
        .map_err(|e| CliError::runtime(format!("verify proof RPC failed: {e}")))?
        .into_inner();

    let evidence_hash_matches: Value = if let Some(path) = parsed.evidence_file.as_ref() {
        let ebytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CliError::runtime(format!("evidence file not found: {}", path.display()))
            } else {
                CliError::runtime(format!("cannot read evidence file {}: {e}", path.display()))
            }
        })?;
        let recomputed = sha256_hex(&ebytes);
        Value::Bool(recomputed == evidence_sha256)
    } else {
        Value::Null
    };

    let out = json!({
        "valid": response.valid,
        "reason": response.reason.clone(),
        "verdict": verdict,
        "evidence_hash_matches": evidence_hash_matches,
        "evidence_sha256": evidence_sha256,
    });
    print_json(&out);
    let hash_bad = matches!(evidence_hash_matches, Value::Bool(false));
    Ok(if response.valid && !hash_bad { 0 } else { 1 })
}

fn nightly_help() -> String {
    r#"gm nightly: nightly build-lane touchpoint (WO-37 / v0.32.0)

USAGE:
  gm nightly <action> [options]

ACTIONS:
  check    Check a nightly build-lane action before it proceeds and write a receipt
  verify   Re-check a saved nightly proof and receipt evidence hash

Exit 0 is the only outcome under which the caller may proceed with the
build dispatch or merge; exit 1 and exit 2 both mean do not proceed.

Run `gm nightly check --help` or `gm nightly verify --help` for details."#
        .to_string()
}

fn nightly_check_help() -> String {
    r#"gm nightly check: evaluate a nightly build-lane action before it proceeds

USAGE:
  gm nightly check --work-order <id> --evidence-file <path> [--run <run-id>]
                   [--session-file <path>] [--proof-out <path>]
                   [--receipt-out <path>] [--endpoint <url>]

Reads the evidence file, computes its SHA-256 itself, and calls a real
Evaluate (never Simulate) for action_type NIGHTLY_BUILD with context
"nightly:<work-order>", the work order as target, and metadata carrying
kind="nightly", work_order, evidence_sha256, evidence_bytes and run when given.
This checks a build dispatch or a merge step in the nightly program before it
proceeds. Saves the sealed proof and a receipt pairing the proof with the
evidence hash, work order and run. This command does not dispatch the build or
perform the merge itself. Simulation is never a nightly check.

Defaults: --proof-out gm-nightly-proof.json beside the session file,
--receipt-out gm-nightly-receipt.json in the current directory.

EXIT CODES:
  0  verdict ALLOW: the receipt was written and the caller may proceed with
     the build dispatch or merge; this is the only outcome under which it may
     do so.
  1  a verdict response arrived and verdict is not ALLOW (BLOCK/THROTTLE/
     ESCALATE): the receipt is still written naming the verdict; do not proceed.
  2  usage, session, transport or RPC error (including a pre-proof block
     delivered as a permission-denied RPC error): nothing is written; do not
     proceed.

OPTIONS:
  --work-order <id>    Work order being gated (required)
  --run <run-id>       Optional nightly run id, recorded in metadata and receipt
  --evidence-file <p>  Evidence file to be hashed (required)
  --session-file <p>   Session file path (default $HOME/.guardian-mesh/gm-session.json)
  --proof-out <p>      Proof file path (default gm-nightly-proof.json beside session)
  --receipt-out <p>    Receipt file path (default gm-nightly-receipt.json)
  --endpoint <url>     Daemon gRPC endpoint (default from session file, then
                       http://127.0.0.1:50051; GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
        .to_string()
}

fn nightly_verify_help() -> String {
    r#"gm nightly verify: verify a nightly proof and receipt evidence hash

USAGE:
  gm nightly verify [--receipt-file <path>] [--proof-file <path>]
                    [--evidence-file <path>] [--endpoint <url>]

Loads the receipt and proof, calls VerifyProof, and optionally recomputes
the SHA-256 of --evidence-file and compares it to the receipt. This checks
the proof with the daemon and the receipt's evidence-hash pairing by
recomputation; it does not require a session.

EXIT CODES:
  0  proof valid and evidence_hash_matches is not false.
  1  proof invalid or evidence hash mismatch.
  2  usage, transport, missing/malformed receipt or proof.

OPTIONS:
  --receipt-file <p>   Receipt file (default gm-nightly-receipt.json)
  --proof-file <p>     Proof file (default: receipt's proof_file)
  --evidence-file <p>  Evidence file to hash-compare against the receipt
  --endpoint <url>     Daemon gRPC endpoint (default http://127.0.0.1:50051;
                       GM_ENDPOINT when the flag is absent)
  --help               Show this help"#
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
        assert!(matches!(&error, CliError::Usage(_)));
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
        assert!(matches!(&error, CliError::Usage(_)));
    }

    #[test]
    fn evaluate_rejects_unknown_flag() {
        let args = ["--nope".to_string()];
        let error = parse_evaluate_args(&args, None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(&error, CliError::Usage(_)));
    }

    fn certificate_issue_args() -> Vec<String> {
        [
            "--product",
            "guardian-mesh",
            "--version",
            "0.28.0",
            "--verdict",
            "PASS WITH FINDINGS",
            "--evidence-file",
            "gate-pack.json",
            "--evidence-scope",
            "full-history",
            "--tests-passed",
            "85",
            "--tests-failed",
            "0",
            "--policy",
            "gate-v1.0.0",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect()
    }

    fn certificate_issue_args_without(flag: &str) -> Vec<String> {
        let args = certificate_issue_args();
        let mut filtered = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if args[i] == flag {
                i += 2;
                continue;
            }
            filtered.push(args[i].clone());
            i += 1;
        }
        filtered
    }

    fn unique_temp_file(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "gm-test-{name}-{}-{nanos}.json",
            std::process::id()
        ));
        path
    }

    #[test]
    fn certificate_issue_parses_all_required_flags() {
        let args = certificate_issue_args();
        let parsed = parse_certificate_issue_args(&args, None).unwrap();
        assert_eq!(parsed.product, "guardian-mesh");
        assert_eq!(parsed.version, "0.28.0");
        assert_eq!(parsed.verdict, "PASS WITH FINDINGS");
        assert_eq!(parsed.evidence_file, PathBuf::from("gate-pack.json"));
        assert_eq!(parsed.evidence_scope, "full-history");
        assert_eq!(parsed.tests_passed, 85);
        assert_eq!(parsed.tests_failed, 0);
        assert_eq!(parsed.policy, "gate-v1.0.0");
        assert_eq!(parsed.cert_out, PathBuf::from("gm-certificate.json"));
        assert_eq!(parsed.endpoint, None);
    }

    #[test]
    fn certificate_issue_requires_each_flag() {
        for flag in [
            "--product",
            "--version",
            "--verdict",
            "--evidence-file",
            "--evidence-scope",
            "--tests-passed",
            "--tests-failed",
            "--policy",
        ] {
            let args = certificate_issue_args_without(flag);
            let error = parse_certificate_issue_args(&args, None).unwrap_err();
            assert_eq!(error.code(), 2, "missing {flag} should exit 2");
            assert!(
                matches!(&error, CliError::Usage(_)),
                "missing {flag} should be a usage error"
            );
            assert!(
                error.message().contains(flag),
                "error should name {flag}: {}",
                error.message()
            );
        }
    }

    #[test]
    fn certificate_issue_rejects_bad_test_count() {
        let mut args = certificate_issue_args();
        let position = args
            .iter()
            .position(|value| value == "--tests-passed")
            .unwrap();
        args[position + 1] = "many".to_string();
        let error = parse_certificate_issue_args(&args, None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(&error, CliError::Usage(_)));
        assert!(error.message().contains("--tests-passed"));
    }

    #[test]
    fn certificate_status_requires_serial() {
        let args = ["--serial".to_string(), "cert-1".to_string()];
        let parsed = parse_certificate_status_args(&args, None).unwrap();
        assert_eq!(parsed.serial, "cert-1");

        let error = parse_certificate_status_args(&[], None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(&error, CliError::Usage(_)));
        assert!(error.message().contains("--serial"));
    }

    #[test]
    fn certificate_verify_defaults_and_parses_cert_file() {
        let parsed = parse_certificate_verify_args(&[], None).unwrap();
        assert_eq!(parsed.cert_file, PathBuf::from("gm-certificate.json"));

        let args = [
            "--cert-file".to_string(),
            "ops/gm-certificate.json".to_string(),
        ];
        let parsed = parse_certificate_verify_args(&args, None).unwrap();
        assert_eq!(parsed.cert_file, PathBuf::from("ops/gm-certificate.json"));
    }

    #[test]
    fn certificate_revoke_requires_serial_and_reason() {
        let args = [
            "--serial".to_string(),
            "cert-1".to_string(),
            "--reason".to_string(),
            "verdict withdrawn".to_string(),
        ];
        let parsed = parse_certificate_revoke_args(&args, None).unwrap();
        assert_eq!(parsed.serial, "cert-1");
        assert_eq!(parsed.reason, "verdict withdrawn");

        for flag in ["--serial", "--reason"] {
            let mut filtered = Vec::new();
            let mut i = 0;
            while i < args.len() {
                if args[i] == flag {
                    i += 2;
                    continue;
                }
                filtered.push(args[i].clone());
                i += 1;
            }
            let error = parse_certificate_revoke_args(&filtered, None).unwrap_err();
            assert_eq!(error.code(), 2);
            assert!(matches!(&error, CliError::Usage(_)));
            assert!(error.message().contains(flag));
        }
    }

    #[test]
    fn certificate_unknown_action_is_usage_error() {
        let error =
            parse_certificate_action(&["frobnicate".to_string()], None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(&error, CliError::Usage(_)));
        assert!(error.message().contains("issue"));
        assert!(error.message().contains("status"));
        assert!(error.message().contains("verify"));
        assert!(error.message().contains("revoke"));

        let error = parse_certificate_action(&[], None).unwrap_err();
        assert_eq!(error.code(), 2);
        assert!(matches!(&error, CliError::Usage(_)));
    }

    #[test]
    fn sha256_hex_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn certificate_file_save_load_round_trip() {
        let path = unique_temp_file("certificate");
        let envelope = ProtoSealedEnvelope {
            payload: b"certificate body bytes".to_vec(),
            payload_type: b"guardian_mesh.Certificate".to_vec(),
            crc32c: 0x1234_abcd,
            ml_dsa_65_signature: vec![9, 8, 7, 6, 5, 4],
            timestamp: 0x00ff_00ff_00ff_00ff,
            nonce: (0u8..32).rev().collect(),
        };

        save_proof(&path, &envelope).unwrap();
        let loaded = load_proof(&path).unwrap();
        let rebuilt = proto_from_proof_file(&loaded).unwrap();
        assert_eq!(rebuilt, envelope);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn certificate_status_name_mapping() {
        assert_eq!(certificate_status_name(0), "UNKNOWN");
        assert_eq!(certificate_status_name(1), "ACTIVE");
        assert_eq!(certificate_status_name(2), "SUPERSEDED");
        assert_eq!(certificate_status_name(3), "REVOKED");
        assert_eq!(certificate_status_name(99), "UNKNOWN");
    }

    fn publish_check_args() -> Vec<String> {
        [
            "--content-file",
            "post.md",
            "--destination",
            "https://example.test/post",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect()
    }

    #[test]
    fn publish_check_requires_content_file_and_destination() {
        let no_content = vec!["--destination".to_string(), "https://x".to_string()];
        let err = parse_publish_check_args(&no_content, None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(err.message().contains("--content-file"));
        let no_dest = vec!["--content-file".to_string(), "a.txt".to_string()];
        let err = parse_publish_check_args(&no_dest, None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(err.message().contains("--destination"));
    }

    #[test]
    fn publish_check_rejects_unknown_flag_and_applies_defaults() {
        let mut args = publish_check_args();
        args.push("--nope".to_string());
        let err = parse_publish_check_args(&args, None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(matches!(&err, CliError::Usage(_)));
        let parsed = parse_publish_check_args(&publish_check_args(), None).unwrap();
        assert_eq!(parsed.channel, "blog");
        assert_eq!(
            parsed.receipt_out,
            None
        );
        let p = parse_publish_action(&["check".to_string(), "--content-file".to_string(), "a".to_string(), "--destination".to_string(), "d".to_string()], None).unwrap();
        match p { PublishAction::Check(c) => assert_eq!(c.channel, "blog"), _ => panic!("expected check") }
    }

    #[test]
    fn publish_action_rejects_unknown() {
        let err = parse_publish_action(&["frobnicate".to_string()], None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(err.message().contains("check"));
        assert!(err.message().contains("verify"));
    }

    #[test]
    fn publish_check_exit_mapping() {
        assert_eq!(publish_check_exit("ALLOW"), 0);
        assert_eq!(publish_check_exit("BLOCK"), 1);
        assert_eq!(publish_check_exit("THROTTLE"), 1);
        assert_eq!(publish_check_exit("ESCALATE"), 1);
        assert_eq!(publish_check_exit("WHATEVER"), 1);
    }

    #[test]
    fn publish_receipt_round_trip_preserves_fields() {
        let receipt = PublishReceipt {
            receipt_version: 1,
            kind: "publish".to_string(),
            content_sha256: sha256_hex(b"hello"),
            content_bytes: 5,
            destination: "https://dest".to_string(),
            channel: "blog".to_string(),
            verdict: "ALLOW".to_string(),
            reason: "ok".to_string(),
            simulation: false,
            proof: json!({"action_id":"PUBLISH","verdict":"ALLOW","timestamp":1,"policy_version":1,"issuing_node":"n"}),
            proof_file: "gm-publish-proof.json".to_string(),
        };
        let path = unique_temp_file("publish-receipt");
        write_json(&path, &receipt, false).unwrap();
        let bytes = fs::read(&path).unwrap();
        let loaded: PublishReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded, receipt);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn content_hash_compare_detects_mismatch() {
        let a = sha256_hex(b"same");
        let b = sha256_hex(b"same");
        let c = sha256_hex(b"sane");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    fn conduit_check_args() -> Vec<String> {
        [
            "--tool",
            "shell",
            "--tenant",
            "acme-example",
            "--args-file",
            "args.json",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect()
    }

    #[test]
    fn conduit_check_requires_tool_tenant_and_args_file() {
        for flag in ["--tool", "--tenant", "--args-file"] {
            let args = conduit_check_args();
            let mut filtered = Vec::new();
            let mut i = 0;
            while i < args.len() {
                if args[i] == flag {
                    i += 2;
                    continue;
                }
                filtered.push(args[i].clone());
                i += 1;
            }
            let err = parse_conduit_check_args(&filtered, None).unwrap_err();
            assert_eq!(err.code(), 2, "missing {flag} should exit 2");
            assert!(matches!(&err, CliError::Usage(_)));
            assert!(
                err.message().contains(flag),
                "error should name {flag}: {}",
                err.message()
            );
        }
    }

    #[test]
    fn conduit_check_rejects_unknown_flag_and_applies_defaults() {
        let mut args = conduit_check_args();
        args.push("--nope".to_string());
        let err = parse_conduit_check_args(&args, None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(matches!(&err, CliError::Usage(_)));
        assert!(err.message().contains("--nope"));

        let parsed = parse_conduit_check_args(&conduit_check_args(), None).unwrap();
        assert_eq!(parsed.tool, "shell");
        assert_eq!(parsed.tenant, "acme-example");
        assert_eq!(parsed.args_file, PathBuf::from("args.json"));
        assert_eq!(parsed.provider, None);
        assert_eq!(parsed.proof_out, None);
        assert_eq!(parsed.receipt_out, None);

        let mut with_provider = conduit_check_args();
        with_provider.extend(["--provider".to_string(), "example-provider".to_string()]);
        let parsed = parse_conduit_check_args(&with_provider, None).unwrap();
        assert_eq!(parsed.provider.as_deref(), Some("example-provider"));

        let verify = parse_conduit_verify_args(&[], None).unwrap();
        assert_eq!(
            verify.receipt_file,
            PathBuf::from("gm-conduit-receipt.json")
        );
        assert_eq!(verify.proof_file, None);
        assert_eq!(verify.args_file, None);
    }

    #[test]
    fn conduit_action_rejects_unknown() {
        let err = parse_conduit_action(&["frobnicate".to_string()], None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(err.message().contains("check"));
        assert!(err.message().contains("verify"));
    }

    #[test]
    fn conduit_check_exit_mapping() {
        assert_eq!(conduit_check_exit("ALLOW"), 0);
        assert_eq!(conduit_check_exit("BLOCK"), 1);
        assert_eq!(conduit_check_exit("THROTTLE"), 1);
        assert_eq!(conduit_check_exit("ESCALATE"), 1);
        assert_eq!(conduit_check_exit("WHATEVER"), 1);
    }

    #[test]
    fn conduit_receipt_round_trip_preserves_fields() {
        let receipt = ConduitReceipt {
            receipt_version: 1,
            kind: "conduit".to_string(),
            tenant: "acme-example".to_string(),
            tool: "shell".to_string(),
            provider: Some("example-provider".to_string()),
            args_sha256: sha256_hex(b"hello"),
            args_bytes: 5,
            verdict: "ALLOW".to_string(),
            reason: "ok".to_string(),
            simulation: false,
            proof: json!({"action_id":"TOOL_CALL","verdict":"ALLOW","timestamp":1,"policy_version":1,"issuing_node":"n"}),
            proof_file: "gm-conduit-proof.json".to_string(),
        };
        let path = unique_temp_file("conduit-receipt");
        write_json(&path, &receipt, false).unwrap();
        let bytes = fs::read(&path).unwrap();
        let loaded: ConduitReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded, receipt);

        let absent_provider = ConduitReceipt {
            provider: None,
            ..receipt
        };
        let value = serde_json::to_value(&absent_provider).unwrap();
        assert_eq!(value["provider"], Value::Null);
        let _ = fs::remove_file(&path);
    }

    fn repo_check_args() -> Vec<String> {
        [
            "--repo",
            "example-owner/example-repo",
            "--commit",
            "0000000000000000000000000000000000000000",
            "--evidence-file",
            "evidence.json",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect()
    }

    #[test]
    fn repo_check_requires_repo_commit_and_evidence_file() {
        for flag in ["--repo", "--commit", "--evidence-file"] {
            let args = repo_check_args();
            let mut filtered = Vec::new();
            let mut i = 0;
            while i < args.len() {
                if args[i] == flag {
                    i += 2;
                    continue;
                }
                filtered.push(args[i].clone());
                i += 1;
            }
            let err = parse_repo_check_args(&filtered, None).unwrap_err();
            assert_eq!(err.code(), 2, "missing {flag} should exit 2");
            assert!(matches!(&err, CliError::Usage(_)));
            assert!(
                err.message().contains(flag),
                "error should name {flag}: {}",
                err.message()
            );
        }
    }

    #[test]
    fn repo_check_rejects_unknown_flag_and_applies_defaults() {
        let mut args = repo_check_args();
        args.push("--nope".to_string());
        let err = parse_repo_check_args(&args, None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(matches!(&err, CliError::Usage(_)));
        assert!(err.message().contains("--nope"));

        let parsed = parse_repo_check_args(&repo_check_args(), None).unwrap();
        assert_eq!(parsed.repo, "example-owner/example-repo");
        assert_eq!(
            parsed.commit,
            "0000000000000000000000000000000000000000"
        );
        assert_eq!(parsed.evidence_file, PathBuf::from("evidence.json"));
        assert_eq!(parsed.branch, None);
        assert_eq!(parsed.proof_out, None);
        assert_eq!(parsed.receipt_out, None);

        let mut with_branch = repo_check_args();
        with_branch.extend(["--branch".to_string(), "main".to_string()]);
        let parsed = parse_repo_check_args(&with_branch, None).unwrap();
        assert_eq!(parsed.branch.as_deref(), Some("main"));

        let verify = parse_repo_verify_args(&[], None).unwrap();
        assert_eq!(
            verify.receipt_file,
            PathBuf::from("gm-repo-receipt.json")
        );
        assert_eq!(verify.proof_file, None);
        assert_eq!(verify.evidence_file, None);
    }

    #[test]
    fn repo_action_rejects_unknown() {
        let err = parse_repo_action(&["frobnicate".to_string()], None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(err.message().contains("check"));
        assert!(err.message().contains("verify"));
    }

    #[test]
    fn repo_check_exit_mapping() {
        assert_eq!(repo_check_exit("ALLOW"), 0);
        assert_eq!(repo_check_exit("BLOCK"), 1);
        assert_eq!(repo_check_exit("THROTTLE"), 1);
        assert_eq!(repo_check_exit("ESCALATE"), 1);
        assert_eq!(repo_check_exit("WHATEVER"), 1);
    }

    #[test]
    fn repo_receipt_round_trip_preserves_fields() {
        let receipt = RepoReceipt {
            receipt_version: 1,
            kind: "repo".to_string(),
            repo: "example-owner/example-repo".to_string(),
            commit: "0000000000000000000000000000000000000000".to_string(),
            branch: Some("main".to_string()),
            evidence_sha256: sha256_hex(b"hello"),
            evidence_bytes: 5,
            verdict: "ALLOW".to_string(),
            reason: "ok".to_string(),
            simulation: false,
            proof: json!({"action_id":"REPO_RELEASE","verdict":"ALLOW","timestamp":1,"policy_version":1,"issuing_node":"n"}),
            proof_file: "gm-repo-proof.json".to_string(),
        };
        let path = unique_temp_file("repo-receipt");
        write_json(&path, &receipt, false).unwrap();
        let bytes = fs::read(&path).unwrap();
        let loaded: RepoReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded, receipt);

        let absent_branch = RepoReceipt {
            branch: None,
            ..receipt
        };
        let value = serde_json::to_value(&absent_branch).unwrap();
        assert_eq!(value["branch"], Value::Null);
        let _ = fs::remove_file(&path);
    }

    fn nightly_check_args() -> Vec<String> {
        [
            "--work-order",
            "WO-37-T5",
            "--evidence-file",
            "evidence.json",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect()
    }

    #[test]
    fn nightly_check_requires_work_order_and_evidence_file() {
        for flag in ["--work-order", "--evidence-file"] {
            let args = nightly_check_args();
            let mut filtered = Vec::new();
            let mut i = 0;
            while i < args.len() {
                if args[i] == flag {
                    i += 2;
                    continue;
                }
                filtered.push(args[i].clone());
                i += 1;
            }
            let err = parse_nightly_check_args(&filtered, None).unwrap_err();
            assert_eq!(err.code(), 2, "missing {flag} should exit 2");
            assert!(matches!(&err, CliError::Usage(_)));
            assert!(
                err.message().contains(flag),
                "error should name {flag}: {}",
                err.message()
            );
        }
    }

    #[test]
    fn nightly_check_rejects_unknown_flag_and_applies_defaults() {
        let mut args = nightly_check_args();
        args.push("--nope".to_string());
        let err = parse_nightly_check_args(&args, None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(matches!(&err, CliError::Usage(_)));
        assert!(err.message().contains("--nope"));

        let parsed = parse_nightly_check_args(&nightly_check_args(), None).unwrap();
        assert_eq!(parsed.work_order, "WO-37-T5");
        assert_eq!(parsed.evidence_file, PathBuf::from("evidence.json"));
        assert_eq!(parsed.run, None);
        assert_eq!(parsed.proof_out, None);
        assert_eq!(parsed.receipt_out, None);

        let mut with_run = nightly_check_args();
        with_run.extend(["--run".to_string(), "nightly-1".to_string()]);
        let parsed = parse_nightly_check_args(&with_run, None).unwrap();
        assert_eq!(parsed.run.as_deref(), Some("nightly-1"));

        let verify = parse_nightly_verify_args(&[], None).unwrap();
        assert_eq!(
            verify.receipt_file,
            PathBuf::from("gm-nightly-receipt.json")
        );
        assert_eq!(verify.proof_file, None);
        assert_eq!(verify.evidence_file, None);
    }

    #[test]
    fn nightly_action_rejects_unknown() {
        let err = parse_nightly_action(&["frobnicate".to_string()], None).unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(err.message().contains("check"));
        assert!(err.message().contains("verify"));
    }

    #[test]
    fn nightly_check_exit_mapping() {
        assert_eq!(nightly_check_exit("ALLOW"), 0);
        assert_eq!(nightly_check_exit("BLOCK"), 1);
        assert_eq!(nightly_check_exit("THROTTLE"), 1);
        assert_eq!(nightly_check_exit("ESCALATE"), 1);
        assert_eq!(nightly_check_exit("WHATEVER"), 1);
    }

    #[test]
    fn nightly_receipt_round_trip_preserves_fields() {
        let receipt = NightlyReceipt {
            receipt_version: 1,
            kind: "nightly".to_string(),
            work_order: "WO-37-T5".to_string(),
            run: Some("nightly-1".to_string()),
            evidence_sha256: sha256_hex(b"hello"),
            evidence_bytes: 5,
            verdict: "ALLOW".to_string(),
            reason: "ok".to_string(),
            simulation: false,
            proof: json!({"action_id":"NIGHTLY_BUILD","verdict":"ALLOW","timestamp":1,"policy_version":1,"issuing_node":"n"}),
            proof_file: "gm-nightly-proof.json".to_string(),
        };
        let path = unique_temp_file("nightly-receipt");
        write_json(&path, &receipt, false).unwrap();
        let bytes = fs::read(&path).unwrap();
        let loaded: NightlyReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded, receipt);

        let absent_run = NightlyReceipt {
            run: None,
            ..receipt
        };
        let value = serde_json::to_value(&absent_run).unwrap();
        assert_eq!(value["run"], Value::Null);
        let reparsed: NightlyReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(reparsed.run, None);
        let _ = fs::remove_file(&path);
    }

}
