// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

pub const DEFAULT_HANDSHAKE_SECRET: &[u8] = b"guardian-mesh-handshake-secret-2026";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    Production,
    Demo,
}

impl Posture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Posture::Production => "production",
            Posture::Demo => "demo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureFinding {
    pub setting: String,
    pub blocking: bool,
    pub message: String,
}

pub struct Config {
    pub bind_addr: String,
    pub bind_port: u16,
    pub handshake_secret: Vec<u8>,
    pub ml_dsa_secret_key: Vec<u8>,
    pub ml_dsa_public_key: Vec<u8>,
    pub policy_rules_path: Option<String>,
    pub enclave_timeout_ms: u64,
    pub workspace_dir: String,
    pub output_dir: String,
    pub program_dir: String,
    pub policy_throttle_rate: usize,
    pub policy_escalate_actions: Vec<String>,
    pub policy_admin_keys_dir: Option<String>,
    pub revocation_bound_secs: u64,
    pub spiffe_trust_domains: Vec<String>,
    pub spiffe_required: bool,
    pub pgp_admin_keys_dir: Option<String>,
    pub tenants: Vec<String>,
    pub tenant_rate_budget: u64,
    pub tenant_budget_window_ms: u64,
    pub node_id: Option<String>,
    pub degraded: bool,
    pub degraded_safe_actions: Vec<String>,
    pub posture: Posture,
    pub posture_env_invalid: Option<String>,
    pub handshake_secret_is_default: bool,
}

impl Config {
    pub fn audit_dir(&self) -> PathBuf {
        Path::new(&self.workspace_dir).join("audit")
    }

    pub fn sessions_dir(&self) -> PathBuf {
        Path::new(&self.workspace_dir).join("sessions")
    }

    pub fn keys_dir(&self) -> PathBuf {
        Path::new(&self.workspace_dir).join("keys")
    }

    pub fn policy_dir(&self) -> PathBuf {
        Path::new(&self.workspace_dir).join("policy")
    }

    pub fn revocation_dir(&self) -> PathBuf {
        Path::new(&self.workspace_dir).join("revocation")
    }

    pub fn project_output_dir(&self, project_name: &str) -> PathBuf {
        Path::new(&self.output_dir).join(sanitize(project_name))
    }

    pub fn create_project_output_dir(&self, project_name: &str) -> std::io::Result<PathBuf> {
        let dir = self.project_output_dir(project_name);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn create_run_output_dir(&self, project_name: &str) -> std::io::Result<PathBuf> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = self.project_output_dir(project_name).join(format!("run_{}", ts));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.workspace_dir)?;
        std::fs::create_dir_all(&self.output_dir)?;
        std::fs::create_dir_all(self.audit_dir())?;
        std::fs::create_dir_all(self.sessions_dir())?;
        std::fs::create_dir_all(self.keys_dir())?;
        std::fs::create_dir_all(self.policy_dir())?;
        std::fs::create_dir_all(self.revocation_dir())?;
        Ok(())
    }

    pub fn verify_no_program_dir_write(&self) -> Result<(), String> {
        let prog = Path::new(&self.program_dir)
            .canonicalize()
            .map_err(|e| format!("program_dir '{}' invalid: {}", self.program_dir, e))?;

        let prog_str = prog.to_string_lossy().replace('\\', "/");
        let ws_str = Path::new(&self.workspace_dir)
            .to_string_lossy()
            .replace('\\', "/");
        let out_str = Path::new(&self.output_dir)
            .to_string_lossy()
            .replace('\\', "/");

        if ws_str.starts_with(&prog_str) {
            return Err(format!(
                "workspace_dir '{}' is inside program_dir '{}'",
                self.workspace_dir, self.program_dir
            ));
        }
        if out_str.starts_with(&prog_str) {
            return Err(format!(
                "output_dir '{}' is inside program_dir '{}'",
                self.output_dir, self.program_dir
            ));
        }
        Ok(())
    }

    pub fn posture_findings(&self) -> Vec<PostureFinding> {
        let mut findings = Vec::new();

        if let Some(invalid) = &self.posture_env_invalid {
            findings.push(PostureFinding {
                setting: "GUARDIAN_MESH_POSTURE".to_string(),
                blocking: true,
                message: format!(
                    "invalid posture value '{}'; accepted values are 'production' and 'demo'",
                    invalid
                ),
            });
        }

        if self.handshake_secret_is_default {
            findings.push(PostureFinding {
                setting: "GUARDIAN_MESH_HANDSHAKE_SECRET".to_string(),
                blocking: self.posture == Posture::Production,
                message: "the daemon is using the built-in default handshake secret, which is public in the source code; set GUARDIAN_MESH_HANDSHAKE_SECRET to a deployment-specific value (demo posture permits the default for local demonstration only)".to_string(),
            });
        } else if self.handshake_secret.len() < 16 {
            findings.push(PostureFinding {
                setting: "GUARDIAN_MESH_HANDSHAKE_SECRET".to_string(),
                blocking: false,
                message: format!(
                    "handshake secret is only {} bytes long; use at least 16 bytes",
                    self.handshake_secret.len()
                ),
            });
        }

        if self.posture == Posture::Production
            && matches!(self.bind_addr.as_str(), "0.0.0.0" | "::")
        {
            findings.push(PostureFinding {
                setting: "GUARDIAN_MESH_BIND_ADDR".to_string(),
                blocking: false,
                message: format!(
                    "production posture is binding to non-loopback address '{}'; gate access in front of the daemon or bind to loopback",
                    self.bind_addr
                ),
            });
        }

        if self.posture == Posture::Production && self.degraded {
            findings.push(PostureFinding {
                setting: "GUARDIAN_MESH_DEGRADED".to_string(),
                blocking: false,
                message: "degraded mode is active in production posture; only the pre-declared safe action subset is permitted".to_string(),
            });
        }

        if self.posture == Posture::Production && !self.spiffe_required {
            findings.push(PostureFinding {
                setting: "GUARDIAN_MESH_REQUIRE_SPIFFE".to_string(),
                blocking: false,
                message: "SPIFFE attestation is not required in production posture; set GUARDIAN_MESH_REQUIRE_SPIFFE=1 to require SVID attestation at handshake".to_string(),
            });
        }

        findings
    }

    pub fn validate_posture(&self) -> Result<(), Vec<PostureFinding>> {
        let blocking: Vec<PostureFinding> = self
            .posture_findings()
            .into_iter()
            .filter(|finding| finding.blocking)
            .collect();
        if blocking.is_empty() {
            Ok(())
        } else {
            Err(blocking)
        }
    }
}

fn parse_posture(value: Option<&str>) -> (Posture, Option<String>) {
    match value {
        None => (Posture::Production, None),
        Some(raw) if raw.eq_ignore_ascii_case("production") => (Posture::Production, None),
        Some(raw) if raw.eq_ignore_ascii_case("demo") => (Posture::Demo, None),
        Some(raw) => (Posture::Production, Some(raw.to_string())),
    }
}

fn resolve_handshake_secret(value: Option<&str>) -> (Vec<u8>, bool) {
    match value {
        None => (DEFAULT_HANDSHAKE_SECRET.to_vec(), true),
        Some(raw) => {
            let secret = raw.as_bytes().to_vec();
            let is_default =
                secret.is_empty() || secret.as_slice() == DEFAULT_HANDSHAKE_SECRET;
            (secret, is_default)
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let ws = std::env::var("GUARDIAN_MESH_WORKSPACE")
            .unwrap_or_else(|_| "guardian-mesh-data/workspace".into());
        let out = std::env::var("GUARDIAN_MESH_OUTPUT")
            .unwrap_or_else(|_| "guardian-mesh-data/output".into());
        let posture_raw = std::env::var("GUARDIAN_MESH_POSTURE").ok();
        let (posture, posture_env_invalid) = parse_posture(posture_raw.as_deref());
        let secret_raw = std::env::var("GUARDIAN_MESH_HANDSHAKE_SECRET").ok();
        let (handshake_secret, handshake_secret_is_default) =
            resolve_handshake_secret(secret_raw.as_deref());
        
        let policy_throttle_rate = std::env::var("GUARDIAN_MESH_POLICY_THROTTLE_RATE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        
        let policy_escalate_actions = std::env::var("GUARDIAN_MESH_POLICY_ESCALATE_ACTIONS")
            .ok()
            .map(|s| s.split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect())
            .unwrap_or_default();
        
        let policy_admin_keys_dir = std::env::var("GUARDIAN_MESH_POLICY_ADMIN_KEYS_DIR").ok();
        
        let revocation_bound_secs = std::env::var("GUARDIAN_MESH_REVOCATION_BOUND_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        let revocation_bound_secs = if revocation_bound_secs == 0 { 60 } else { revocation_bound_secs };
        
        let spiffe_trust_domains = std::env::var("GUARDIAN_MESH_SPIFFE_TRUST_DOMAINS")
            .ok()
            .map(|s| s.split(',').map(|d| d.trim().to_string()).filter(|d| !d.is_empty()).collect())
            .unwrap_or_default();
        
        let spiffe_required = std::env::var("GUARDIAN_MESH_REQUIRE_SPIFFE")
            .ok()
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);
        
        let pgp_admin_keys_dir = std::env::var("GUARDIAN_MESH_PGP_ADMIN_KEYS_DIR").ok();
        
        let tenants = std::env::var("GUARDIAN_MESH_TENANTS")
            .ok()
            .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
            .unwrap_or_default();
        
        let tenant_rate_budget = std::env::var("GUARDIAN_MESH_TENANT_RATE_BUDGET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(policy_throttle_rate as u64);

        // WO-15.1 (Wright carry): the tenant budget is a RATE budget —
        // its limit applies per sliding window, not over the daemon's
        // lifetime. The window defaults to the PF-18 / policy-rate
        // window (1s), the window the default limit is derived from.
        let tenant_budget_window_ms = std::env::var("GUARDIAN_MESH_TENANT_BUDGET_WINDOW_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&v| v > 0)
            .unwrap_or(1000);

        let node_id = std::env::var("GUARDIAN_MESH_NODE_ID").ok();

        let degraded = std::env::var("GUARDIAN_MESH_DEGRADED")
            .ok()
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);

        let degraded_safe_actions = std::env::var("GUARDIAN_MESH_DEGRADED_SAFE_ACTIONS")
            .ok()
            .map(|s| s.split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect())
            .unwrap_or_default();
        
        Self {
            bind_addr: std::env::var("GUARDIAN_MESH_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".into()),
            bind_port: std::env::var("GUARDIAN_MESH_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or_else(find_free_port),
            handshake_secret,
            handshake_secret_is_default,
            ml_dsa_secret_key: Vec::new(),
            ml_dsa_public_key: Vec::new(),
            policy_rules_path: None,
            enclave_timeout_ms: 5000,
            workspace_dir: ws,
            output_dir: out,
            program_dir: ".".into(),
            policy_throttle_rate,
            policy_escalate_actions,
            policy_admin_keys_dir,
            revocation_bound_secs,
            spiffe_trust_domains,
            spiffe_required,
            pgp_admin_keys_dir,
            tenants,
            tenant_rate_budget,
            tenant_budget_window_ms,
            node_id,
            degraded,
            degraded_safe_actions,
            posture,
            posture_env_invalid,
        }
    }
}

pub fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(51051)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CUSTOM_SECRET: &[u8] = b"deployment-specific-secret-2026";

    fn secret_is_default(secret: &[u8]) -> bool {
        secret.is_empty() || secret == DEFAULT_HANDSHAKE_SECRET
    }

    fn config_with(posture: Posture, secret: &[u8]) -> Config {
        Config {
            posture,
            posture_env_invalid: None,
            handshake_secret: secret.to_vec(),
            handshake_secret_is_default: secret_is_default(secret),
            bind_addr: "127.0.0.1".to_string(),
            degraded: false,
            spiffe_required: false,
            ..Config::default()
        }
    }

    #[test]
    fn posture_parsing_defaults_to_production() {
        assert_eq!(parse_posture(None), (Posture::Production, None));
        assert_eq!(
            parse_posture(Some("production")),
            (Posture::Production, None)
        );
        assert_eq!(
            parse_posture(Some("PRODUCTION")),
            (Posture::Production, None)
        );
        assert_eq!(parse_posture(Some("demo")), (Posture::Demo, None));
        assert_eq!(parse_posture(Some("DEMO")), (Posture::Demo, None));
        assert_eq!(
            parse_posture(Some("staging")),
            (Posture::Production, Some("staging".to_string()))
        );
    }

    #[test]
    fn default_secret_detection_covers_unset_empty_literal_and_custom() {
        assert_eq!(
            resolve_handshake_secret(None),
            (DEFAULT_HANDSHAKE_SECRET.to_vec(), true)
        );
        assert_eq!(resolve_handshake_secret(Some("")), (Vec::new(), true));
        assert_eq!(
            resolve_handshake_secret(Some("guardian-mesh-handshake-secret-2026")),
            (DEFAULT_HANDSHAKE_SECRET.to_vec(), true)
        );
        assert_eq!(
            resolve_handshake_secret(Some("custom-deployment-secret")),
            (b"custom-deployment-secret".to_vec(), false)
        );
    }

    #[test]
    fn validate_blocks_production_with_default_secret() {
        let config = config_with(Posture::Production, DEFAULT_HANDSHAKE_SECRET);
        let findings = config.validate_posture().unwrap_err();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].blocking);
        assert_eq!(findings[0].setting, "GUARDIAN_MESH_HANDSHAKE_SECRET");
        assert!(config
            .posture_findings()
            .iter()
            .any(|finding| finding.setting == "GUARDIAN_MESH_HANDSHAKE_SECRET" && finding.blocking));
    }

    #[test]
    fn validate_passes_production_with_custom_secret() {
        let config = config_with(Posture::Production, CUSTOM_SECRET);

        assert!(config.validate_posture().is_ok());
        assert!(!config
            .posture_findings()
            .iter()
            .any(|finding| finding.blocking));
    }

    #[test]
    fn demo_allows_default_secret_but_still_names_it() {
        let config = config_with(Posture::Demo, DEFAULT_HANDSHAKE_SECRET);

        assert!(config.validate_posture().is_ok());
        let findings = config.posture_findings();
        let default_finding = findings
            .iter()
            .find(|finding| finding.setting == "GUARDIAN_MESH_HANDSHAKE_SECRET")
            .expect("demo posture must still name the default secret");
        assert!(!default_finding.blocking);
    }

    #[test]
    fn invalid_posture_blocks_in_demo_too() {
        let mut config = config_with(Posture::Demo, CUSTOM_SECRET);
        config.posture_env_invalid = Some("staging".to_string());

        let findings = config.validate_posture().unwrap_err();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].setting, "GUARDIAN_MESH_POSTURE");
        assert!(findings[0].blocking);
        assert!(findings[0].message.contains("staging"));
    }

    #[test]
    fn short_custom_secret_is_a_non_blocking_warning_naming_only_length() {
        let config = config_with(Posture::Production, b"short");
        let findings = config.posture_findings();
        let short = findings
            .iter()
            .find(|finding| finding.setting == "GUARDIAN_MESH_HANDSHAKE_SECRET")
            .expect("short secret must be named");

        assert!(!short.blocking);
        assert!(short.message.contains("5 bytes"));
        assert!(!short.message.contains("short"));
    }
}
