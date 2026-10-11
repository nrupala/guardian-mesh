// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::{Path, PathBuf};

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
}

impl Default for Config {
    fn default() -> Self {
        let ws = std::env::var("GUARDIAN_MESH_WORKSPACE")
            .unwrap_or_else(|_| "guardian-mesh-data/workspace".into());
        let out = std::env::var("GUARDIAN_MESH_OUTPUT")
            .unwrap_or_else(|_| "guardian-mesh-data/output".into());
        let secret_env = std::env::var("GUARDIAN_MESH_HANDSHAKE_SECRET")
            .ok()
            .map(|s| s.into_bytes())
            .unwrap_or_else(|| b"guardian-mesh-handshake-secret-2026".to_vec());
        Self {
            bind_addr: std::env::var("GUARDIAN_MESH_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".into()),
            bind_port: std::env::var("GUARDIAN_MESH_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or_else(find_free_port),
            handshake_secret: secret_env,
            ml_dsa_secret_key: Vec::new(),
            ml_dsa_public_key: Vec::new(),
            policy_rules_path: None,
            enclave_timeout_ms: 5000,
            workspace_dir: ws,
            output_dir: out,
            program_dir: ".".into(),
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
