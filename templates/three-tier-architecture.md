# Three-Tier Directory Architecture

A defensive directory layout that **never** lets a program write into its own source tree.

## The Three Tiers

```
┌─────────────────────────────────────────────────────────┐
│                   1. PROGRAM DIR                         │
│   Read-only at runtime. Contains source code, build     │
│   files, config templates. NEVER written to by the      │
│   running application.                                  │
│   Example: /opt/myapp, D:\project\src                   │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │ never writes
                          │
┌─────────────────────────────────────────────────────────┐
│                  2. WORKSPACE DIR                        │
│   Per-instance runtime data. Survives restarts.         │
│   Contains: audit logs, session state, keys, caches.   │
│   Example: /var/lib/myapp, D:\data\workspace           │
│   Subdirs: audit/ sessions/ keys/ projects/             │
└─────────────────────────────────────────────────────────┘
                          ▲
                          │
                          │
┌─────────────────────────────────────────────────────────┐
│                   3. OUTPUT DIR                          │
│   Per-project generated output. NEVER overwritten —     │
│   each run gets a timestamped folder.                   │
│   Example: /var/output/myapp, D:\data\output           │
│   Layout: {project}/run_{nanos}/                        │
└─────────────────────────────────────────────────────────┘
```

## Guardrails

- **Startup assertion**: the program canonicalizes its own path and checks
  that neither workspace_dir nor output_dir is a prefix-match child of
  program_dir. If they are, the process `exit(1)`s before touching disk.

- **Env-var overrides**: `WORKSPACE_DIR`, `OUTPUT_DIR`, `BIND_ADDR`, `PORT`
  can be set at runtime. Hardcoded defaults point to system-standard
  locations (`/var/lib/...`, `/var/output/...`).

- **`ensure_dirs()`**: called on startup — creates all sub-directories
  (audit, sessions, keys, output) before any method runs.

- **`create_run_output_dir(project)`**: creates `{output}/{project}/run_{ts}/`
  with a nanosecond timestamp, guaranteeing no two runs share an output
  folder. No file is ever overwritten.

## Reference Implementation (Rust)

### Config struct

```rust
pub struct Config {
    pub workspace_dir: String,   // tier 2
    pub output_dir: String,      // tier 3
    pub program_dir: String,     // tier 1 (default: ".")
}
```

### Sub-directory helpers

```rust
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
    pub fn project_output_dir(&self, project: &str) -> PathBuf {
        Path::new(&self.output_dir).join(sanitize(project))
    }
    pub fn create_run_output_dir(&self, project: &str) -> io::Result<PathBuf> {
        let ts = SystemTime::now()…;
        let dir = self.project_output_dir(project).join(format!("run_{}", ts));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}
```

### Startup guard

```rust
fn verify_no_program_dir_write(&self) -> Result<(), String> {
    let prog = Path::new(&self.program_dir).canonicalize()?;
    if Path::new(&self.workspace_dir).starts_with(&prog) { /* reject */ }
    if Path::new(&self.output_dir).starts_with(&prog)    { /* reject */ }
    Ok(())
}

fn main() {
    config.ensure_dirs()?;
    config.verify_no_program_dir_write()?;
    // … start serving …
}
```

## Usage Template

Copy the following files to start a new project with this architecture:

- `src/config.rs`  — Config struct with env-var support and dir helpers
- `src/main.rs`    — Startup flow: `ensure_dirs()` → `verify_no_program_dir_write()` → serve

### Required dependencies (Cargo.toml)

```toml
# No extra dependencies needed — uses std::fs and std::path only.
```

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `WORKSPACE_DIR` | `/var/lib/{app}` | Runtime data (audit, sessions, keys) |
| `OUTPUT_DIR` | `/var/output/{app}` | Generated output per project |
| `BIND_ADDR` | `127.0.0.1` | Listen address |
| `PORT` | `50051` | Listen port |

---

*This template is part of the Guardian Mesh project (D:\guardian-mesh\).*
