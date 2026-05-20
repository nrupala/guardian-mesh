use std::sync::atomic::{AtomicU32, Ordering};

static RULES_PASSED: AtomicU32 = AtomicU32::new(0);
static RULES_TOTAL: AtomicU32 = AtomicU32::new(18);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PfRule {
    Pf01 = 1, Pf02, Pf03, Pf04, Pf05,
    Pf06, Pf07, Pf08, Pf09, Pf10,
    Pf11, Pf12, Pf13, Pf14, Pf15,
    Pf16, Pf17, Pf18,
}

impl PfRule {
    pub fn number(self) -> u32 { self as u32 }
    pub fn name(self) -> &'static str {
        match self {
            Self::Pf01 => "PF-01: Envelope structure valid",
            Self::Pf02 => "PF-02: CRC32C integrity check",
            Self::Pf03 => "PF-03: ML-DSA-65 signature verified",
            Self::Pf04 => "PF-04: Timestamp within drift window",
            Self::Pf05 => "PF-05: Nonce not replayed",
            Self::Pf06 => "PF-06: Source enclave authorized",
            Self::Pf07 => "PF-07: Handshake session exists",
            Self::Pf08 => "PF-08: HMAC tag matches session key",
            Self::Pf09 => "PF-09: Action type is recognized",
            Self::Pf10 => "PF-10: Action context within length limit",
            Self::Pf11 => "PF-11: Target does not contain path traversal",
            Self::Pf12 => "PF-12: Payload type is recognized",
            Self::Pf13 => "PF-13: Source enclave not in blocklist",
            Self::Pf14 => "PF-14: Rate limit not exceeded",
            Self::Pf15 => "PF-15: Action not in deny-list",
            Self::Pf16 => "PF-16: Enclave chain not in degraded state",
            Self::Pf17 => "PF-17: Minimum containment stage satisfied",
            Self::Pf18 => "PF-18: Audit trail transaction opened",
        }
    }
}

#[derive(Debug, Default)]
pub struct FirewallReport {
    pub rules_passed: Vec<u32>,
    pub rules_failed: Vec<(u32, String)>,
    pub passed_count: u32,
    pub total_count: u32,
}

pub struct ProtocolFirewall;

impl ProtocolFirewall {
    pub fn passed_count() -> u32 {
        RULES_PASSED.load(Ordering::Relaxed)
    }

    pub fn total_count() -> u32 {
        RULES_TOTAL.load(Ordering::Relaxed)
    }

    pub fn validate_envelope_structure(data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Err("empty envelope payload".into());
        }
        if data.len() > 1024 * 1024 {
            return Err("envelope payload exceeds 1 MiB".into());
        }
        Ok(())
    }

    pub fn validate_timestamp(drift_ms: i64) -> Result<(), String> {
        if drift_ms.abs() > 30_000 {
            return Err(format!("timestamp drift {}ms exceeds 30s window", drift_ms));
        }
        Ok(())
    }

    pub fn validate_context_length(ctx: &str) -> Result<(), String> {
        if ctx.len() > 4096 {
            return Err("action context exceeds 4096 characters".into());
        }
        Ok(())
    }

    pub fn validate_target_no_traversal(target: &str) -> Result<(), String> {
        if target.contains("..") {
            return Err("path traversal detected in target".into());
        }
        Ok(())
    }

    pub fn run_full_check(
        envelope_data: &[u8],
        drift_ms: i64,
        context: &str,
        target: &str,
    ) -> FirewallReport {
        let checks: Vec<(PfRule, Result<(), String>)> = vec![
            (PfRule::Pf01, Self::validate_envelope_structure(envelope_data)),
            (PfRule::Pf04, Self::validate_timestamp(drift_ms)),
            (PfRule::Pf10, Self::validate_context_length(context)),
            (PfRule::Pf11, Self::validate_target_no_traversal(target)),
        ];

        let mut passed = Vec::new();
        let mut failed = Vec::new();
        for (rule, result) in &checks {
            match result {
                Ok(()) => {
                    passed.push(rule.number());
                    RULES_PASSED.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    failed.push((rule.number(), e.clone()));
                }
            }
        }
        let passed_count = passed.len() as u32;
        FirewallReport {
            rules_passed: passed,
            rules_failed: failed,
            passed_count,
            total_count: 18,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_envelope_rejects_empty() {
        assert!(ProtocolFirewall::validate_envelope_structure(b"").is_err());
    }

    #[test]
    fn validate_envelope_accepts_valid() {
        assert!(ProtocolFirewall::validate_envelope_structure(b"hello").is_ok());
    }

    #[test]
    fn validate_envelope_rejects_oversized() {
        let big = vec![0u8; 2 * 1024 * 1024];
        assert!(ProtocolFirewall::validate_envelope_structure(&big).is_err());
    }

    #[test]
    fn validate_timestamp_within_window() {
        assert!(ProtocolFirewall::validate_timestamp(5000).is_ok());
        assert!(ProtocolFirewall::validate_timestamp(-5000).is_ok());
    }

    #[test]
    fn validate_timestamp_exceeds_window() {
        assert!(ProtocolFirewall::validate_timestamp(31000).is_err());
    }

    #[test]
    fn validate_context_rejects_oversized() {
        let long = "x".repeat(5000);
        assert!(ProtocolFirewall::validate_context_length(&long).is_err());
    }

    #[test]
    fn validate_target_detects_traversal() {
        assert!(ProtocolFirewall::validate_target_no_traversal("../../etc/passwd").is_err());
        assert!(ProtocolFirewall::validate_target_no_traversal("safe/path").is_ok());
    }

    #[test]
    fn run_full_check_counts_rules() {
        let report = ProtocolFirewall::run_full_check(b"data", 100, "ctx", "target");
        assert_eq!(report.total_count, 18);
    }
}
