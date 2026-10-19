// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

//! Protocol Firewall — enforces PF-1..PF-18 from the formal spec §1.4
//! on the Evaluate path for client envelopes.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum envelope size per spec: 16-byte header + 65540 bytes payload/routing = 65556 bytes.
/// For client envelopes we check the payload field within the protobuf message.
const ENVELOPE_SIZE_LIMIT: usize = 64 * 1024; // 64 KiB per spec section 1.4 PF-1

/// ML-DSA-65 signature valid length range per spec PF-17
const ML_DSA_65_SIG_MIN: usize = 2420;
const ML_DSA_65_SIG_MAX: usize = 3500;

/// Maximum nesting depth for JSON payloads per spec PF-13
const MAX_NESTING_DEPTH: usize = 4;

/// Nonce sliding window size per session per spec PF-14
const NONCE_WINDOW_SIZE: usize = 10_000;

/// Timestamp window per spec PF-15 (stale > 5 s)
const STALE_THRESHOLD_MS: i64 = 5_000;

/// Timestamp window per spec PF-16 (future > 1 s)
const FUTURE_THRESHOLD_MS: i64 = 1_000;

/// Rate limit per spec PF-18: 100 msg/s for external sessions
const RATE_LIMIT_EXTERNAL_MSG_PER_SEC: usize = 100;

/// Time window for rate limiting (1 second in milliseconds)
const RATE_LIMIT_WINDOW_MS: u64 = 1_000;

/// Throttle reason for rate limit breaches
#[derive(Debug, Clone, PartialEq)]
pub enum ThrottleReason {
    ProtocolFirewall,
    PolicyRate,
}

/// Nonce tracker: sliding window of the last 10,000 nonces per session.
#[derive(Debug)]
struct NonceWindow {
    nonces: VecDeque<Vec<u8>>,
}

impl NonceWindow {
    fn new() -> Self {
        Self {
            nonces: VecDeque::with_capacity(NONCE_WINDOW_SIZE),
        }
    }

    fn check_and_insert(&mut self, nonce: &[u8]) -> bool {
        if self.nonces.iter().any(|n| n.as_slice() == nonce) {
            return false; // Nonce reuse detected
        }
        self.nonces.push_back(nonce.to_vec());
        if self.nonces.len() > NONCE_WINDOW_SIZE {
            self.nonces.pop_front();
        }
        true
    }
}

/// Rate limiter: tracks message timestamps per session.
#[derive(Debug)]
struct RateLimiter {
    timestamps: VecDeque<u64>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::new(),
        }
    }

    fn check_rate(&mut self, now_ms: u64, limit: usize) -> bool {
        // Remove timestamps outside the window
        while let Some(&ts) = self.timestamps.front() {
            if now_ms.saturating_sub(ts) > RATE_LIMIT_WINDOW_MS {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
        
        if self.timestamps.len() >= limit {
            return false; // Rate limit exceeded
        }
        
        self.timestamps.push_back(now_ms);
        true
    }
}

/// Per-session state for Protocol Firewall checks.
#[derive(Debug)]
struct SessionState {
    nonce_window: NonceWindow,
    rate_limiter_pf18: RateLimiter,
    rate_limiter_policy: RateLimiter,
}

impl SessionState {
    fn new() -> Self {
        Self {
            nonce_window: NonceWindow::new(),
            rate_limiter_pf18: RateLimiter::new(),
            rate_limiter_policy: RateLimiter::new(),
        }
    }
}

/// Global state for the Protocol Firewall.
pub struct ProtocolFirewall {
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
}

impl Default for ProtocolFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolFirewall {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// PF-1/PF-5: Envelope/payload size bounds (64 KiB envelope budget per spec).
    pub fn check_envelope_size(payload: &[u8]) -> Result<(), String> {
        if payload.len() > ENVELOPE_SIZE_LIMIT {
            return Err(format!(
                "PF-1 envelope size rejected: payload {} bytes exceeds {} KiB limit",
                payload.len(),
                ENVELOPE_SIZE_LIMIT / 1024
            ));
        }
        Ok(())
    }

    /// PF-12: Reject unknown fields in the ActionDescriptor payload JSON.
    /// The shipped client (webui/src/lib/gmClient.ts) sends exactly:
    /// actionType, context, target, metadata.
    pub fn check_unknown_fields(payload: &[u8]) -> Result<(), String> {
        let json_val: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| format!("PF-12 payload parse failed: {}", e))?;
        
        if let Some(obj) = json_val.as_object() {
            const KNOWN_FIELDS: &[&str] = &["actionType", "context", "target", "metadata"];
            for key in obj.keys() {
                if !KNOWN_FIELDS.contains(&key.as_str()) {
                    return Err(format!("PF-12 unknown field rejected: {}", key));
                }
            }
        }
        Ok(())
    }

    /// PF-13: Payload nesting depth max 4.
    pub fn check_nesting_depth(payload: &[u8]) -> Result<(), String> {
        let json_val: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| format!("PF-13 payload parse failed: {}", e))?;
        
        fn depth(val: &serde_json::Value) -> usize {
            match val {
                serde_json::Value::Object(obj) => {
                    1 + obj.values().map(depth).max().unwrap_or(0)
                }
                serde_json::Value::Array(arr) => {
                    1 + arr.iter().map(depth).max().unwrap_or(0)
                }
                _ => 0,
            }
        }
        
        let d = depth(&json_val);
        if d > MAX_NESTING_DEPTH {
            return Err(format!(
                "PF-13 nesting depth rejected: depth {} exceeds limit {}",
                d, MAX_NESTING_DEPTH
            ));
        }
        Ok(())
    }

    /// PF-14: Nonce uniqueness — sliding window of the last 10,000 nonces per session.
    pub fn check_nonce_uniqueness(&self, session_id: &str, nonce: &[u8]) -> Result<(), String> {
        let mut sessions = self.sessions.lock().unwrap();
        let state = sessions.entry(session_id.to_string()).or_insert_with(SessionState::new);
        
        if !state.nonce_window.check_and_insert(nonce) {
            return Err("PF-14 nonce reuse rejected".to_string());
        }
        Ok(())
    }

    /// PF-15/PF-16: Envelope timestamp windows per spec.
    /// The envelope timestamp field is unix NANOSECONDS per the shipped client.
    /// Stale > 5 s, future > 1 s.
    pub fn check_timestamp_windows(timestamp_ns: u64) -> Result<(), String> {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        let drift_ms = ((now_ns as i128 - timestamp_ns as i128) / 1_000_000) as i64;
        
        if drift_ms > STALE_THRESHOLD_MS {
            return Err(format!(
                "PF-15 stale timestamp rejected: {}ms old exceeds {}ms limit",
                drift_ms, STALE_THRESHOLD_MS
            ));
        }
        
        if drift_ms < -FUTURE_THRESHOLD_MS {
            return Err(format!(
                "PF-16 future timestamp rejected: {}ms ahead exceeds {}ms limit",
                -drift_ms, FUTURE_THRESHOLD_MS
            ));
        }
        
        Ok(())
    }

    /// PF-17: Signature format budget — ML-DSA-65 signature length within [2420, 3500] bytes.
    pub fn check_signature_format(signature: &[u8]) -> Result<(), String> {
        let len = signature.len();
        if len < ML_DSA_65_SIG_MIN || len > ML_DSA_65_SIG_MAX {
            return Err(format!(
                "PF-17 signature format rejected: length {} bytes not in valid range [{}, {}]",
                len, ML_DSA_65_SIG_MIN, ML_DSA_65_SIG_MAX
            ));
        }
        Ok(())
    }

    /// Check policy-configured per-session rate limit.
    /// Returns Ok(None) if under limit, Ok(Some(reason)) for THROTTLE verdict.
    /// WO-5: This is checked BEFORE PF-18, as the design allows the policy rate
    /// to be lower than PF-18's hard ceiling.
    pub fn check_policy_rate(&self, session_id: &str, limit: usize) -> Result<Option<ThrottleReason>, String> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        let mut sessions = self.sessions.lock().unwrap();
        let state = sessions.entry(session_id.to_string()).or_insert_with(SessionState::new);
        
        if !state.rate_limiter_policy.check_rate(now_ms, limit) {
            return Ok(Some(ThrottleReason::PolicyRate));
        }
        Ok(None)
    }

    /// PF-18: Rate limit 100 msg/s per external session.
    /// Returns Ok(None) if under limit, Ok(Some(reason)) for THROTTLE verdict.
    pub fn check_rate_limit(&self, session_id: &str) -> Result<Option<ThrottleReason>, String> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        let mut sessions = self.sessions.lock().unwrap();
        let state = sessions.entry(session_id.to_string()).or_insert_with(SessionState::new);
        
        if !state.rate_limiter_pf18.check_rate(now_ms, RATE_LIMIT_EXTERNAL_MSG_PER_SEC) {
            return Ok(Some(ThrottleReason::ProtocolFirewall));
        }
        Ok(None)
    }

    /// Clean up expired sessions.
    pub fn evict_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf01_envelope_size_accepts_valid() {
        let payload = vec![0u8; 1024];
        assert!(ProtocolFirewall::check_envelope_size(&payload).is_ok());
    }

    #[test]
    fn pf01_envelope_size_rejects_oversized() {
        let payload = vec![0u8; 65 * 1024];
        let err = ProtocolFirewall::check_envelope_size(&payload).unwrap_err();
        assert!(err.contains("PF-1"));
    }

    #[test]
    fn pf12_unknown_fields_accepts_known() {
        let json = r#"{"actionType":"TOOL_CALL","context":"test","target":"panel","metadata":{"source":"webui"}}"#;
        assert!(ProtocolFirewall::check_unknown_fields(json.as_bytes()).is_ok());
    }

    #[test]
    fn pf12_unknown_fields_rejects_unknown() {
        let json = r#"{"actionType":"TOOL_CALL","unknownField":"bad"}"#;
        let err = ProtocolFirewall::check_unknown_fields(json.as_bytes()).unwrap_err();
        assert!(err.contains("PF-12"));
        assert!(err.contains("unknownField"));
    }

    #[test]
    fn pf13_nesting_depth_accepts_shallow() {
        let json = r#"{"a":{"b":{"c":"value"}}}"#;
        assert!(ProtocolFirewall::check_nesting_depth(json.as_bytes()).is_ok());
    }

    #[test]
    fn pf13_nesting_depth_rejects_deep() {
        let json = r#"{"a":{"b":{"c":{"d":{"e":"too deep"}}}}}"#;
        let err = ProtocolFirewall::check_nesting_depth(json.as_bytes()).unwrap_err();
        assert!(err.contains("PF-13"));
    }

    #[test]
    fn pf14_nonce_uniqueness_accepts_new() {
        let pf = ProtocolFirewall::new();
        assert!(pf.check_nonce_uniqueness("session1", b"nonce1").is_ok());
    }

    #[test]
    fn pf14_nonce_uniqueness_rejects_reuse() {
        let pf = ProtocolFirewall::new();
        pf.check_nonce_uniqueness("session1", b"nonce1").unwrap();
        let err = pf.check_nonce_uniqueness("session1", b"nonce1").unwrap_err();
        assert!(err.contains("PF-14"));
    }

    #[test]
    fn pf14_nonce_uniqueness_different_sessions_ok() {
        let pf = ProtocolFirewall::new();
        pf.check_nonce_uniqueness("session1", b"nonce1").unwrap();
        assert!(pf.check_nonce_uniqueness("session2", b"nonce1").is_ok());
    }

    #[test]
    fn pf15_timestamp_accepts_recent() {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        assert!(ProtocolFirewall::check_timestamp_windows(now_ns).is_ok());
    }

    #[test]
    fn pf15_timestamp_rejects_stale() {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let stale_ns = now_ns - (6_000 * 1_000_000); // 6 seconds ago
        let err = ProtocolFirewall::check_timestamp_windows(stale_ns).unwrap_err();
        assert!(err.contains("PF-15"));
    }

    #[test]
    fn pf16_timestamp_rejects_future() {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let future_ns = now_ns + (2_000 * 1_000_000); // 2 seconds ahead
        let err = ProtocolFirewall::check_timestamp_windows(future_ns).unwrap_err();
        assert!(err.contains("PF-16"));
    }

    #[test]
    fn pf17_signature_format_accepts_valid() {
        let sig = vec![0u8; 3309]; // Typical ML-DSA-65 signature length
        assert!(ProtocolFirewall::check_signature_format(&sig).is_ok());
    }

    #[test]
    fn pf17_signature_format_rejects_too_short() {
        let sig = vec![0u8; 2000];
        let err = ProtocolFirewall::check_signature_format(&sig).unwrap_err();
        assert!(err.contains("PF-17"));
    }

    #[test]
    fn pf17_signature_format_rejects_too_long() {
        let sig = vec![0u8; 4000];
        let err = ProtocolFirewall::check_signature_format(&sig).unwrap_err();
        assert!(err.contains("PF-17"));
    }

    #[test]
    fn pf18_rate_limit_accepts_under_limit() {
        let pf = ProtocolFirewall::new();
        for _ in 0..50 {
            let result = pf.check_rate_limit("session1").unwrap();
            assert_eq!(result, None);
        }
    }

    #[test]
    fn pf18_rate_limit_returns_throttle_over_limit() {
        let pf = ProtocolFirewall::new();
        for _ in 0..100 {
            pf.check_rate_limit("session1").unwrap();
        }
        let result = pf.check_rate_limit("session1").unwrap();
        assert_eq!(result, Some(ThrottleReason::ProtocolFirewall));
    }

    #[test]
    fn pf18_rate_limit_different_sessions_independent() {
        let pf = ProtocolFirewall::new();
        for _ in 0..100 {
            pf.check_rate_limit("session1").unwrap();
        }
        // session2 should still be able to send
        let result = pf.check_rate_limit("session2").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn policy_rate_limit_accepts_under_limit() {
        let pf = ProtocolFirewall::new();
        for _ in 0..10 {
            let result = pf.check_policy_rate("session1", 20).unwrap();
            assert_eq!(result, None);
        }
    }

    #[test]
    fn policy_rate_limit_returns_throttle_over_limit() {
        let pf = ProtocolFirewall::new();
        for _ in 0..20 {
            pf.check_policy_rate("session1", 20).unwrap();
        }
        let result = pf.check_policy_rate("session1", 20).unwrap();
        assert_eq!(result, Some(ThrottleReason::PolicyRate));
    }

    #[test]
    fn nonce_window_size_enforcement() {
        let pf = ProtocolFirewall::new();
        // Insert 10,001 nonces - the window is 10,000, so the first one gets evicted
        for i in 0..10_001 {
            let nonce = format!("nonce{}", i);
            pf.check_nonce_uniqueness("session1", nonce.as_bytes()).unwrap();
        }
        // The first nonce (nonce0) should have been evicted, so we can reuse it
        assert!(pf.check_nonce_uniqueness("session1", b"nonce0").is_ok());
    }
}
