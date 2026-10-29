// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;
use rand::rngs::SysRng;
use rand::TryRng;
use std::collections::HashMap;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct HandshakeSession {
    pub session_id: String,
    pub session_key: [u8; 32],
    pub source_enclave: String,
    pub created_at: u64,
    /// The caller's ML-DSA-65 verifying key, bound at Handshake time.
    /// Evaluate requires every envelope signature on the session to
    /// verify against this key. Empty for legacy sessions created
    /// without a key — those fail closed at Evaluate.
    pub source_public_key: Vec<u8>,
    pub auth_factors: Vec<String>,
    pub workload_id: String,
}

pub struct HandshakeBus {
    sessions: Mutex<HashMap<String, HandshakeSession>>,
    #[allow(dead_code)]
    master_secret: Vec<u8>,
}

pub const SESSION_TTL_SECS: u64 = 300;

impl HandshakeBus {
    pub fn new(master_secret: &[u8]) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            master_secret: master_secret.to_vec(),
        }
    }

    pub fn evict_expired_at(&self, now_secs: u64) -> Vec<String> {
        let mut sessions = self.sessions.lock().unwrap();
        let mut evicted = Vec::new();
        sessions.retain(|id, s| {
            if now_secs.saturating_sub(s.created_at) >= SESSION_TTL_SECS {
                evicted.push(id.clone());
                false
            } else {
                true
            }
        });
        evicted
    }

    pub fn evict_expired(&self) -> Vec<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.evict_expired_at(now)
    }

    pub fn create_session(&self, source_enclave: &str) -> String {
        self.create_session_full(source_enclave, &[]).session_id
    }

    /// Create a session and return it in full, including the session
    /// key. This is what the Handshake RPC hands to a caller: without
    /// the key the caller cannot produce the HMAC tags the Gatekeeper
    /// verifies, so session creation and key delivery are one step.
    /// The caller's ML-DSA-65 verifying key is bound to the session
    /// here; the Gatekeeper verifies envelope signatures against it.
    pub fn create_session_full(
        &self,
        source_enclave: &str,
        source_public_key: &[u8],
    ) -> HandshakeSession {
        let auth_factors = if source_public_key.is_empty() {
            vec![]
        } else {
            vec!["ML_DSA_65".to_string(), "HMAC_SESSION".to_string()]
        };
        self.create_session_attested(source_enclave, source_public_key, auth_factors, String::new())
    }

    pub fn create_session_attested(
        &self,
        source_enclave: &str,
        source_public_key: &[u8],
        auth_factors: Vec<String>,
        workload_id: String,
    ) -> HandshakeSession {
        let mut session_id_bytes = [0u8; 16];
        let _ = SysRng.try_fill_bytes(&mut session_id_bytes);
        let session_id = hex::encode(session_id_bytes);

        let mut session_key = [0u8; 32];
        let _ = SysRng.try_fill_bytes(&mut session_key);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = HandshakeSession {
            session_id: session_id.clone(),
            session_key,
            source_enclave: source_enclave.to_string(),
            created_at: now,
            source_public_key: source_public_key.to_vec(),
            auth_factors,
            workload_id,
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session.clone());
        session
    }

    pub fn compute_hmac(&self, session_id: &str, data: &[u8]) -> Result<Vec<u8>, String> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("session {} not found", session_id))?;

        let mut mac = HmacSha256::new_from_slice(&session.session_key)
            .map_err(|e| format!("HMAC init failed: {}", e))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_hmac(
        &self,
        session_id: &str,
        data: &[u8],
        tag: &[u8],
    ) -> Result<bool, String> {
        let computed = self.compute_hmac(session_id, data)?;
        Ok(computed.as_slice() == tag)
    }

    pub fn session_exists(&self, session_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.get(session_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(s.created_at) < SESSION_TTL_SECS
        } else {
            false
        }
    }

    /// The ML-DSA-65 verifying key bound to a session, when the
    /// session exists, is unexpired, and a key was bound to it.
    /// Returns None in every other case — callers fail closed.
    pub fn session_public_key(&self, session_id: &str) -> Option<Vec<u8>> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(session_id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            return None;
        }
        if session.source_public_key.is_empty() {
            return None;
        }
        Some(session.source_public_key.clone())
    }

    pub fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }

    /// Return the IDs of all unexpired sessions bound to a given ML-DSA-65
    /// verifying key (by fingerprint). Only sessions with non-empty keys
    /// are considered. Used by key revocation to find sessions to drop.
    pub fn sessions_bound_to_key(&self, fingerprint: &str) -> Vec<String> {
        use sha2::Digest;
        let sessions = self.sessions.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        sessions
            .iter()
            .filter(|(_, s)| {
                // Only unexpired sessions
                if now.saturating_sub(s.created_at) >= SESSION_TTL_SECS {
                    return false;
                }
                // Only sessions with a bound key
                if s.source_public_key.is_empty() {
                    return false;
                }
                // Compute the key fingerprint (hex SHA-256 of the raw key bytes)
                let key_fp = hex::encode(Sha256::digest(&s.source_public_key));
                key_fp == fingerprint
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get auth factors and workload_id for a session (unexpired only).
    pub fn session_auth(&self, session_id: &str) -> Option<(Vec<String>, String)> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(session_id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            return None;
        }
        Some((session.auth_factors.clone(), session.workload_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn create_and_verify_session() {
        let bus = HandshakeBus::new(b"test-secret");
        let sid = bus.create_session("test-enclave");
        assert!(bus.session_exists(&sid));
        let hmac = bus.compute_hmac(&sid, b"hello").unwrap();
        assert!(bus.verify_hmac(&sid, b"hello", &hmac).unwrap());
    }

    #[test]
    fn full_session_carries_a_usable_key() {
        // The Handshake RPC contract: the returned key must be the
        // key the bus verifies HMAC tags against.
        use hmac::{Hmac, Mac, KeyInit};
        use sha2::Sha256;
        let bus = HandshakeBus::new(b"test-secret");
        let session = bus.create_session_full("webui", &[7u8; 1952]);
        assert!(bus.session_exists(&session.session_id));
        let mut mac = Hmac::<Sha256>::new_from_slice(&session.session_key).unwrap();
        mac.update(b"payload");
        let tag = mac.finalize().into_bytes().to_vec();
        assert!(bus.verify_hmac(&session.session_id, b"payload", &tag).unwrap());
    }

    #[test]
    fn bound_public_key_is_retrievable() {
        let bus = HandshakeBus::new(b"test-secret");
        let key = vec![9u8; 1952];
        let session = bus.create_session_full("webui", &key);
        assert_eq!(bus.session_public_key(&session.session_id), Some(key));
    }

    #[test]
    fn session_without_bound_key_reports_none() {
        let bus = HandshakeBus::new(b"test-secret");
        let sid = bus.create_session("legacy-enclave");
        assert_eq!(bus.session_public_key(&sid), None);
        assert_eq!(bus.session_public_key("nonexistent"), None);
    }

    #[test]
    fn missing_session_rejected() {
        let bus = HandshakeBus::new(b"test-secret");
        assert!(!bus.session_exists("nonexistent"));
        assert!(bus.compute_hmac("nonexistent", b"data").is_err());
    }

    #[test]
    fn tampered_hmac_rejected() {
        let bus = HandshakeBus::new(b"test-secret");
        let sid = bus.create_session("test-enclave");
        let mut hmac = bus.compute_hmac(&sid, b"data").unwrap();
        hmac[0] ^= 0xff;
        assert!(!bus.verify_hmac(&sid, b"data", &hmac).unwrap());
    }

    #[test]
    fn remove_session_works() {
        let bus = HandshakeBus::new(b"test-secret");
        let sid = bus.create_session("test-enclave");
        assert!(bus.session_exists(&sid));
        bus.remove_session(&sid);
        assert!(!bus.session_exists(&sid));
    }

    #[test]
    fn session_ttl_expiry() {
        let bus = HandshakeBus::new(b"test-secret");
        let sid = bus.create_session("test-enclave");
        assert!(bus.session_exists(&sid));
        let evicted = bus.evict_expired();
        assert!(evicted.is_empty());
        assert!(bus.session_exists(&sid));
    }

    // WO-19: evict_expired_at test
    #[test]
    fn evict_expired_at_returns_evicted_ids() {
        let bus = HandshakeBus::new(b"test-secret");
        let session = bus.create_session_full("test-enclave", &[]);
        let sid = session.session_id.clone();
        let created_at = session.created_at;
        
        // At creation time, no eviction
        let evicted = bus.evict_expired_at(created_at);
        assert!(evicted.is_empty());
        assert!(bus.session_exists(&sid));
        
        // At TTL+1, session is evicted
        let future = created_at + SESSION_TTL_SECS + 1;
        let evicted = bus.evict_expired_at(future);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0], sid);
        assert!(!bus.session_exists(&sid));
    }

    #[test]
    fn sessions_bound_to_key_returns_matching_unexpired_sessions() {
        use sha2::Digest;
        let bus = HandshakeBus::new(b"test-secret");
        
        // Create three sessions with different keys
        let key_a = vec![1u8; 1952];
        let key_b = vec![2u8; 1952];
        let fp_a = hex::encode(Sha256::digest(&key_a));
        let fp_b = hex::encode(Sha256::digest(&key_b));
        
        let session_a1 = bus.create_session_full("enclave1", &key_a);
        let session_a2 = bus.create_session_full("enclave2", &key_a);
        let session_b = bus.create_session_full("enclave3", &key_b);
        let session_no_key = bus.create_session_full("enclave4", &[]);
        
        // sessions_bound_to_key should find only the two sessions with key_a
        let bound = bus.sessions_bound_to_key(&fp_a);
        assert_eq!(bound.len(), 2);
        assert!(bound.contains(&session_a1.session_id));
        assert!(bound.contains(&session_a2.session_id));
        
        // sessions_bound_to_key should find only the one session with key_b
        let bound_b = bus.sessions_bound_to_key(&fp_b);
        assert_eq!(bound_b.len(), 1);
        assert!(bound_b.contains(&session_b.session_id));
        
        // No sessions bound to a non-existent key
        let bound_none = bus.sessions_bound_to_key(&"0".repeat(64));
        assert_eq!(bound_none.len(), 0);
        
        // session_no_key should not appear in any result
        assert!(!bound.contains(&session_no_key.session_id));
        assert!(!bound_b.contains(&session_no_key.session_id));
    }

    #[test]
    fn session_auth_returns_factors_and_workload() {
        let bus = HandshakeBus::new(b"test-secret");
        
        // Attested session
        let factors = vec!["ML_DSA_65".to_string(), "SPIFFE_X509".to_string()];
        let workload_id = "spiffe://cluster.local/workload".to_string();
        let session = bus.create_session_attested("test", &[1u8; 1952], factors.clone(), workload_id.clone());
        
        let (auth_factors, wid) = bus.session_auth(&session.session_id).unwrap();
        assert_eq!(auth_factors, factors);
        assert_eq!(wid, workload_id);
        
        // Expired session returns None
        assert_eq!(bus.session_auth("nonexistent"), None);
        
        // Unknown session returns None
        let expired_time = session.created_at + SESSION_TTL_SECS + 1;
        bus.evict_expired_at(expired_time);
        assert_eq!(bus.session_auth(&session.session_id), None);
    }
}
