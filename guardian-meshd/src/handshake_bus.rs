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

    pub fn evict_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| now.saturating_sub(s.created_at) < SESSION_TTL_SECS);
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
        bus.evict_expired();
        assert!(bus.session_exists(&sid));
    }
}
