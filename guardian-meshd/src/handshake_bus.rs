// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: AGPL-3.0-or-later

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
}

pub struct HandshakeBus {
    sessions: Mutex<HashMap<String, HandshakeSession>>,
    #[allow(dead_code)]
    master_secret: Vec<u8>,
}

const SESSION_TTL_SECS: u64 = 300;

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
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session);
        session_id
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
