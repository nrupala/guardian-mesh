// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

//! CM-2 execution tokens and the resource-side checker.
//!
//! A token is issued by the daemon on a real (non-simulation) ALLOW and
//! binds the exact action descriptor the daemon judged. The wire form is
//! `u32-BE payload length || payload || ML-DSA-65 signature`, where the
//! signature covers the payload bytes. The payload is the ASCII header
//! `GMET1` followed by length-prefixed fields (token id, action hash,
//! session id, tenant id, issued-at, expires-at).
//!
//! The [`ExecutionChecker`] is the resource-side half: an embedder
//! constructs it with the daemon's verifying key, optionally escrows the
//! credentials it holds, and refuses execution without a token that
//! verifies, matches the presented action, is unexpired and unused.
//!
//! The checker uses `&mut self` for its consuming checks (the used-token
//! set and escrow store are owned maps). It is not used by the daemon
//! service itself - only tests and resource-side embedders construct one.

use ml_dsa::{
    MlDsa65, Signature, SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::rngs::SysRng;
use rand::TryRng;
use sha2::{Digest, Sha256};

use crate::proto::ActionDescriptor;

/// Lifetime of an issued execution token, in seconds.
pub const TOKEN_TTL_SECS: u64 = 120;

/// ASCII header that prefixes every token payload.
const TOKEN_HEADER: &[u8] = b"GMET1";

/// Claims carried inside a verified execution token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClaims {
    pub token_id: String,
    pub action_hash: String,
    pub session_id: String,
    pub tenant_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_len_prefixed<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
    if buf.len() < *pos + 4 {
        return Err("malformed execution token".into());
    }
    let len = u32::from_be_bytes(
        buf[*pos..*pos + 4]
            .try_into()
            .expect("4-byte slice fits u32"),
    ) as usize;
    *pos += 4;
    if buf.len() < *pos + len {
        return Err("malformed execution token".into());
    }
    let out = &buf[*pos..*pos + len];
    *pos += len;
    Ok(out)
}

fn read_string(buf: &[u8], pos: &mut usize) -> Result<String, String> {
    let bytes = read_len_prefixed(buf, pos)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| "malformed execution token".into())
}

/// Hex SHA-256 over a canonical length-prefixed encoding of the action:
/// action_type, context, target in order, then metadata entries sorted by
/// key. Each field is `u32-BE length || bytes`; a metadata entry is
/// `u32-BE len || key || u32-BE len || value`. Metadata insertion order
/// therefore cannot affect the hash.
pub fn action_hash(action: &ActionDescriptor) -> String {
    let mut canonical = Vec::new();
    push_len_prefixed(&mut canonical, action.action_type.as_bytes());
    push_len_prefixed(&mut canonical, action.context.as_bytes());
    push_len_prefixed(&mut canonical, action.target.as_bytes());

    let mut entries: Vec<(&String, &String)> = action.metadata.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in entries {
        push_len_prefixed(&mut canonical, key.as_bytes());
        push_len_prefixed(&mut canonical, value.as_bytes());
    }

    hex::encode(Sha256::digest(&canonical))
}

fn build_payload(
    token_id: &str,
    action_hash: &str,
    session_id: &str,
    tenant_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(TOKEN_HEADER);
    push_len_prefixed(&mut payload, token_id.as_bytes());
    push_len_prefixed(&mut payload, action_hash.as_bytes());
    push_len_prefixed(&mut payload, session_id.as_bytes());
    push_len_prefixed(&mut payload, tenant_id.as_bytes());
    push_len_prefixed(&mut payload, issued_at.to_string().as_bytes());
    push_len_prefixed(&mut payload, expires_at.to_string().as_bytes());
    payload
}

fn parse_claims(payload: &[u8]) -> Result<TokenClaims, String> {
    if payload.len() < TOKEN_HEADER.len() || &payload[..TOKEN_HEADER.len()] != TOKEN_HEADER {
        return Err("malformed execution token".into());
    }

    let mut pos = TOKEN_HEADER.len();
    let token_id = read_string(payload, &mut pos)?;
    let action_hash = read_string(payload, &mut pos)?;
    let session_id = read_string(payload, &mut pos)?;
    let tenant_id = read_string(payload, &mut pos)?;
    let issued_at_raw = read_string(payload, &mut pos)?;
    let expires_at_raw = read_string(payload, &mut pos)?;

    if pos != payload.len() {
        return Err("malformed execution token".into());
    }

    let issued_at = issued_at_raw
        .parse::<u64>()
        .map_err(|_| "malformed execution token".to_string())?;
    let expires_at = expires_at_raw
        .parse::<u64>()
        .map_err(|_| "malformed execution token".to_string())?;

    Ok(TokenClaims {
        token_id,
        action_hash,
        session_id,
        tenant_id,
        issued_at,
        expires_at,
    })
}

/// Issue a CM-2 execution token for `action`, signed with the daemon's
/// ML-DSA-65 signing key.
pub fn issue_token(
    signing_key: &SigningKey<MlDsa65>,
    action: &ActionDescriptor,
    session_id: &str,
    tenant_id: &str,
    now_unix: u64,
) -> Vec<u8> {
    let mut id_bytes = [0u8; 16];
    let _ = SysRng.try_fill_bytes(&mut id_bytes);
    let token_id = hex::encode(id_bytes);
    let action_hash = action_hash(action);
    let expires_at = now_unix + TOKEN_TTL_SECS;

    let payload = build_payload(
        &token_id,
        &action_hash,
        session_id,
        tenant_id,
        now_unix,
        expires_at,
    );
    let signature = signing_key.sign(&payload);

    let mut wire = Vec::with_capacity(4 + payload.len() + signature.to_bytes().len());
    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(&payload);
    wire.extend_from_slice(&signature.to_bytes());
    wire
}

/// The resource-side CM-2 checker.
///
/// Holds the daemon verifying key, an in-memory escrow store populated by
/// the resource-side process, and the set of already-consumed token ids.
/// Escrowed credential bytes are never printed: the manual `Debug`
/// implementation reports counts only.
pub struct ExecutionChecker {
    verifying_key: VerifyingKey<MlDsa65>,
    escrow: std::collections::HashMap<String, Vec<u8>>,
    used_tokens: std::collections::HashSet<String>,
}

impl std::fmt::Debug for ExecutionChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionChecker")
            .field("escrow_targets", &self.escrow.len())
            .field("used_tokens", &self.used_tokens.len())
            .finish()
    }
}

impl ExecutionChecker {
    pub fn new(verifying_key: VerifyingKey<MlDsa65>) -> Self {
        Self {
            verifying_key,
            escrow: std::collections::HashMap::new(),
            used_tokens: std::collections::HashSet::new(),
        }
    }

    pub fn with_escrow(mut self, target: &str, credential: Vec<u8>) -> Self {
        self.escrow.insert(target.to_string(), credential);
        self
    }

    pub fn add_escrow(&mut self, target: &str, credential: Vec<u8>) {
        self.escrow.insert(target.to_string(), credential);
    }

    /// Verify and consume a token for `action`.
    ///
    /// Order: structural parse -> signature verify -> claims parse ->
    /// expiry -> action-hash compare -> replay consume. The token id is
    /// inserted into the used set only after every check passes.
    pub fn check(
        &mut self,
        token: &[u8],
        action: &ActionDescriptor,
        now_unix: u64,
    ) -> Result<TokenClaims, String> {
        if token.is_empty() {
            return Err("missing execution token".into());
        }
        if token.len() < 4 {
            return Err("malformed execution token".into());
        }

        let payload_len = u32::from_be_bytes(
            token[..4]
                .try_into()
                .expect("4-byte slice fits u32"),
        ) as usize;
        if token.len() < 4 + payload_len + 1 {
            return Err("malformed execution token".into());
        }

        let payload = &token[4..4 + payload_len];
        let signature_bytes = &token[4 + payload_len..];

        let signature = Signature::<MlDsa65>::try_from(signature_bytes)
            .map_err(|_| "execution token signature invalid".to_string())?;
        self.verifying_key
            .verify(payload, &signature)
            .map_err(|_| "execution token signature invalid".to_string())?;

        let claims = parse_claims(payload)?;

        if now_unix > claims.expires_at {
            return Err("execution token expired".into());
        }

        if claims.action_hash != action_hash(action) {
            return Err(
                "execution token action mismatch: token was issued for a different action".into(),
            );
        }

        if self.used_tokens.contains(&claims.token_id) {
            return Err("execution token already used".into());
        }
        self.used_tokens.insert(claims.token_id.clone());

        Ok(claims)
    }

    /// Run [`check`](Self::check) and, on success, return a clone of the
    /// credential escrowed for `action.target` (`None` when none is
    /// escrowed). A refusal releases nothing.
    pub fn check_and_release(
        &mut self,
        token: &[u8],
        action: &ActionDescriptor,
        now_unix: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        self.check(token, action, now_unix)?;
        Ok(self.escrow.get(&action.target).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_envelope::generate_keypair;
    use std::collections::HashMap;

    fn action() -> ActionDescriptor {
        let mut metadata = HashMap::new();
        metadata.insert("b".to_string(), "2".to_string());
        metadata.insert("a".to_string(), "1".to_string());
        ActionDescriptor {
            action_type: "TOOL_CALL".to_string(),
            context: "ctx".to_string(),
            target: "panel".to_string(),
            metadata,
        }
    }

    #[test]
    fn hash_is_stable_and_metadata_order_independent() {
        let first = action();
        let second = action();
        let mut reordered = action();
        let mut metadata = HashMap::new();
        metadata.insert("a".to_string(), "1".to_string());
        metadata.insert("b".to_string(), "2".to_string());
        reordered.metadata = metadata;

        assert_eq!(action_hash(&first), action_hash(&first));
        assert_eq!(action_hash(&first), action_hash(&second));
        assert_eq!(action_hash(&first), action_hash(&reordered));
    }

    #[test]
    fn hash_is_sensitive_to_every_field() {
        let base = action_hash(&action());

        let mut different_type = action();
        different_type.action_type = "CODE_EXECUTE".to_string();
        let mut different_context = action();
        different_context.context = "other".to_string();
        let mut different_target = action();
        different_target.target = "other".to_string();
        let mut different_metadata = action();
        different_metadata.metadata.insert("a".to_string(), "changed".to_string());

        assert_ne!(base, action_hash(&different_type));
        assert_ne!(base, action_hash(&different_context));
        assert_ne!(base, action_hash(&different_target));
        assert_ne!(base, action_hash(&different_metadata));
    }

    #[test]
    fn issue_and_check_round_trip() {
        let (sk, vk) = generate_keypair();
        let action = action();
        let token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let mut checker = ExecutionChecker::new(vk);

        let claims = checker.check(&token, &action, 1_000).unwrap();
        assert_eq!(claims.session_id, "session-1");
        assert_eq!(claims.tenant_id, "tenant-1");
        assert_eq!(claims.action_hash, action_hash(&action));
        assert_eq!(claims.issued_at, 1_000);
        assert_eq!(claims.expires_at, 1_000 + TOKEN_TTL_SECS);
        assert_eq!(claims.token_id.len(), 32);
    }

    #[test]
    fn tampered_payload_is_refused() {
        let (sk, vk) = generate_keypair();
        let action = action();
        let mut token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        token[4] ^= 0xff;
        let mut checker = ExecutionChecker::new(vk);

        let err = checker.check(&token, &action, 1_000).unwrap_err();
        assert_eq!(err, "execution token signature invalid");
    }

    #[test]
    fn wrong_key_is_refused() {
        let (sk, _vk) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let action = action();
        let token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let mut checker = ExecutionChecker::new(wrong_vk);

        let err = checker.check(&token, &action, 1_000).unwrap_err();
        assert_eq!(err, "execution token signature invalid");
    }

    #[test]
    fn different_action_is_refused() {
        let (sk, vk) = generate_keypair();
        let action = action();
        let token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let mut other = action.clone();
        other.target = "other-resource".to_string();
        let mut checker = ExecutionChecker::new(vk);

        let err = checker.check(&token, &other, 1_000).unwrap_err();
        assert!(err.contains("action mismatch"));
    }

    #[test]
    fn expired_token_is_refused() {
        let (sk, vk) = generate_keypair();
        let action = action();
        let token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let mut checker = ExecutionChecker::new(vk);

        // now == expires_at is still valid.
        assert!(checker
            .check(&token, &action, 1_000 + TOKEN_TTL_SECS)
            .is_ok());

        // now > expires_at refuses.
        let (sk2, vk2) = generate_keypair();
        let token2 = issue_token(&sk2, &action, "session-1", "tenant-1", 1_000);
        let mut checker2 = ExecutionChecker::new(vk2);
        let err = checker2
            .check(&token2, &action, 1_000 + TOKEN_TTL_SECS + 1)
            .unwrap_err();
        assert_eq!(err, "execution token expired");
    }

    #[test]
    fn replay_is_refused_on_second_check() {
        let (sk, vk) = generate_keypair();
        let action = action();
        let token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let mut checker = ExecutionChecker::new(vk);

        assert!(checker.check(&token, &action, 1_000).is_ok());
        let err = checker.check(&token, &action, 1_000).unwrap_err();
        assert_eq!(err, "execution token already used");
    }

    #[test]
    fn escrow_is_released_on_valid_check() {
        let (sk, vk) = generate_keypair();
        let action = action();
        let token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let mut checker =
            ExecutionChecker::new(vk).with_escrow("panel", b"test-escrow-value".to_vec());

        let released = checker.check_and_release(&token, &action, 1_000).unwrap();
        assert_eq!(released, Some(b"test-escrow-value".to_vec()));
    }

    #[test]
    fn escrow_is_not_released_on_refused_check() {
        let (sk, vk) = generate_keypair();
        let action = action();
        let token = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let mut other = action.clone();
        other.target = "other-resource".to_string();
        let mut checker =
            ExecutionChecker::new(vk).with_escrow("panel", b"test-escrow-value".to_vec());

        assert!(checker.check_and_release(&token, &other, 1_000).is_err());

        let token2 = issue_token(&sk, &action, "session-1", "tenant-1", 1_000);
        let released = checker.check_and_release(&token2, &action, 1_000).unwrap();
        assert_eq!(released, Some(b"test-escrow-value".to_vec()));
    }

    #[test]
    fn empty_token_is_refused() {
        let (_, vk) = generate_keypair();
        let action = action();
        let mut checker = ExecutionChecker::new(vk);

        let err = checker.check(&[], &action, 1_000).unwrap_err();
        assert_eq!(err, "missing execution token");
    }
}
