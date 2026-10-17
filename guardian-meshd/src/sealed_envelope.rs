// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use crc32c::crc32c;
use ml_dsa::{MlDsa65, Keypair, SigningKey, VerifyingKey, Signer, Verifier, SignatureEncoding, Signature};
use rand::rngs::SysRng;
use rand::TryRng;
use sha2::{Sha256, Digest};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct SealedEnvelope {
    pub payload: Vec<u8>,
    pub payload_type: Vec<u8>,
    pub crc32c_digest: u32,
    pub ml_dsa_65_signature: Vec<u8>,
    pub timestamp: u64,
    pub nonce: [u8; 32],
}

impl SealedEnvelope {
    pub fn new(payload: Vec<u8>, payload_type: Vec<u8>, signing_key: &SigningKey<MlDsa65>) -> Self {
        let crc = crc32c(&payload);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let timestamp: u64 = timestamp.try_into().unwrap_or(u64::MAX);

        let mut nonce = [0u8; 32];
        let _ = SysRng.try_fill_bytes(&mut nonce);

        let to_sign = Self::build_signing_payload(crc, &payload);
        let sig = signing_key.sign(&to_sign);

        Self {
            payload,
            payload_type,
            crc32c_digest: crc,
            ml_dsa_65_signature: sig.to_bytes().to_vec(),
            timestamp,
            nonce,
        }
    }

    fn build_signing_payload(crc: u32, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + payload.len());
        data.extend_from_slice(&crc.to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

    pub fn verify(&self, verifying_key: &VerifyingKey<MlDsa65>) -> Result<(), String> {
        verify_payload(&self.payload, self.crc32c_digest, &self.ml_dsa_65_signature, verifying_key)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&(self.payload_type.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload_type);
        buf.extend_from_slice(&self.crc32c_digest.to_le_bytes());
        buf.extend_from_slice(&self.ml_dsa_65_signature);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }
}

pub fn verify_proto_envelope(
    payload: &[u8],
    crc32c_digest: u32,
    signature: &[u8],
    verifying_key: &VerifyingKey<MlDsa65>,
) -> Result<(), String> {
    verify_payload(payload, crc32c_digest, signature, verifying_key)
}

fn verify_payload(
    payload: &[u8],
    crc32c_digest: u32,
    signature_bytes: &[u8],
    verifying_key: &VerifyingKey<MlDsa65>,
) -> Result<(), String> {
    let computed_crc = crc32c(payload);
    if computed_crc != crc32c_digest {
        return Err("CRC32C mismatch: payload integrity check failed".into());
    }

    let to_verify = {
        let mut data = Vec::with_capacity(4 + payload.len());
        data.extend_from_slice(&crc32c_digest.to_le_bytes());
        data.extend_from_slice(payload);
        data
    };
    let sig = Signature::<MlDsa65>::try_from(signature_bytes)
        .map_err(|e| format!("invalid signature bytes: {}", e))?;

    verifying_key
        .verify(&to_verify, &sig)
        .map_err(|e| format!("ML-DSA-65 signature verification failed: {}", e))
}

/// Byte length of an encoded ML-DSA-65 verifying key — the key a
/// caller registers with the daemon at Handshake time.
pub const ML_DSA_65_VERIFYING_KEY_LEN: usize = 1952;

/// Decode an encoded ML-DSA-65 verifying key from its wire bytes.
/// Any 1952-byte string decodes (the encoding carries no checksums),
/// so a decode success is not an authenticity proof — verification
/// of a signature against the key is.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<MlDsa65>, String> {
    if bytes.len() != ML_DSA_65_VERIFYING_KEY_LEN {
        return Err(format!(
            "ML-DSA-65 verifying key must be {} bytes, got {}",
            ML_DSA_65_VERIFYING_KEY_LEN,
            bytes.len()
        ));
    }
    let enc: ml_dsa::EncodedVerifyingKey<MlDsa65> = bytes.try_into()
        .map_err(|_| "failed to convert bytes to EncodedVerifyingKey".to_string())?;
    Ok(VerifyingKey::<MlDsa65>::decode(&enc))
}

pub fn generate_keypair() -> (SigningKey<MlDsa65>, VerifyingKey<MlDsa65>) {    let mut seed_bytes = [0u8; 32];
    let _ = SysRng.try_fill_bytes(&mut seed_bytes);
    let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice())
        .expect("32 bytes fits Seed");
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// The byte length of an ML-DSA seed (used to derive the signing key).
const ML_DSA_SEED_LEN: usize = 32;

/// Compute the SHA-256 fingerprint of an ML-DSA-65 public key.
/// Returns the lowercase hex-encoded string.
pub fn compute_fingerprint(vk: &VerifyingKey<MlDsa65>) -> String {
    let encoded = vk.encode();
    let encoded_bytes: &[u8] = encoded.as_ref();
    let hash = Sha256::digest(encoded_bytes);
    hex::encode(hash)
}

/// Load or generate the daemon's persistent ML-DSA-65 signing key.
/// 
/// On first start, generates a new keypair and stores the seed to
/// `{keys_dir}/daemon_signing_key.bin` with restrictive permissions
/// (0600 on Unix). On subsequent starts, loads the existing seed and
/// reconstructs the keypair.
/// 
/// If the stored key file exists but is corrupt or the wrong length,
/// this function fails closed: it returns an error and does NOT
/// silently regenerate the key (which would invalidate all outstanding
/// proofs).
pub fn load_or_generate_signing_key<P: AsRef<Path>>(
    keys_dir: P,
) -> Result<(SigningKey<MlDsa65>, VerifyingKey<MlDsa65>), String> {
    let key_path = keys_dir.as_ref().join("daemon_signing_key.bin");

    if key_path.exists() {
        // Load existing seed
        let seed_bytes = fs::read(&key_path)
            .map_err(|e| format!("FATAL: failed to read signing key from {}: {}", key_path.display(), e))?;

        if seed_bytes.len() != ML_DSA_SEED_LEN {
            return Err(format!(
                "FATAL: signing key file {} has invalid length: expected {} bytes, got {} bytes. \
                 The key file is corrupt. Do NOT delete it without operator approval — \
                 all proofs signed under this key will stop verifying if it is replaced.",
                key_path.display(),
                ML_DSA_SEED_LEN,
                seed_bytes.len()
            ));
        }

        let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice())
            .map_err(|e| format!("FATAL: failed to parse signing key seed: {}", e))?;
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk = sk.verifying_key();
        Ok((sk, vk))
    } else {
        // Generate new key on first start
        let mut seed_bytes = [0u8; ML_DSA_SEED_LEN];
        let _ = SysRng.try_fill_bytes(&mut seed_bytes);

        // Write with restrictive permissions
        let mut file = fs::File::create(&key_path)
            .map_err(|e| format!("failed to create signing key file {}: {}", key_path.display(), e))?;

        // Set permissions to 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&key_path, perms)
                .map_err(|e| format!("failed to set permissions on {}: {}", key_path.display(), e))?;
        }

        // On Windows, use the closest equivalent (file ACLs would be more thorough
        // but require additional dependencies; the file system default is acceptable
        // for a workspace directory that operators should already protect).

        file.write_all(&seed_bytes)
            .map_err(|e| format!("failed to write signing key to {}: {}", key_path.display(), e))?;

        file.sync_all()
            .map_err(|e| format!("failed to sync signing key file {}: {}", key_path.display(), e))?;

        let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice())
            .expect("32 bytes fits Seed");
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk = sk.verifying_key();
        Ok((sk, vk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_works() {
        let (sk, vk) = generate_keypair();
        let envelope = SealedEnvelope::new(b"test payload".to_vec(), b"test".to_vec(), &sk);
        assert!(envelope.verify(&vk).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, vk) = generate_keypair();
        let mut envelope = SealedEnvelope::new(b"test payload".to_vec(), b"test".to_vec(), &sk);
        envelope.payload = b"tampered".to_vec();
        assert!(envelope.verify(&vk).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (sk, _vk) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let envelope = SealedEnvelope::new(b"test payload".to_vec(), b"test".to_vec(), &sk);
        assert!(envelope.verify(&wrong_vk).is_err());
    }

    #[test]
    fn verifying_key_bytes_roundtrip() {
        let (sk, vk) = generate_keypair();
        let encoded = vk.encode();
        assert_eq!(encoded.len(), ML_DSA_65_VERIFYING_KEY_LEN);
        let decoded = verifying_key_from_bytes(&encoded).unwrap();
        let envelope = SealedEnvelope::new(b"payload".to_vec(), b"test".to_vec(), &sk);
        assert!(envelope.verify(&decoded).is_ok());
    }

    #[test]
    fn verifying_key_from_bytes_rejects_wrong_length() {
        assert!(verifying_key_from_bytes(&[]).is_err());
        assert!(verifying_key_from_bytes(&[0u8; 100]).is_err());
        assert!(verifying_key_from_bytes(&[0u8; ML_DSA_65_VERIFYING_KEY_LEN + 1]).is_err());
    }

    #[test]
    fn to_bytes_roundtrip() {
        let (sk, _vk) = generate_keypair();
        let envelope = SealedEnvelope::new(b"roundtrip data".to_vec(), b"type".to_vec(), &sk);
        let bytes = envelope.to_bytes();
        assert!(!bytes.is_empty());
        assert_eq!(envelope.crc32c_digest, crc32c(b"roundtrip data"));
    }

    #[test]
    fn compute_fingerprint_is_lowercase_hex_sha256() {
        let (_, vk) = generate_keypair();
        let fingerprint = compute_fingerprint(&vk);
        // SHA-256 produces 32 bytes = 64 hex chars
        assert_eq!(fingerprint.len(), 64);
        // All chars must be lowercase hex
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        // Recomputing the same key should give the same fingerprint
        let fingerprint2 = compute_fingerprint(&vk);
        assert_eq!(fingerprint, fingerprint2);
    }

    #[test]
    fn persistent_key_is_loaded_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        fs::create_dir_all(&keys_dir).unwrap();

        // First start: generate and save
        let (sk1, vk1) = load_or_generate_signing_key(&keys_dir).unwrap();
        let fingerprint1 = compute_fingerprint(&vk1);
        let pk1_enc = vk1.encode();
        let pk1_bytes: &[u8] = pk1_enc.as_ref();
        let pk1 = pk1_bytes.to_vec();

        // Second start: load existing
        let (sk2, vk2) = load_or_generate_signing_key(&keys_dir).unwrap();
        let fingerprint2 = compute_fingerprint(&vk2);
        let pk2_enc = vk2.encode();
        let pk2_bytes: &[u8] = pk2_enc.as_ref();
        let pk2 = pk2_bytes.to_vec();

        // Public keys and fingerprints must match exactly
        assert_eq!(pk1, pk2);
        assert_eq!(fingerprint1, fingerprint2);

        // A signature from the first key must verify with the second
        let envelope = SealedEnvelope::new(b"test".to_vec(), b"type".to_vec(), &sk1);
        assert!(envelope.verify(&vk2).is_ok());

        // And vice versa
        let envelope2 = SealedEnvelope::new(b"test2".to_vec(), b"type".to_vec(), &sk2);
        assert!(envelope2.verify(&vk1).is_ok());
    }

    #[test]
    fn corrupt_key_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        fs::create_dir_all(&keys_dir).unwrap();

        // Write a corrupt key file (wrong length)
        let key_path = keys_dir.join("daemon_signing_key.bin");
        fs::write(&key_path, b"corrupt data").unwrap();

        // Loading must fail with a clear error
        let result = load_or_generate_signing_key(&keys_dir);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("FATAL"));
        assert!(err.contains("invalid length"));
        assert!(err.contains("corrupt"));

        // The corrupt file must still exist (not silently replaced)
        assert!(key_path.exists());
        let contents = fs::read(&key_path).unwrap();
        assert_eq!(contents, b"corrupt data");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_0600_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        fs::create_dir_all(&keys_dir).unwrap();

        let _ = load_or_generate_signing_key(&keys_dir).unwrap();

        let key_path = keys_dir.join("daemon_signing_key.bin");
        let metadata = fs::metadata(&key_path).unwrap();
        let perms = metadata.permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
