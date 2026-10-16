// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use crc32c::crc32c;
use ml_dsa::{MlDsa65, Keypair, SigningKey, VerifyingKey, Signer, Verifier, SignatureEncoding, Signature};
use rand::rngs::SysRng;
use rand::TryRng;
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
    let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::from_slice(bytes);
    Ok(VerifyingKey::<MlDsa65>::decode(enc))
}

pub fn generate_keypair() -> (SigningKey<MlDsa65>, VerifyingKey<MlDsa65>) {    let mut seed_bytes = [0u8; 32];
    let _ = SysRng.try_fill_bytes(&mut seed_bytes);
    let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice())
        .expect("32 bytes fits Seed");
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
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
}
