// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: MIT

use super::{EnclaveContext, Verdict, ContainmentStage};
use sha2::{Sha256, Digest};
use ml_dsa::{MlDsa65, SigningKey, Signer, SignatureEncoding};

pub struct WitnessEnclave;

impl WitnessEnclave {
    pub fn evaluate(ctx: &mut EnclaveContext, signing_key: &SigningKey<MlDsa65>) {
        ctx.stage = ContainmentStage::Throttle;

        let mut hasher = Sha256::new();
        hasher.update(b"guardian-mesh:witness");
        hasher.update(ctx.verdict.as_ref().map(|v| v.as_str()).unwrap_or("UNKNOWN").as_bytes());
        hasher.update(ctx.reason.as_deref().unwrap_or("no reason"));
        let digest = hasher.finalize();

        let sig = signing_key.sign(&digest);
        ctx.witness_signature = sig.to_bytes().to_vec();

        ctx.verdict = Some(Verdict::Allow);
        ctx.reason = Some("Witness signed audit proof, forwarding to Arbiter".into());
    }
}
