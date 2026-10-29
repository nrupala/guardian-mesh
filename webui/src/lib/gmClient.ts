// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

// Live-daemon client for the control panel.
//
// The build is "live" when VITE_GUARDIAN_MESH_ENDPOINT names the
// daemon's gRPC-web base URL (the guardian.aimlds.org build sets it
// to its own origin). The public GitHub Pages build leaves it unset:
// the panel then stays in its labeled demonstration mode and nothing
// on that page pretends to be a live measurement.

import { GrpcWebFetchTransport } from "@protobuf-ts/grpcweb-transport"
import { GuardianMeshClient } from "../gen/guardian_mesh_pb.client"
import type {
  ActionDescriptor,
  EvaluateResponse,
  HealthResponse,
  SealedEnvelope,
  VerifyProofResponse,
  ReadAuditLogResponse,
  PolicyBundleMessage,
  RevocationStatusResponse,
  AuthenticatorStatusResponse,
} from "../gen/guardian_mesh_pb"

export const DAEMON_ENDPOINT: string | null =
  import.meta.env.VITE_GUARDIAN_MESH_ENDPOINT || null

export const LIVE_MODE = DAEMON_ENDPOINT !== null

let clientSingleton: GuardianMeshClient | null = null

export function daemonClient(): GuardianMeshClient {
  if (!DAEMON_ENDPOINT) {
    throw new Error("This build has no daemon endpoint configured.")
  }
  if (!clientSingleton) {
    clientSingleton = new GuardianMeshClient(
      new GrpcWebFetchTransport({ baseUrl: DAEMON_ENDPOINT }),
    )
  }
  return clientSingleton
}

// ── CRC32C (Castagnoli) — the envelope integrity digest ─────────────

const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let crc = i
    for (let j = 0; j < 8; j++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1
    }
    table[i] = crc >>> 0
  }
  return table
})()

export function crc32c(data: Uint8Array): number {
  let crc = 0xffffffff
  for (const b of data) {
    crc = CRC32C_TABLE[(crc ^ b) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

// ── Small byte helpers ───────────────────────────────────────────────

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = ""
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s/g, ""))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new Uint8Array(data))
  return new Uint8Array(sig)
}

// ── Handshake session ────────────────────────────────────────────────
// The session key is a bearer credential: it lives in memory only,
// never in storage, and is renewed when the daemon's TTL runs out.

interface Session {
  id: string
  key: Uint8Array
  expiresAtMs: number
}

let session: Session | null = null
let clientKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null

// The client's ML-DSA-65 identity for this page session. The public
// key is registered with the daemon at Handshake time and the daemon
// verifies every envelope signature against it (WO-1), so the
// keypair is created before the session opens and never leaves
// memory.
async function getClientKeyPair(): Promise<{
  publicKey: Uint8Array
  secretKey: Uint8Array
}> {
  if (!clientKeyPair) {
    const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js")
    clientKeyPair = ml_dsa65.keygen()
  }
  return clientKeyPair
}

export function sessionState(): { established: boolean; id?: string } {
  if (session && Date.now() < session.expiresAtMs) {
    return { established: true, id: session.id }
  }
  return { established: false }
}

async function ensureSession(client: GuardianMeshClient): Promise<Session> {
  if (session && Date.now() < session.expiresAtMs - 30_000) return session
  const keyPair = await getClientKeyPair()
  const res = await client.handshake({
    sourceEnclave: "webui",
    sourcePublicKey: keyPair.publicKey,
    // WO-14: the WebUI does not present a SPIFFE SVID in v1; the fields
    // are sent empty (attestation stays a workload-to-daemon capability).
    spiffeId: "",
    svidLeafDer: new Uint8Array(),
    svidSignature: new Uint8Array(),
  }).response
  const ttlMs = Number(res.ttlSeconds || "300") * 1000
  session = {
    id: res.sessionId,
    key: res.sessionKey,
    expiresAtMs: Date.now() + ttlMs,
  }
  return session
}

// ── The evaluation flow ──────────────────────────────────────────────
// Mirrors the daemon's client protocol exactly:
//   1. Handshake -> session id + HMAC key; the handshake registers
//      this client's ML-DSA-65 public key with the session
//   2. Seal the action payload: CRC32C digest + ML-DSA-65 signature
//      over (crc32c as little-endian u32 || payload), the daemon's
//      own signing layout — the daemon verifies it against the
//      registered key before the action is judged
//   3. HMAC-SHA256 the payload with the session key
//   4. Evaluate or Simulate
//
// A BLOCK from the Sentinel or Gatekeeper in real Evaluate arrives as a
// permission-denied error carrying the enclave's reason — callers
// should read RpcError.code for that case. Simulate never errors on a
// verdict outcome: every block returns as Ok(EvaluateResponse).

export interface ActionInput {
  actionType: string
  context: string
  target: string
}

export async function runEvaluation(
  client: GuardianMeshClient,
  action: ActionInput,
): Promise<EvaluateResponse> {
  const s = await ensureSession(client)

  const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js")
  const keyPair = await getClientKeyPair()

  const descriptor: ActionDescriptor = {
    actionType: action.actionType,
    context: action.context,
    target: action.target,
    metadata: { source: "webui" },
  }
  const payload = new TextEncoder().encode(JSON.stringify(descriptor))
  const crc = crc32c(payload)

  const crcLe = new Uint8Array(4)
  new DataView(crcLe.buffer).setUint32(0, crc, true)
  const toSign = new Uint8Array(crcLe.length + payload.length)
  toSign.set(crcLe, 0)
  toSign.set(payload, crcLe.length)
  const signature = ml_dsa65.sign(toSign, keyPair.secretKey)

  const nonce = new Uint8Array(32)
  crypto.getRandomValues(nonce)

  const envelope: SealedEnvelope = {
    payload,
    payloadType: new TextEncoder().encode("guardian_mesh.ActionDescriptor"),
    crc32C: crc,
    mlDsa65Signature: signature,
    // Unix nanoseconds, as the daemon's envelope format specifies.
    timestamp: (BigInt(Date.now()) * 1_000_000n).toString(),
    nonce,
  }

  const hmacTag = await hmacSha256(s.key, payload)

  return client.evaluate({
    firewalled: {
      envelope,
      sourceEnclave: "webui",
      handshakeSession: s.id,
      hmacTag,
    },
    action: descriptor,
  }).response
}

export async function runSimulation(
  client: GuardianMeshClient,
  action: ActionInput,
): Promise<EvaluateResponse> {
  const s = await ensureSession(client)

  const { ml_dsa65 } = await import("@noble/post-quantum/ml-dsa.js")
  const keyPair = await getClientKeyPair()

  const descriptor: ActionDescriptor = {
    actionType: action.actionType,
    context: action.context,
    target: action.target,
    metadata: { source: "webui" },
  }
  const payload = new TextEncoder().encode(JSON.stringify(descriptor))
  const crc = crc32c(payload)

  const crcLe = new Uint8Array(4)
  new DataView(crcLe.buffer).setUint32(0, crc, true)
  const toSign = new Uint8Array(crcLe.length + payload.length)
  toSign.set(crcLe, 0)
  toSign.set(payload, crcLe.length)
  const signature = ml_dsa65.sign(toSign, keyPair.secretKey)

  // Each call seals a FRESH envelope with a fresh nonce, exactly like
  // runEvaluation — that is what makes "simulate, then really evaluate
  // the same action" work.
  const nonce = new Uint8Array(32)
  crypto.getRandomValues(nonce)

  const envelope: SealedEnvelope = {
    payload,
    payloadType: new TextEncoder().encode("guardian_mesh.ActionDescriptor"),
    crc32C: crc,
    mlDsa65Signature: signature,
    timestamp: (BigInt(Date.now()) * 1_000_000n).toString(),
    nonce,
  }

  const hmacTag = await hmacSha256(s.key, payload)

  return client.simulate({
    firewalled: {
      envelope,
      sourceEnclave: "webui",
      handshakeSession: s.id,
      hmacTag,
    },
    action: descriptor,
  }).response
}

export async function fetchHealth(
  client: GuardianMeshClient,
): Promise<HealthResponse> {
  return client.health({}).response
}

export async function verifyProofEnvelope(
  client: GuardianMeshClient,
  proofEnvelope: SealedEnvelope,
): Promise<VerifyProofResponse> {
  return client.verifyProof({ proofEnvelope }).response
}

export async function fetchAuditLog(
  client: GuardianMeshClient,
): Promise<ReadAuditLogResponse> {
  return client.readAuditLog({}).response
}

export async function getPolicy(
  client: GuardianMeshClient,
): Promise<PolicyBundleMessage> {
  return client.getPolicy({}).response
}

export async function getRevocationSummary(
  client: GuardianMeshClient,
): Promise<RevocationStatusResponse> {
  return client.revocationStatus({ kind: "", targetId: "" }).response
}

export async function getAuthenticatorSummary(
  client: GuardianMeshClient,
): Promise<AuthenticatorStatusResponse> {
  return client.authenticatorStatus({}).response
}
