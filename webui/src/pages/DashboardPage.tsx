// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react"
import { RpcError } from "@protobuf-ts/runtime-rpc"
import { useAuth } from "../lib/auth"
import {
  LIVE_MODE,
  daemonClient,
  fetchHealth,
  runEvaluation,
  runSimulation,
  sessionState,
  verifyProofEnvelope,
  fetchAuditLog,
  base64ToBytes,
  bytesToBase64,
} from "../lib/gmClient"
import {
  HealthResponse_ServingStatus,
  SealedEnvelope,
} from "../gen/guardian_mesh_pb"
import type {
  EvaluateResponse,
  HealthResponse,
  VerifyProofResponse,
  ReadAuditLogResponse,
} from "../gen/guardian_mesh_pb"

export function DashboardPage() {
  return LIVE_MODE ? <LivePanel /> : <DemoPanel />
}

// ── Demonstration panel (public site build — no daemon endpoint) ────

function DemoPanel() {
  const { user, logout } = useAuth()

  return (
    <div className="dashboard">
      <header className="dash-header">
        <h1>Guardian Mesh</h1>
        <div className="dash-user">
          <span>{user}</span>
          <button onClick={logout} className="btn-ghost">Sign Out</button>
        </div>
      </header>

      <main className="dash-content">
        <div className="demo-banner" role="note">
          <strong>Demonstration panel.</strong> The values below are samples
          showing the panel's shape — this page is not connected to a running
          daemon, so nothing here is a live measurement. Actions stay disabled
          until a real daemon connection exists; a button that pretended to
          run an evaluation would be a lie in exactly the place this product
          exists to prevent.
        </div>

        <div className="status-cards">
          <div className="card">
            <h3>Daemon</h3>
            <p className="status-info">Sample: Running</p>
          </div>
          <div className="card">
            <h3>Protocol Firewall</h3>
            <p className="status-info">18 checks (as coded)</p>
          </div>
          <div className="card">
            <h3>Auth</h3>
            <p className="status-info">Sample: 2FA Enabled</p>
          </div>
          <div className="card">
            <h3>Enclaves</h3>
            <p className="status-info">5 guardians (by design)</p>
          </div>
        </div>

        <section className="dash-section">
          <h2>Quick Actions</h2>
          <div className="action-grid">
            <button className="action-btn" disabled>Run Evaluation</button>
            <button className="action-btn" disabled>Simulate (dry run)</button>
            <button className="action-btn" disabled>Verify Proof</button>
            <button className="action-btn" disabled>Health Check</button>
          </div>
          <p className="hint">Actions become available when connected to the daemon. The working panel lives at guardian.aimlds.org.</p>
        </section>
      </main>
    </div>
  )
}

// ── Live panel (guardian.aimlds.org build — real daemon) ────────────

const ACTION_TYPES: { value: string; label: string }[] = [
  { value: "TOOL_CALL", label: "Use a tool" },
  { value: "NETWORK_REQUEST", label: "Make a network request" },
  { value: "FILE_READ", label: "Read a file" },
  { value: "FILE_WRITE", label: "Write a file" },
  { value: "GENERATE", label: "Generate content" },
  { value: "CODE_EXECUTE", label: "Run code" },
  { value: "AGENT_SPAWN", label: "Start another agent" },
  { value: "AGENT_MESSAGE", label: "Message another agent" },
  { value: "MEMORY_READ", label: "Read memory" },
  { value: "MEMORY_WRITE", label: "Write memory" },
  { value: "MODEL_LOAD", label: "Load a model" },
]

type EvalOutcome =
  | { kind: "verdict"; response: EvaluateResponse }
  | { kind: "blocked"; reason: string }
  | { kind: "error"; message: string }

function servingLabel(status: HealthResponse_ServingStatus | undefined): string {
  switch (status) {
    case HealthResponse_ServingStatus.SERVING:
      return "Serving"
    case HealthResponse_ServingStatus.DEGRADED:
      return "Degraded"
    case HealthResponse_ServingStatus.NOT_SERVING:
      return "Not serving"
    default:
      return "Unknown"
  }
}

function LivePanel() {
  const client = daemonClient()
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthError, setHealthError] = useState<string | null>(null)
  const [checkingHealth, setCheckingHealth] = useState(false)
  const [sessionTick, setSessionTick] = useState(0)

  const [actionType, setActionType] = useState("TOOL_CALL")
  const [context, setContext] = useState("")
  const [target, setTarget] = useState("")
  const [evaluating, setEvaluating] = useState(false)
  const [simulating, setSimulating] = useState(false)
  const [outcome, setOutcome] = useState<EvalOutcome | null>(null)
  const [simOutcome, setSimOutcome] = useState<EvaluateResponse | null>(null)

  const [pasteEnvelope, setPasteEnvelope] = useState("")
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState<VerifyProofResponse | null>(null)
  const [verifyError, setVerifyError] = useState<string | null>(null)

  const [auditLog, setAuditLog] = useState<ReadAuditLogResponse | null>(null)
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditError, setAuditError] = useState<string | null>(null)

  const evalRef = useRef<HTMLElement | null>(null)
  const verifyRef = useRef<HTMLElement | null>(null)
  const auditRef = useRef<HTMLElement | null>(null)

  const doHealth = useCallback(async () => {
    setCheckingHealth(true)
    try {
      const h = await fetchHealth(client)
      setHealth(h)
      setHealthError(null)
    } catch (e) {
      setHealthError(e instanceof Error ? e.message : String(e))
    } finally {
      setCheckingHealth(false)
    }
  }, [client])

  useEffect(() => {
    let cancelled = false
    fetchHealth(client)
      .then((h) => {
        if (!cancelled) {
          setHealth(h)
          setHealthError(null)
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setHealthError(e instanceof Error ? e.message : String(e))
        }
      })
    return () => {
      cancelled = true
    }
  }, [client])

  const doEvaluate = async () => {
    setEvaluating(true)
    setOutcome(null)
    setVerifyResult(null)
    try {
      const response = await runEvaluation(client, {
        actionType,
        context: context || "Requested from the guardian.aimlds.org control panel",
        target: target || "panel",
      })
      setOutcome({ kind: "verdict", response })
    } catch (e) {
      if (e instanceof RpcError && /permission/i.test(e.code)) {
        // The Sentinel or Gatekeeper blocked the action before a
        // verdict: the daemon delivers that BLOCK as an error
        // carrying the enclave's reason.
        setOutcome({ kind: "blocked", reason: e.message })
      } else {
        setOutcome({
          kind: "error",
          message: e instanceof Error ? e.message : String(e),
        })
      }
    } finally {
      setEvaluating(false)
      setSessionTick((t) => t + 1)
      void doHealth()
    }
  }

  const doSimulate = async () => {
    setSimulating(true)
    setSimOutcome(null)
    try {
      const response = await runSimulation(client, {
        actionType,
        context: context || "Requested from the guardian.aimlds.org control panel",
        target: target || "panel",
      })
      setSimOutcome(response)
    } catch (e) {
      // Simulate should not error on verdict outcomes, but handle
      // unexpected errors
      setSimOutcome(null)
      console.error("Simulation error:", e)
    } finally {
      setSimulating(false)
    }
  }

  const doVerify = async (envelope: SealedEnvelope) => {
    setVerifying(true)
    setVerifyResult(null)
    setVerifyError(null)
    try {
      const res = await verifyProofEnvelope(client, envelope)
      setVerifyResult(res)
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : String(e))
    } finally {
      setVerifying(false)
    }
  }

  const doVerifyPasted = async () => {
    let envelope: SealedEnvelope
    try {
      envelope = SealedEnvelope.fromBinary(base64ToBytes(pasteEnvelope.trim()))
    } catch {
      setVerifyResult(null)
      setVerifyError("That text is not a sealed proof envelope (base64 expected).")
      return
    }
    await doVerify(envelope)
  }

  const doFetchAuditLog = async () => {
    setAuditLoading(true)
    setAuditError(null)
    try {
      const log = await fetchAuditLog(client)
      setAuditLog(log)
    } catch (e) {
      setAuditError(e instanceof Error ? e.message : String(e))
    } finally {
      setAuditLoading(false)
    }
  }

  const sess = sessionState()
  void sessionTick // session card re-renders when evaluations run

  const enclaveEntries = health ? Object.entries(health.enclaveHealth) : []
  const enclavesOk = enclaveEntries.filter(([, v]) => v === "ok").length

  const lastEnvelope =
    outcome?.kind === "verdict" ? outcome.response.proofEnvelope : undefined

  return (
    <div className="dashboard">
      <header className="dash-header">
        <h1>Guardian Mesh</h1>
        <div className="dash-user">
          <span>guardian.aimlds.org</span>
          <a href="/cdn-cgi/access/logout" className="btn-ghost">Sign Out</a>
        </div>
      </header>

      <main className="dash-content">
        {health ? (
          <div className="demo-banner live-banner" role="note">
            <strong>Live panel.</strong> Connected to the Guardian Mesh daemon
            running on this machine — every value and verdict below is a real
            answer from it, produced when you asked.
          </div>
        ) : (
          <div className="demo-banner" role="alert">
            <strong>Daemon not reached.</strong>{" "}
            {healthError
              ? `The health check failed: ${healthError}`
              : "Checking the daemon…"}
            {" "}Nothing below is a live value until the daemon answers.
          </div>
        )}

        <div className="status-cards">
          <div className="card">
            <h3>Daemon</h3>
            <p className="status-info">
              {health ? servingLabel(health.status) : "—"}
            </p>
          </div>
          <div className="card">
            <h3>Protocol Firewall</h3>
            <p className="status-info">
              {health
                ? `${health.protocolFirewallRulesPassed} checks passed`
                : "—"}
            </p>
            <p className="status-sub">
              {health
                ? `of ${health.protocolFirewallRulesTotal} firewall checks run since the daemon started`
                : ""}
            </p>
            {health && health.protocolFirewallRuleCounters && Object.keys(health.protocolFirewallRuleCounters).length > 0 && (
              <div className="status-sub" style={{ marginTop: "0.5rem" }}>
                {Object.entries(health.protocolFirewallRuleCounters)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([rule, counts]) => (
                    <div key={rule}>
                      {rule}: {counts}
                    </div>
                  ))}
              </div>
            )}
          </div>
          <div className="card">
            <h3>Session</h3>
            <p className="status-info">
              {sess.established ? "Handshake open" : "Not opened yet"}
            </p>
            <p className="status-sub">
              {sess.established
                ? `session ${sess.id?.slice(0, 8)}… — opens with your first evaluation`
                : "opens with your first evaluation"}
            </p>
          </div>
          <div className="card">
            <h3>Guardians</h3>
            <p className="status-info">
              {health ? `${enclavesOk} / ${enclaveEntries.length} healthy` : "—"}
            </p>
            <p className="status-sub">
              {health ? enclaveEntries.map(([k]) => k).join(" · ") : ""}
            </p>
          </div>
        </div>

        <section className="dash-section">
          <h2>Quick Actions</h2>
          <div className="action-grid">
            <button
              className="action-btn"
              onClick={() => void doHealth()}
              disabled={checkingHealth}
            >
              {checkingHealth ? "Checking…" : "Health Check"}
            </button>
            <button
              className="action-btn"
              onClick={() =>
                auditRef.current?.scrollIntoView({ behavior: "smooth" })
              }
            >
              View Audit Log
            </button>
            <button
              className="action-btn"
              onClick={() =>
                evalRef.current?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Run Evaluation
            </button>
            <button
              className="action-btn"
              onClick={() =>
                verifyRef.current?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Verify Proof
            </button>
          </div>
          <p className="hint">
            Every action below talks to the daemon when you press it — nothing
            is pre-computed.
          </p>
        </section>

        <section className="dash-section" ref={auditRef}>
          <h2>Audit Log</h2>
          <p className="hint">
            The audit trail lists every evaluation the daemon has made, in
            append order, with chain verification status showing whether the
            log is intact.
          </p>
          <button
            className="action-btn"
            onClick={() => void doFetchAuditLog()}
            disabled={auditLoading}
          >
            {auditLoading ? "Loading…" : "Load Audit Log"}
          </button>
          {auditLog && (
            <div className="audit-log-container">
              {auditLog.verification && (
                <div
                  className={`verdict-panel ${auditLog.verification.verified ? "verdict-allow" : "verdict-block"}`}
                >
                  <p className="verdict-word">
                    Chain: {auditLog.verification.verified ? "VERIFIED" : "BROKEN"}
                  </p>
                  <p>{auditLog.verification.statusMessage}</p>
                  <p className="status-sub">
                    Entries checked: {auditLog.verification.entriesChecked}
                    {!auditLog.verification.verified &&
                      ` · First break at position ${auditLog.verification.firstBreakPosition}`}
                  </p>
                </div>
              )}
              {auditLog.entries.length === 0 ? (
                <p className="hint">No entries in the audit log yet.</p>
              ) : (
                <div className="audit-entries">
                  {auditLog.entries.map((entry) => (
                    <div key={entry.sequence} className="audit-entry card">
                      <div className="audit-entry-header">
                        <span className="audit-seq">#{entry.sequence}</span>
                        <span className={`verdict-tag verdict-${entry.verdict.toLowerCase()}`}>
                          {entry.verdict}
                        </span>
                        <span className="audit-timestamp">
                          {new Date(Number(entry.timestamp) * 1000).toLocaleString()}
                        </span>
                      </div>
                      <div className="audit-entry-body">
                        <p>
                          <strong>Action:</strong> {entry.actionId}
                        </p>
                        <p>
                          <strong>Reason:</strong> {entry.reason || "(none)"}
                        </p>
                        <p className="status-sub">
                          Chain: {entry.enclaveChain}
                        </p>
                        <p className="status-sub">
                          Hash: {entry.chainHash.slice(0, 16)}…
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
          {auditError && (
            <div className="verdict-panel verdict-block">
              <p className="verdict-word">Could not load audit log</p>
              <p>{auditError}</p>
            </div>
          )}
        </section>

        <section className="dash-section" ref={evalRef}>
          <h2>Run an evaluation</h2>
          <p className="hint">
            Describe an action an agent wants to take. The guardians check it
            and answer with a verdict and a sealed proof.
          </p>
          <div className="gm-form">
            <label className="gm-field">
              <span>Action</span>
              <select
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
              >
                {ACTION_TYPES.map((a) => (
                  <option key={a.value} value={a.value}>
                    {a.label} ({a.value})
                  </option>
                ))}
              </select>
            </label>
            <label className="gm-field">
              <span>Why (context)</span>
              <input
                type="text"
                value={context}
                onChange={(e) => setContext(e.target.value)}
                placeholder="Requested from the control panel"
              />
            </label>
            <label className="gm-field">
              <span>Target</span>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="panel"
              />
            </label>
            <div className="action-grid">
              <button
                className="action-btn"
                onClick={() => void doEvaluate()}
                disabled={evaluating}
              >
                {evaluating ? "Asking the guardians…" : "Ask Guardian Mesh"}
              </button>
              <button
                className="action-btn"
                onClick={() => void doSimulate()}
                disabled={simulating}
              >
                {simulating ? "Simulating…" : "Simulate (dry run)"}
              </button>
            </div>
          </div>

          {outcome?.kind === "verdict" && (
            <div className={`verdict-panel verdict-${outcome.response.verdict.toLowerCase()}`}>
              <p className="verdict-word">{outcome.response.verdict}</p>
              <p>{outcome.response.reason}</p>
              <p className="status-sub">
                Containment stage: {outcome.response.containmentStage}
                {outcome.response.proof &&
                  ` · Proof: ${outcome.response.proof.enclaveChain} · signed by the Witness (${outcome.response.proof.signature.length} bytes) · ${new Date(
                    Number(outcome.response.proof.timestamp) * 1000,
                  ).toLocaleString()}`}
              </p>
              {lastEnvelope && (
                <>
                  <div className="action-grid">
                    <button
                      className="action-btn"
                      onClick={() => void doVerify(lastEnvelope)}
                      disabled={verifying}
                    >
                      {verifying ? "Verifying…" : "Verify this proof"}
                    </button>
                    <button
                      className="action-btn"
                      onClick={() =>
                        void navigator.clipboard.writeText(
                          bytesToBase64(SealedEnvelope.toBinary(lastEnvelope)),
                        )
                      }
                    >
                      Copy the sealed proof
                    </button>
                  </div>
                  <p className="hint">
                    The sealed proof is the daemon-signed envelope for this
                    verdict. Anyone can paste it into the verify section below
                    and have the daemon re-check it.
                  </p>
                </>
              )}
            </div>
          )}
          {outcome?.kind === "blocked" && (
            <div className="verdict-panel verdict-block">
              <p className="verdict-word">BLOCK</p>
              <p>{outcome.reason}</p>
              <p className="status-sub">
                Stopped by the Sentinel or the Gatekeeper before a verdict —
                the daemon reports these blocks as errors carrying the reason.
              </p>
            </div>
          )}
          {outcome?.kind === "error" && (
            <div className="verdict-panel verdict-block">
              <p className="verdict-word">No answer</p>
              <p>The evaluation could not be completed: {outcome.message}</p>
            </div>
          )}

          {simOutcome && (
            <div className={`verdict-panel verdict-${simOutcome.verdict.toLowerCase()}`}>
              <p className="verdict-word">SIMULATION — no execution rights, nothing was executed or logged</p>
              <p className="verdict-word">{simOutcome.verdict}</p>
              <p>{simOutcome.reason}</p>
              <p className="status-sub">
                Containment stage: {simOutcome.containmentStage}
              </p>
              {simOutcome.reasons && simOutcome.reasons.length > 0 && (
                <div className="structured-reasons">
                  <h4>Structured reasons:</h4>
                  <ul>
                    {simOutcome.reasons.map((r, i) => (
                      <li key={i}>
                        <strong>{r.ruleId}</strong>: {r.detail}
                        {r.remediation && (
                          <div className="remediation">
                            <em>Remediation:</em> {r.remediation}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </section>

        <section className="dash-section" ref={verifyRef}>
          <h2>Verify a proof</h2>
          <p className="hint">
            Paste a sealed proof envelope (base64) from any evaluation. The
            daemon re-checks its integrity digest and its ML-DSA-65
            signature — a tampered proof fails.
          </p>
          <div className="gm-form">
            <label className="gm-field">
              <span>Sealed proof envelope</span>
              <textarea
                value={pasteEnvelope}
                onChange={(e) => setPasteEnvelope(e.target.value)}
                rows={4}
                placeholder="Paste base64 here"
              />
            </label>
            <button
              className="action-btn"
              onClick={() => void doVerifyPasted()}
              disabled={verifying || !pasteEnvelope.trim()}
            >
              {verifying ? "Verifying…" : "Verify"}
            </button>
          </div>
          {verifyResult && (
            <div
              className={`verdict-panel ${verifyResult.valid ? "verdict-allow" : "verdict-block"}`}
            >
              <p className="verdict-word">
                {verifyResult.valid ? "VALID" : "NOT VALID"}
              </p>
              <p>{verifyResult.reason}</p>
            </div>
          )}
          {verifyError && (
            <div className="verdict-panel verdict-block">
              <p className="verdict-word">Could not verify</p>
              <p>{verifyError}</p>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}
