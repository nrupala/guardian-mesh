// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

const MODULES: Array<[string, string, string]> = [
  ["guardian-meshd/src/main.rs", "The daemon: serves Evaluate, VerifyProof, and Health over gRPC and runs the enclave pipeline. Its evaluate handler is the most-connected symbol in the codebase (39 graph connections).", "1 class · 4 methods · 2 functions"],
  ["guardian-meshd/src/protocol_firewall.rs", "The protocol firewall: the 18 message checks every request must pass (size, structure, replay, rate, and content rules).", "3 classes · 9 methods · 8 functions"],
  ["guardian-meshd/src/enclave/sentinel.rs", "Sentinel: runs the firewall check over the sealed payload, context, and target.", "1 class · 1 method · 1 function"],
  ["guardian-meshd/src/enclave/gatekeeper.rs", "Gatekeeper: requires a live handshake session and a valid HMAC before anything proceeds.", "1 class · 1 method"],
  ["guardian-meshd/src/enclave/witness.rs", "Witness: hashes the verdict and its reason, and signs the digest with ML-DSA-65.", "1 class · 1 method"],
  ["guardian-meshd/src/enclave/arbiter.rs", "Arbiter: applies policy and settles the final verdict; unsettled means blocked.", "1 class · 1 method · 2 functions"],
  ["guardian-meshd/src/enclave/vault.rs", "Vault: seals the signed audit proof. Its seal function is the second most-connected symbol (32 connections).", "2 classes · 4 methods · 5 functions"],
  ["guardian-meshd/src/enclave/mod.rs", "Shared enclave types: the verdicts and containment stages every guardian works with.", "3 classes · 3 methods · 3 functions"],
  ["guardian-meshd/src/handshake_bus.rs", "The handshake bus: issues and tracks the sessions Gatekeeper checks.", "2 classes · 7 methods · 5 functions"],
  ["guardian-meshd/src/sealed_envelope.rs", "The sealed envelope: integrity (CRC32C) and payload verification for messages in transit.", "1 class · 4 methods · 7 functions"],
  ["guardian-meshd/src/policy.rs", "The policy engine the Arbiter applies: thresholds, stages, and escalation rules.", "2 classes · 5 methods · 5 functions"],
  ["guardian-meshd/src/config.rs", "Daemon configuration, including the guard that the daemon never writes into program directories.", "1 class · 9 methods · 2 functions"],
  ["webui/src", "This website and the demonstration control panel (React + TypeScript).", "7 source files"],
]

export function ArchitecturePage() {
  return (
    <>
      <section className="page-head">
        <h1>Architecture, measured — not drawn from memory</h1>
        <p className="section-sub">
          This page is generated from a <strong>codetopo</strong> scan of the
          Guardian Mesh repository itself: codetopo indexes the source into a
          queryable graph of symbols and the calls, imports, and references
          between them. The numbers below are that scan's output for
          version 0.1.5 — the same graph an agent can download and query.
        </p>
      </section>

      <section className="section">
        <div className="stat-grid">
          <div className="stat"><span className="stat-n">24</span><span className="stat-l">source files indexed</span></div>
          <div className="stat"><span className="stat-n">581</span><span className="stat-l">symbols (graph nodes)</span></div>
          <div className="stat"><span className="stat-n">1,176</span><span className="stat-l">connections (graph edges)</span></div>
          <div className="stat"><span className="stat-n">557</span><span className="stat-l">call edges</span></div>
          <div className="stat"><span className="stat-n">324</span><span className="stat-l">reference edges</span></div>
          <div className="stat"><span className="stat-n">86</span><span className="stat-l">import edges</span></div>
        </div>
        <p className="hint">
          Symbol mix: 51 functions, 49 methods, 19 classes, 3 interfaces across
          the Rust daemon and this web UI. Full snapshot:{" "}
          <a href="/guardian-mesh/guardian-mesh-topology.json">guardian-mesh-topology.json</a>{" "}
          (codetopo JSON export, unsigned).
        </p>
      </section>

      <section className="section">
        <h2>The shape of the system</h2>
        <p className="section-sub">
          Two programs and one contract. The <strong>daemon</strong> (Rust) does
          the guarding. The <strong>web UI</strong> (this site) explains and
          demonstrates it. Between callers and the daemon sits the{" "}
          <strong>contract</strong>: the gRPC service definition
          (<code>guardian_mesh.proto</code>) with three calls — Evaluate,
          VerifyProof, Health. The call graph confirms the design: nearly every
          path runs through <code>evaluate</code> in the daemon and out through
          the Vault's <code>seal</code> — check first, proof last, nothing in
          between is optional.
        </p>
      </section>

      <section className="section">
        <h2>Module by module</h2>
        <div className="table-wrap">
          <table className="mod-table">
            <thead>
              <tr><th>Module</th><th>What it does</th><th>Contents</th></tr>
            </thead>
            <tbody>
              {MODULES.map(([f, d, c]) => (
                <tr key={f}><td><code>{f}</code></td><td>{d}</td><td>{c}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section">
        <h2>Designed, not yet in the graph</h2>
        <p className="section-sub">
          The v2 design adds hardware enclave (TEE) attestation, multi-node
          consensus, public anchoring of proof batches, and Lean 4 formal
          verification of the core. None of that exists in the code above yet —
          when it does, this scan will show it, and this page will change with
          the graph, not with a marketing calendar.
        </p>
      </section>
    </>
  )
}
