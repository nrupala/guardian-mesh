// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom"

const GUARDIANS = [
  {
    name: "Sentinel",
    role: "First check",
    plain: "Watches every incoming request and runs the protocol firewall's 18 checks on it — malformed, oversized, or suspicious actions are caught here first.",
  },
  {
    name: "Gatekeeper",
    role: "Identity & permission",
    plain: "Checks identity and permission. The caller must hold a valid handshake session and a correct message signature, or the action is blocked on the spot.",
  },
  {
    name: "Witness",
    role: "Signs the record",
    plain: "Writes down what was decided and why, then signs the record with a post-quantum signature (ML-DSA-65) so it cannot be quietly rewritten later.",
  },
  {
    name: "Arbiter",
    role: "Final decision",
    plain: "Applies the policy and settles the final verdict — allow, block, throttle, or escalate to a human. If anything is undecided, the default is block.",
  },
  {
    name: "Vault",
    role: "Seals the proof",
    plain: "Seals the signed record into a tamper-evident proof envelope. That proof is the certificate anyone can re-check later, without trusting us.",
  },
]

const FLOW = [
  ["1", "An agent asks", "Software or an AI agent wants to do something — call a tool, run code, reach the network."],
  ["2", "Sealed and checked", "The request travels in a sealed, signed envelope through the protocol firewall's 18 checks."],
  ["3", "Five guardians review", "Sentinel, Gatekeeper, Witness, and Arbiter each examine it in turn; any one of them can stop it."],
  ["4", "A verdict is returned", "Allow, block, throttle, or escalate — with the reason stated, never silent."],
  ["5", "Proof is sealed", "The Vault seals the signed record. The verdict ships with evidence anyone can verify independently."],
]

export function HomePage() {
  return (
    <>
      <section className="hero">
        <h1>Every action checked before it runs.<br />Every verdict proven afterwards.</h1>
        <p className="hero-sub">
          Guardian Mesh is a guardian system for AI agents and software. It sits
          between an agent and the tools it wants to use, examines every action
          before it happens, and seals the decision into a proof that anyone can
          re-check — without having to trust the guardian.
        </p>
        <div className="hero-ctas">
          <Link to="/guide" className="btn-primary">How it works</Link>
          <Link to="/agents" className="btn-ghost">I am an agent — how do I use it?</Link>
        </div>
      </section>

      <section className="section">
        <h2>What it does for you</h2>
        <div className="card-grid">
          <div className="card">
            <h3>Nothing runs unchecked</h3>
            <p>Tool calls, code execution, and network requests are evaluated <em>before</em> they execute — not logged after the damage.</p>
          </div>
          <div className="card">
            <h3>Proof, not promises</h3>
            <p>Every verdict comes with a signed, tamper-evident proof. Re-check it yourself, any time, without an account with us.</p>
          </div>
          <div className="card">
            <h3>It fails closed</h3>
            <p>Missing signature, expired session, undecided policy — the default answer is <strong>block</strong>, not “probably fine”.</p>
          </div>
          <div className="card">
            <h3>Yours, on your machine</h3>
            <p>Guardian Mesh is a local-first daemon. Your actions and proofs stay on infrastructure you control.</p>
          </div>
        </div>
      </section>

      <section className="section">
        <h2>The five guardians</h2>
        <p className="section-sub">
          Five specialised components — enclaves — examine every action in
          sequence, carried over a handshake bus in sealed envelopes. Two
          supporting pieces hold them together: the <strong>Protocol Firewall</strong>,
          which runs the 18 message checks, and the <strong>Policy</strong> engine
          the Arbiter applies.
        </p>
        <div className="card-grid">
          {GUARDIANS.map(g => (
            <div className="card" key={g.name}>
              <h3>{g.name} <span className="stage">{g.role}</span></h3>
              <p>{g.plain}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="section">
        <h2>How an action flows</h2>
        <ol className="flow">
          {FLOW.map(([n, title, body]) => (
            <li key={n}>
              <span className="flow-n">{n}</span>
              <div>
                <h3>{title}</h3>
                <p>{body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="section">
        <h2>What is real today, and what is still design</h2>
        <div className="card-grid two">
          <div className="card">
            <h3 className="status-ok">Working today</h3>
            <ul className="plain-list">
              <li>The Rust daemon with its three services: Evaluate, VerifyProof, Health</li>
              <li>The five enclaves and the protocol firewall's 18 checks</li>
              <li>Sealed envelopes with ML-DSA-65 signatures and CRC32C integrity</li>
              <li>Signed audit proofs that VerifyProof can re-check</li>
              <li>This website and the demonstration control panel</li>
            </ul>
          </div>
          <div className="card">
            <h3 className="status-info">Designed — not yet built</h3>
            <ul className="plain-list">
              <li>Hardware enclave (TEE) attestation</li>
              <li>Multi-node consensus between guardians</li>
              <li>Public anchoring of proof batches</li>
              <li>Formal verification of the core in Lean 4</li>
              <li>A live connection from this website to a running daemon</li>
            </ul>
          </div>
        </div>
        <p className="hint">
          We label the difference because the proof is the product — a guardian
          that exaggerates cannot be trusted to verify anything else.
        </p>
      </section>
    </>
  )
}
