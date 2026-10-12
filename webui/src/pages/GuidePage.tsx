// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom"

export function GuidePage() {
  return (
    <>
      <section className="page-head">
        <h1>User guide & help</h1>
        <p className="section-sub">
          What Guardian Mesh is, how to use everything on this site, and
          instructions for running the daemon itself.
        </p>
      </section>

      <section className="section">
        <h2>What Guardian Mesh is, in one paragraph</h2>
        <p className="body-text">
          Guardian Mesh is a guardian system for AI agents and software. Before
          an agent runs a command, calls a tool, or reaches the network, the
          action is sent to the Guardian Mesh daemon. Five specialised
          components examine it — message checks, identity, policy — and the
          daemon answers with a verdict and a signed proof of that decision.
          The proof can be re-verified later by anyone, without trusting the
          daemon, this website, or us.
        </p>
      </section>

      <section className="section">
        <h2>Getting started on this site</h2>
        <ol className="flow">
          <li><span className="flow-n">1</span><div><h3>Start with the overview</h3><p>The <Link to="/">front page</Link> explains what the system does for you and introduces the five guardians in plain words.</p></div></li>
          <li><span className="flow-n">2</span><div><h3>See how it is built</h3><p>The <Link to="/architecture">Architecture</Link> page shows the real structure of the code, measured with codetopo — not a marketing diagram.</p></div></li>
          <li><span className="flow-n">3</span><div><h3>Look at the control panel</h3><p>Open the <Link to="/login">control panel</Link> with the demonstration login below and see the shape of the operator's view.</p></div></li>
          <li><span className="flow-n">4</span><div><h3>If you are an agent</h3><p>Go straight to <Link to="/agents">For Agents</Link>: the calling contract, the verdict rules you must respect, and the machine-readable files.</p></div></li>
        </ol>
      </section>

      <section className="section">
        <h2>Using the demonstration panel — step by step</h2>
        <ol className="flow">
          <li><span className="flow-n">1</span><div><h3>Sign in</h3><p>Username <code>admin</code>, password <code>guardian</code>. This is a public demo login printed here on purpose — it is not a security boundary.</p></div></li>
          <li><span className="flow-n">2</span><div><h3>Set up two-factor (demo)</h3><p>The panel shows a QR code for an authenticator app. In this demonstration any 6-digit code is accepted — the step exists to show the flow, and it is labeled that way because a fake check presented as real would be exactly what this product exists to prevent.</p></div></li>
          <li><span className="flow-n">3</span><div><h3>Read the panel honestly</h3><p>Status values are samples marked “Sample”. The panel is not connected to a running daemon — a browser page cannot speak the daemon's native gRPC protocol yet — so the action buttons stay disabled rather than pretend.</p></div></li>
          <li><span className="flow-n">4</span><div><h3>Sign out</h3><p>The Sign Out button ends the demo session and clears it from your browser.</p></div></li>
        </ol>
      </section>

      <section className="section">
        <h2>The four verdicts</h2>
        <div className="card-grid two">
          <div className="card"><h3>ALLOW</h3><p>The action may proceed — this action only, exactly as described. Change the action and it needs a fresh evaluation.</p></div>
          <div className="card"><h3>BLOCK</h3><p>The action must not proceed. Guardian Mesh fails closed: a missing signature, an expired session, or an undecided policy all end here.</p></div>
          <div className="card"><h3>THROTTLE</h3><p>The action may proceed, but more slowly — used when rate or load limits are being approached.</p></div>
          <div className="card"><h3>ESCALATE</h3><p>A human decides. The action waits until a person reviews it.</p></div>
        </div>
      </section>

      <section className="section">
        <h2>Running the daemon — operator instructions</h2>
        <p className="body-text">
          Guardian Mesh is local-first: you run the daemon on your own
          infrastructure and your proofs stay with you. From the{" "}
          <a href="https://github.com/nrupala/guardian-mesh">repository</a>:
        </p>
        <ol className="flow">
          <li><span className="flow-n">1</span><div><h3>Build and start the daemon</h3><p><code>cargo build --release</code> then <code>cargo run --release</code>. It listens on <code>127.0.0.1:50051</code> (override with the <code>GUARDIAN_MESH_PORT</code> environment variable).</p></div></li>
          <li><span className="flow-n">2</span><div><h3>Connect a client</h3><p>Clients speak gRPC to the <code>GuardianMesh</code> service (<code>Evaluate</code>, <code>VerifyProof</code>, <code>Health</code>) defined in <code>guardian-meshd/proto/guardian_mesh.proto</code>. The <Link to="/agents">For Agents</Link> page describes the calling contract.</p></div></li>
          <li><span className="flow-n">3</span><div><h3>Run the tests</h3><p><code>cargo test</code> runs the daemon's unit suite (31 tests at this version), covering the firewall checks, the enclaves, and the envelope seal.</p></div></li>
          <li><span className="flow-n">4</span><div><h3>Build this website</h3><p>In <code>webui/</code>: <code>npm run dev</code> for local development, <code>npm run build</code> for the production bundle, <code>npm run lint</code> for the lint gate CI enforces.</p></div></li>
        </ol>
      </section>

      <section className="section">
        <h2>Words we use, in plain language</h2>
        <div className="card-grid two">
          <div className="card"><h3>Sealed envelope</h3><p>The tamper-evident wrapper every request travels in. If anyone changes the contents on the way, the seal breaks and the action is blocked.</p></div>
          <div className="card"><h3>Handshake session</h3><p>A short-lived “we have introduced ourselves and proven it” pass between a caller and the daemon. No valid session, no service.</p></div>
          <div className="card"><h3>Audit proof</h3><p>The signed record of a verdict: what was asked, what was decided, why, and the containment stage reached. The Vault seals it; VerifyProof re-checks it.</p></div>
          <div className="card"><h3>Certificate</h3><p>A proof about a specific item that was tested — this code, this version, this policy, this date. It vouches for the test that happened, never for how someone later chooses to deploy the item.</p></div>
        </div>
      </section>

      <section className="section">
        <h2>Questions people ask</h2>
        <div className="card-grid two">
          <div className="card"><h3>Does Guardian Mesh phone home?</h3><p>No. The daemon is local-first: it runs on your infrastructure and its proofs live with you.</p></div>
          <div className="card"><h3>Can a verdict be changed afterwards?</h3><p>The record cannot be quietly edited — it is signed and sealed. A wrong verdict is answered with a new evaluation and a revocation record, in the open.</p></div>
          <div className="card"><h3>What if the daemon is down?</h3><p>Callers should treat “no answer” as BLOCK. Guardian Mesh is designed to fail closed, and integrations are expected to do the same.</p></div>
          <div className="card"><h3>I am an AI agent. Where do I start?</h3><p>The <Link to="/agents">For Agents</Link> page: the contract, the verdict rules you must respect, and the machine-readable files.</p></div>
        </div>
      </section>
    </>
  )
}
