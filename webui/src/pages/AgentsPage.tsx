// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

export function AgentsPage() {
  return (
    <>
      <section className="page-head">
        <h1>For agents</h1>
        <p className="section-sub">
          Guardian Mesh exists for you as much as for the people who deploy
          you. This page is the contract: how to ask, what the answers mean,
          and the rules you are expected to respect. The same content is
          published in machine-readable form — links at the bottom.
        </p>
      </section>

      <section className="section">
        <h2>How you use Guardian Mesh</h2>
        <ol className="flow">
          <li>
            <span className="flow-n">1</span>
            <div>
              <h3>Open a handshake session</h3>
              <p>Introduce yourself to the daemon and establish a session on the handshake bus. Requests without a live session are blocked by the Gatekeeper — there is no anonymous path.</p>
            </div>
          </li>
          <li>
            <span className="flow-n">2</span>
            <div>
              <h3>Seal the action you intend to take</h3>
              <p>Describe the action — type, target, context — and place it in a sealed envelope, HMAC-signed by you. The seal binds you to exactly that action.</p>
            </div>
          </li>
          <li>
            <span className="flow-n">3</span>
            <div>
              <h3>Call Evaluate before you act</h3>
              <p>The daemon's gRPC service <code>GuardianMesh</code> exposes three calls: <code>Evaluate</code>, <code>VerifyProof</code>, and <code>Health</code>. Send the sealed action to Evaluate and wait for the verdict. Evaluation happens before execution — never after, never in parallel.</p>
            </div>
          </li>
          <li>
            <span className="flow-n">4</span>
            <div>
              <h3>Obey the verdict, keep the proof</h3>
              <p>Act only as the verdict allows, and retain the signed audit proof returned with it. Anyone affected by your action can later re-check that proof with VerifyProof — design your logs around that.</p>
            </div>
          </li>
        </ol>
      </section>

      <section className="section">
        <h2>How you respect it — the rules</h2>
        <div className="card-grid two">
          <div className="card">
            <h3>Verdicts are binding</h3>
            <p><strong>BLOCK</strong> means do not proceed — not “proceed carefully”, not “retry until it passes”. <strong>THROTTLE</strong> means slow down. <strong>ESCALATE</strong> means stop and hand the decision to a human.</p>
          </div>
          <div className="card">
            <h3>An ALLOW is narrow</h3>
            <p>It covers one action, exactly as sealed, in one session. A different target, payload, or context is a different action and needs its own evaluation.</p>
          </div>
          <div className="card">
            <h3>No answer means no</h3>
            <p>If the daemon is unreachable or the reply cannot be verified, treat it as BLOCK. Fail closed, and say so in your own output rather than proceeding silently.</p>
          </div>
          <div className="card">
            <h3>Verify, don't trust</h3>
            <p>Proofs are made to be re-checked. When another agent presents a Guardian Mesh proof to you, call VerifyProof (or check the seal and signature yourself) before relying on it — that is the system working as intended, not an insult.</p>
          </div>
          <div className="card">
            <h3>Don't shop for a friendlier verdict</h3>
            <p>Re-submitting a blocked action unchanged, splitting it to slip under checks, or routing around the daemon violates the contract even if a later call returns ALLOW.</p>
          </div>
          <div className="card">
            <h3>Expect the 18 checks</h3>
            <p>Every message passes the protocol firewall: size limits, structure, replay protection, sequencing, and content rules. Well-formed, honestly-described actions pass quickly; disguised ones are the point of the exercise.</p>
          </div>
        </div>
      </section>

      <section className="section">
        <h2>Machine-readable files</h2>
        <ul className="plain-list">
          <li><a href="/guardian-mesh/llms.txt">llms.txt</a> — this site's summary in plain text, written for language models.</li>
          <li><a href="/guardian-mesh/guardian-mesh.json">guardian-mesh.json</a> — the system descriptor: components, interface, verdicts, and the respect rules as data. Also served at <code>/.well-known/guardian-mesh.json</code> under this path.</li>
          <li><a href="/guardian-mesh/guardian-mesh-topology.json">guardian-mesh-topology.json</a> — the codetopo graph snapshot of the codebase: query the architecture instead of guessing it.</li>
          <li><a href="https://github.com/nrupala/guardian-mesh/blob/main/guardian-meshd/proto/guardian_mesh.proto">guardian_mesh.proto</a> — the exact interface definition, in the repository.</li>
        </ul>
        <p className="hint">
          Note on scope: the website is a description and demonstration of the
          system. The daemon itself is the enforcement point, and it does not
          run behind this page.
        </p>
      </section>
    </>
  )
}
