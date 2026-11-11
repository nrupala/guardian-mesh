// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

export function PrivacyPage() {
  return (
    <>
      <section className="page-head">
        <h1>Privacy</h1>
        <p className="section-sub">
          What this site and the Guardian Mesh control panel handle, in plain
          words.
        </p>
      </section>

      <section className="section">
        <h2>Who operates this site</h2>
        <p className="body-text">
          This site and the Guardian Mesh control panel are operated by{" "}
          <strong>2351485 ALBERTA INC.</strong>, the Alberta company behind
          AIMLDS. Guardian Mesh is a guardian system for AI agents and
          software: an action is checked before it runs, and every verdict is
          sealed into a proof that can be re-checked later.
        </p>
      </section>

      <section className="section">
        <h2>Who the control panel is for</h2>
        <p className="body-text">
          The control panel at guardian.aimlds.org is an internal operator
          console, not a public service. Sign-in is handled by Cloudflare
          Access and is limited to authorized operators while the deployment
          matures.
        </p>
      </section>

      <section className="section">
        <h2>What the console handles</h2>
        <p className="body-text">
          Two kinds of information, and nothing beyond them:
        </p>
        <ul className="body-text">
          <li>
            <strong>Sign-in identity.</strong> Cloudflare Access identifies
            the operator who signed in (their email address) and passes that
            identity to the console. The console does not collect sign-in
            details from anyone else.
          </li>
          <li>
            <strong>System records.</strong> The panel displays records the
            daemon itself produces while it works: actions submitted for
            evaluation, the verdicts issued, sealed proof certificates, and
            the audit log. These records exist so that every decision can be
            re-checked — that is the product&rsquo;s purpose.
          </li>
        </ul>
        <p className="body-text">
          The public pages of this site are static. The site&rsquo;s own code
          sets no advertising or analytics cookies and loads no third-party
          trackers. Cloudflare, which runs the sign-in gate and delivers the
          site, may set strictly functional cookies for those purposes.
        </p>
      </section>

      <section className="section">
        <h2>What we do not do</h2>
        <p className="body-text">
          We do not sell personal information, and we do not share console
          records with advertisers or data brokers. Console records are kept
          on infrastructure operated by 2351485 ALBERTA INC. so the audit
          trail stays verifiable.
        </p>
      </section>

      <section className="section">
        <h2>Questions</h2>
        <p className="body-text">
          Questions about privacy on this site go to{" "}
          <a href="mailto:info@aimlds.org">info@aimlds.org</a>. If this page
          changes, the new version will be posted here with its date. This
          version is dated November 11, 2026.
        </p>
      </section>
    </>
  )
}
