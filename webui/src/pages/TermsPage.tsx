// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

export function TermsPage() {
  return (
    <>
      <section className="page-head">
        <h1>Terms of use</h1>
        <p className="section-sub">
          The terms for this website and the Guardian Mesh control panel.
        </p>
      </section>

      <section className="section">
        <h2>What these terms cover</h2>
        <p className="body-text">
          These terms govern use of this website and the Guardian Mesh
          control panel at guardian.aimlds.org, operated by{" "}
          <strong>2351485 ALBERTA INC.</strong> The Guardian Mesh product
          itself — the daemon and its packaged distributions — is governed by
          the{" "}
          <a href="https://github.com/nrupala/guardian-mesh/blob/main/TERMS.md">
            Product Terms
          </a>{" "}
          in the source repository and by its licence (Apache License 2.0
          plus the AIMLDS Payment Rider). For the product, the Product Terms
          control to the extent of any conflict with this page.
        </p>
      </section>

      <section className="section">
        <h2>Authorized use</h2>
        <p className="body-text">
          The control panel is an internal operator console. It may be used
          only by operators authorized by 2351485 ALBERTA INC., and only for
          operating and monitoring Guardian Mesh. Reach the panel and the
          daemon only through the sign-in provided, and submit for evaluation
          only actions you have the right to submit.
        </p>
      </section>

      <section className="section">
        <h2>Decisions remain yours</h2>
        <p className="body-text">
          Guardian Mesh returns verdicts and proofs; it does not make
          decisions for you. Operators remain responsible for what they
          approve, deploy, and run, and for independently evaluating any
          output before acting on it.
        </p>
      </section>

      <section className="section">
        <h2>Provided as is</h2>
        <p className="body-text">
          This site and the control panel are provided &ldquo;as is&rdquo;
          and &ldquo;as available,&rdquo; without warranties of any kind, to
          the maximum extent permitted by applicable law. The full warranty,
          liability, and damages terms for the product are set out in the
          Product Terms.
        </p>
      </section>

      <section className="section">
        <h2>Law, changes, and questions</h2>
        <p className="body-text">
          These terms are governed by the laws of Alberta and the federal
          laws of Canada applicable in Alberta. If these terms change, the
          new version will be posted on this page with its date. This version
          is dated November 11, 2026. Questions about these terms go to{" "}
          <a href="mailto:info@aimlds.org">info@aimlds.org</a>.
        </p>
      </section>
    </>
  )
}
