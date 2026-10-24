// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { RELEASES } from "../data/releases"

export function ReleasesPage() {
  return (
    <>
      <section className="page-head">
        <h1>Releases</h1>
        <p className="section-sub">
          The public release log — what changed in each Guardian Mesh release
          and how it was tested. This page is fed from the project's CHANGELOG
          and release-gate records, updated as part of each release. Guardian
          Mesh is licensed under the Apache License 2.0 + Payment Rider.
        </p>
      </section>

      <section className="section">
        <div className="releases-list">
          {RELEASES.map((release) => (
            <article key={release.version} className="release-card">
              <header className="release-header">
                <h2 className="release-version">
                  {release.version}
                  <span className="release-date">{release.date}</span>
                </h2>
                <span className={`release-status release-status-${release.status.toLowerCase().replace(/\s+/g, '-')}`}>
                  {release.status}
                </span>
              </header>

              <p className="release-summary">{release.summary}</p>

              <div className="release-section">
                <h3>Highlights</h3>
                <ul className="release-highlights">
                  {release.highlights.map((highlight, idx) => (
                    <li key={idx}>{highlight}</li>
                  ))}
                </ul>
              </div>

              <div className="release-section">
                <h3>Testing Record</h3>
                <div className="release-testing">
                  <p>
                    <strong>Gate verdict:</strong> {release.gateVerdict}
                  </p>
                  <p>
                    <strong>Tests:</strong> {release.tests}
                  </p>
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  )
}
