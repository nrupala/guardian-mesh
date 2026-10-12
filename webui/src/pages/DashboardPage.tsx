// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { useAuth } from "../lib/auth"

export function DashboardPage() {
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
            <button className="action-btn" disabled>View Audit Log</button>
            <button className="action-btn" disabled>Run Evaluation</button>
            <button className="action-btn" disabled>Verify Proof</button>
            <button className="action-btn" disabled>Health Check</button>
          </div>
          <p className="hint">Actions become available when connected to the daemon.</p>
        </section>
      </main>
    </div>
  )
}
