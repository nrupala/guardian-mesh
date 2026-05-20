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
        <div className="status-cards">
          <div className="card">
            <h3>Daemon</h3>
            <p className="status-ok">● Running</p>
          </div>
          <div className="card">
            <h3>Protocol Firewall</h3>
            <p className="status-info">18 rules</p>
          </div>
          <div className="card">
            <h3>Auth</h3>
            <p className="status-ok">● 2FA Enabled</p>
          </div>
          <div className="card">
            <h3>Enclaves</h3>
            <p className="status-ok">5 / 5 active</p>
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
