// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { Link, NavLink, Outlet } from "react-router-dom"

export function Layout() {
  return (
    <div className="site">
      <header className="site-header">
        <Link to="/" className="brand">
          <svg className="logo" viewBox="0 0 40 40" width="30" height="30" aria-hidden="true">
            <rect x="2" y="2" width="36" height="36" rx="8" fill="none" stroke="currentColor" strokeWidth="3" />
            <path d="M12 20 L18 26 L28 14" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span>Guardian Mesh</span>
        </Link>
        <nav className="site-nav" aria-label="Main">
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/architecture">Architecture</NavLink>
          <NavLink to="/guide">Guide & Help</NavLink>
          <NavLink to="/agents">For Agents</NavLink>
        </nav>
        <Link to="/panel" className="btn-primary nav-cta">Control Panel</Link>
      </header>

      <main className="site-main">
        <Outlet />
      </main>

      <footer className="site-footer">
        <p>
          Guardian Mesh is built by AIMLDS. This site describes the system as it
          actually is — working parts and designs are labeled as such.
        </p>
        <p className="footer-links">
          <a href="/guardian-mesh/llms.txt">llms.txt</a>
          <span aria-hidden="true">·</span>
          <a href="/guardian-mesh/guardian-mesh.json">Machine-readable description</a>
          <span aria-hidden="true">·</span>
          <a href="https://github.com/nrupala/guardian-mesh">Source on GitHub</a>
        </p>
      </footer>
    </div>
  )
}
