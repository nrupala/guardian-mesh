// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { AuthProvider } from "./lib/auth"
import { Layout } from "./components/Layout"
import { ProtectedRoute } from "./components/ProtectedRoute"
import { HomePage } from "./pages/HomePage"
import { ArchitecturePage } from "./pages/ArchitecturePage"
import { GuidePage } from "./pages/GuidePage"
import { AgentsPage } from "./pages/AgentsPage"
import { LoginPage } from "./pages/LoginPage"
import { LIVE_MODE } from "./lib/gmClient"
import { Setup2FAPage } from "./pages/Setup2FAPage"
import { DashboardPage } from "./pages/DashboardPage"

// The hosted build ships a 404.html fallback (see package.json "build")
// so deep links and refreshes on any route resolve to the app instead of
// the host's error page.
export default function App() {
  // The public build lives under /guardian-mesh/ (GitHub Pages); the
  // guardian.aimlds.org build is served from its domain root and sets
  // VITE_BASE_PATH=/ at build time.
  const basename = (
    import.meta.env.VITE_BASE_PATH ?? "/guardian-mesh/"
  ).replace(/\/$/, "")
  return (
    <BrowserRouter basename={basename || undefined}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<HomePage />} />
            <Route path="architecture" element={<ArchitecturePage />} />
            <Route path="guide" element={<GuidePage />} />
            <Route path="help" element={<GuidePage />} />
            <Route path="agents" element={<AgentsPage />} />
            <Route
              path="panel"
              element={
                LIVE_MODE ? (
                  <DashboardPage />
                ) : (
                  <ProtectedRoute>
                    <DashboardPage />
                  </ProtectedRoute>
                )
              }
            />
          </Route>
          <Route
            path="login"
            element={
              LIVE_MODE ? <Navigate to="/panel" replace /> : <LoginPage />
            }
          />
          <Route path="setup-2fa" element={<Setup2FAPage />} />
          <Route path="dashboard" element={<Navigate to="/panel" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
