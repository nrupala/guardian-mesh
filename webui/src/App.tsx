// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: MIT

import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { AuthProvider } from "./lib/auth"
import { ProtectedRoute } from "./components/ProtectedRoute"
import { LoginPage } from "./pages/LoginPage"
import { Setup2FAPage } from "./pages/Setup2FAPage"
import { DashboardPage } from "./pages/DashboardPage"

export default function App() {
  return (
    <BrowserRouter basename="/guardian-mesh">
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/setup-2fa" element={<Setup2FAPage />} />
          <Route path="/" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
