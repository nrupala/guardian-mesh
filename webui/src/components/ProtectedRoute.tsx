// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: MIT

import { Navigate } from "react-router-dom"
import { useAuth } from "../lib/auth"

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { token } = useAuth()
  if (!token) return <Navigate to="/login" replace />
  return children
}
