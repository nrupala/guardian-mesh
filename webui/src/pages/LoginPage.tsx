// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react"
import { useNavigate, Navigate } from "react-router-dom"
import { useAuth } from "../lib/auth"

export function LoginPage() {
  const { login, token } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [totpCode, setTotpCode] = useState("")
  const [step, setStep] = useState<"credentials" | "totp">("credentials")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  // Already signed in (the demo session persists in this browser):
  // never show the form again — go straight to the panel.
  if (token) {
    return <Navigate to="/panel" replace />
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      if (step === "credentials") {
        await login(username, password)
      } else {
        await login(username, password, totpCode)
      }
      navigate("/panel")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      if (msg === "2FA_SETUP_REQUIRED") {
        navigate("/setup-2fa")
        return
      }
      if (msg.toLowerCase().includes("totp") || msg.toLowerCase().includes("2fa")) {
        setStep("totp")
      }
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <svg className="logo" viewBox="0 0 40 40" width="48" height="48">
            <rect x="2" y="2" width="36" height="36" rx="8" fill="none" stroke="currentColor" strokeWidth="3" />
            <path d="M12 20 L18 26 L28 14" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <h1>Guardian Mesh</h1>
          <p className="subtitle">Secure Control Panel</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {step === "credentials" ? (
            <>
              <div className="field">
                <label htmlFor="username">Username</label>
                <input id="username" type="text" value={username} onChange={e => setUsername(e.target.value)} autoFocus required />
              </div>
              <div className="field">
                <label htmlFor="password">Password</label>
                <input id="password" type="password" value={password} onChange={e => setPassword(e.target.value)} required />
              </div>
              <button type="submit" disabled={loading} className="btn-primary">
                {loading ? "Signing in..." : "Sign In"}
              </button>
            </>
          ) : (
            <>
              <div className="field">
                <label htmlFor="totp">Authenticator Code</label>
                <input id="totp" type="text" inputMode="numeric" autoComplete="one-time-code" value={totpCode} onChange={e => setTotpCode(e.target.value)} placeholder="000000" autoFocus required />
              </div>
              <button type="submit" disabled={loading} className="btn-primary">
                {loading ? "Verifying..." : "Verify"}
              </button>
              <button type="button" className="btn-ghost" onClick={() => { setStep("credentials"); setTotpCode("") }}>
                Back
              </button>
            </>
          )}

          {error && <p className="error-msg">{error}</p>}
        </form>

        <p className="hint login-demo-hint">
          Demonstration login — username <code>admin</code>, password{" "}
          <code>guardian</code>. The panel shows sample values and is not
          connected to a live daemon. <a href="/guardian-mesh/guide">Why?</a>
        </p>
      </div>
    </div>
  )
}
