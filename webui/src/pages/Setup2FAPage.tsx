import { useState, useEffect } from "react"
import { useNavigate } from "react-router-dom"
import { QRCodeSVG } from "qrcode.react"
import { useAuth } from "../lib/auth"

export function Setup2FAPage() {
  const { user, setup2FA } = useAuth()
  const navigate = useNavigate()
  const [totpCode, setTotpCode] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [qrUrl, setQrUrl] = useState("")
  const [secret, setSecret] = useState("")

  useEffect(() => {
    const fetchSetup = async () => {
      try {
        const res = await fetch("/api/2fa-setup-info", {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: user }),
          method: "POST",
        })
        const data = await res.json()
        if (res.ok) {
          setQrUrl(data.otpauth_url)
          setSecret(data.secret)
        }
      } catch {
        // backend not available — show placeholder
      }
    }
    fetchSetup()
  }, [user])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      await setup2FA(totpCode)
      navigate("/")
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Verification failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <h1>Set Up Two-Factor Auth</h1>
          <p className="subtitle">Scan with your authenticator app</p>
        </div>

        <div className="qr-section">
          {qrUrl ? (
            <QRCodeSVG value={qrUrl} size={200} level="M" />
          ) : (
            <div className="qr-placeholder">
              <span>Waiting for server...</span>
            </div>
          )}
          {secret && (
            <p className="secret-text">
              Or enter manually: <code>{secret}</code>
            </p>
          )}
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="field">
            <label htmlFor="verify-code">Enter the 6-digit code from your app</label>
            <input id="verify-code" type="text" inputMode="numeric" value={totpCode} onChange={e => setTotpCode(e.target.value)} placeholder="000000" autoFocus required />
          </div>
          <button type="submit" disabled={loading} className="btn-primary">
            {loading ? "Verifying..." : "Verify & Enable"}
          </button>
          {error && <p className="error-msg">{error}</p>}
        </form>
      </div>
    </div>
  )
}
