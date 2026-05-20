import { createContext, useContext, useState, useCallback, type ReactNode } from "react"

interface AuthState {
  token: string | null
  user: string | null
  requires2FASetup: boolean
}

interface AuthContextType extends AuthState {
  login: (username: string, password: string, totpCode?: string) => Promise<void>
  setup2FA: (totpCode: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | null>(null)

const API_BASE = import.meta.env.VITE_API_BASE || ""

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    token: localStorage.getItem("gm_token"),
    user: localStorage.getItem("gm_user"),
    requires2FASetup: false,
  })

  const login = useCallback(async (username: string, password: string, totpCode?: string) => {
    const res = await fetch(`${API_BASE}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, totp_code: totpCode }),
    })
    const data = await res.json()
    if (!res.ok) {
      if (res.status === 428 && data.requires_2fa_setup) {
        setState({ token: null, user: username, requires2FASetup: true })
        throw new Error("2FA_SETUP_REQUIRED")
      }
      throw new Error(data.error || "Login failed")
    }
    localStorage.setItem("gm_token", data.token)
    localStorage.setItem("gm_user", username)
    setState({ token: data.token, user: username, requires2FASetup: false })
  }, [])

  const setup2FA = useCallback(async (totpCode: string) => {
    const res = await fetch(`${API_BASE}/api/setup-2fa`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: state.user, totp_code: totpCode }),
    })
    const data = await res.json()
    if (!res.ok) throw new Error(data.error || "2FA setup failed")
    localStorage.setItem("gm_token", data.token)
    setState({ token: data.token, user: state.user, requires2FASetup: false })
  }, [state.user])

  const logout = useCallback(() => {
    localStorage.removeItem("gm_token")
    localStorage.removeItem("gm_user")
    setState({ token: null, user: null, requires2FASetup: false })
  }, [])

  return (
    <AuthContext.Provider value={{ ...state, login, setup2FA, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used within AuthProvider")
  return ctx
}
