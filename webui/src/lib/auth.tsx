/* eslint-disable react-refresh/only-export-components */

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

const PASSWORD_HASH = "dde6e8974b46a1eddcd7ea3bbb899342f48cad896b47275a6f806062ec5ca14c"
const AuthContext = createContext<AuthContextType | null>(null)

async function sha256(input: string): Promise<string> {
  const enc = new TextEncoder()
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(input))
  const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("")
  return hex
}

function genToken(user: string): string {
  return `gm_${user}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => ({
    token: localStorage.getItem("gm_token"),
    user: localStorage.getItem("gm_user"),
    requires2FASetup: localStorage.getItem("gm_2fa_done") !== "true" && !!localStorage.getItem("gm_user"),
  }))
  const [lastUser, setLastUser] = useState<string>("")

  const login = useCallback(async (username: string, password: string, totpCode?: string) => {
    const hash = await sha256(password)
    if (username !== "admin" || hash !== PASSWORD_HASH) {
      throw new Error("Invalid username or password")
    }
    if (!totpCode) {
      if (localStorage.getItem("gm_2fa_done") !== "true") {
        setState({ token: null, user: username, requires2FASetup: true })
        setLastUser(username)
        throw new Error("2FA_SETUP_REQUIRED")
      }
      throw new Error("2FA code required")
    }
    const token = genToken(username)
    localStorage.setItem("gm_token", token)
    localStorage.setItem("gm_user", username)
    setState({ token, user: username, requires2FASetup: false })
  }, [])

  const setup2FA = useCallback(async (_totpCode: string) => {
    const username = lastUser || state.user || "admin"
    const token = genToken(username)
    localStorage.setItem("gm_token", token)
    localStorage.setItem("gm_user", username)
    localStorage.setItem("gm_2fa_done", "true")
    setState({ token, user: username, requires2FASetup: false })
  }, [lastUser, state.user])

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
