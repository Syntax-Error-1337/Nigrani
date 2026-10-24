import { create } from 'zustand'

export type Role =
  | 'SuperAdmin'
  | 'SiteCommander'
  | 'GateOperator'
  | 'VerificationOfficer'
  | 'ForensicAnalyst'

export interface SessionUser {
  id: string
  username: string
  role: Role
}

interface SessionState {
  accessToken: string | null
  refreshToken: string | null
  user: SessionUser | null
  login: (accessToken: string, refreshToken: string, user: SessionUser) => void
  logout: () => void
}

export const STORAGE_KEY = 'nigrani/session/v1'

function loadInitial(): Pick<SessionState, 'accessToken' | 'refreshToken' | 'user'> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { accessToken: null, refreshToken: null, user: null }
    const parsed = JSON.parse(raw) as {
      accessToken: string
      refreshToken: string
      user: SessionUser
    }
    if (typeof parsed.accessToken !== 'string' || !parsed.user?.role) {
      return { accessToken: null, refreshToken: null, user: null }
    }
    return {
      accessToken: parsed.accessToken,
      refreshToken: typeof parsed.refreshToken === 'string' ? parsed.refreshToken : null,
      user: parsed.user,
    }
  } catch {
    return { accessToken: null, refreshToken: null, user: null }
  }
}

export const useSession = create<SessionState>()((set) => ({
  ...loadInitial(),
  login: (accessToken, refreshToken, user) => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ accessToken, refreshToken, user }))
    set({ accessToken, refreshToken, user })
  },
  logout: () => {
    // Server-side revocation first (best-effort), then local wipe.
    const { refreshToken } = useSession.getState()
    if (refreshToken) {
      fetch('/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      }).catch(() => {})
    }
    localStorage.removeItem(STORAGE_KEY)
    set({ accessToken: null, refreshToken: null, user: null })
  },
}))
