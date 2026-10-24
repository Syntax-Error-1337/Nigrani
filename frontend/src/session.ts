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

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const send = async (token: string | null): Promise<Response> =>
    fetch(path, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    })
  const { accessToken, logout } = useSession.getState()
  const res = await send(accessToken)
  // One silent rotation on 401 (never for the refresh call itself —
  // that path reports family death directly). Only a failed rotation
  // logs out: revoked/locked/expired families are the true logged-out
  // states; a merely-expired access token is not.
  if (res.status !== 401 || path === '/auth/refresh') {
    if (res.status === 401) logout()
    return res
  }
  if (!(await refreshNow())) {
    logout()
    return res
  }
  return send(useSession.getState().accessToken)
}

/// In-flight rotation promise (single-flight: parallel 401s share ONE
/// rotation — the server burns reused tokens, so a second concurrent
/// rotation would nuke the family).
let rotation: Promise<boolean> | null = null

/// Rotate the session pair. Returns true on success (store updated).
export function refreshNow(): Promise<boolean> {
  if (rotation) return rotation
  rotation = (async () => {
    const { refreshToken } = useSession.getState()
    if (!refreshToken) return false
    let res: Response
    try {
      res = await fetch('/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      })
    } catch {
      return false
    }
    if (!res.ok) return false
    const body: unknown = await res.json().catch(() => null)
    if (
      body === null ||
      typeof body !== 'object' ||
      !('access_token' in body) ||
      !('refresh_token' in body) ||
      !('user' in body) ||
      typeof body.access_token !== 'string' ||
      typeof body.refresh_token !== 'string'
    ) {
      return false
    }
    const user = body.user as SessionUser
    if (typeof user?.role !== 'string') return false
    useSession.getState().login(body.access_token, body.refresh_token, user)
    return true
  })().finally(() => {
    rotation = null
  })
  return rotation
}
