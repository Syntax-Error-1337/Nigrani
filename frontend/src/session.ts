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
  user: SessionUser | null
  login: (accessToken: string, user: SessionUser) => void
  logout: () => void
}

const STORAGE_KEY = 'nigrani/session/v1'

function loadInitial(): Pick<SessionState, 'accessToken' | 'user'> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { accessToken: null, user: null }
    const parsed = JSON.parse(raw) as { accessToken: string; user: SessionUser }
    if (typeof parsed.accessToken !== 'string' || !parsed.user?.role) {
      return { accessToken: null, user: null }
    }
    return parsed
  } catch {
    return { accessToken: null, user: null }
  }
}

export const useSession = create<SessionState>()((set) => ({
  ...loadInitial(),
  login: (accessToken, user) => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ accessToken, user }))
    set({ accessToken, user })
  },
  logout: () => {
    localStorage.removeItem(STORAGE_KEY)
    set({ accessToken: null, user: null })
  },
}))

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const { accessToken, logout } = useSession.getState()
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...init.headers,
    },
  })
  if (res.status === 401) logout()
  return res
}
