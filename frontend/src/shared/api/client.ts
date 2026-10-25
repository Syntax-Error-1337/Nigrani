import { useSession, type SessionUser } from '@/shared/session'

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

export async function getJson<T>(path: string): Promise<T> {
  const res = await apiFetch(path)
  if (!res.ok) {
    const body: unknown = await res.json().catch(() => ({}))
    throw new Error(errorMessage(body, `request failed: ${res.status}`))
  }
  return res.json() as Promise<T>
}

function errorMessage(body: unknown, fallback: string): string {
  if (body !== null && typeof body === 'object' && 'error' in body) {
    const err = body.error
    if (typeof err === 'string' && err.length > 0) return err
  }
  return fallback
}

/// apiFetch that never throws on network failure: unreachable API surfaces
/// as a 503 response so every panel's `!res.ok` branch handles it with the
/// same code path as a server error. (Kiosk stays on raw apiFetch — its
/// offline path needs the throw to route through the cached-CRL logic.)
export async function safeApi(path: string, init: RequestInit = {}): Promise<Response> {
  try {
    return await apiFetch(path, init)
  } catch (e) {
    if (e instanceof TypeError) {
      return new Response(JSON.stringify({ error: 'Network error — is the API running?' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    throw e
  }
}
