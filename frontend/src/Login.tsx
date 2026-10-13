import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSession, type SessionUser } from './session'

export default function Login() {
  const navigate = useNavigate()
  const login = useSession((s) => s.login)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      const body: unknown = await res.json().catch(() => ({}))
      if (!res.ok) {
        const err =
          body !== null && typeof body === 'object' && 'error' in body ? body.error : null
        setError(typeof err === 'string' && err.length > 0 ? err : 'Sign in failed')
        return
      }
      if (!isLoginBody(body)) {
        setError('Unexpected sign-in response')
        return
      }
      login(
        body.access_token,
        body.refresh_token,
        {
          id: body.user.id,
          username: body.user.username,
          role: body.user.role as SessionUser['role'],
        },
      )
      navigate('/dashboard', { replace: true })
    } catch {
      setError('Network error — is the API running?')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-paper p-6">
      <section className="w-full max-w-sm border-2 border-ink bg-white p-8 shadow-[6px_6px_0_0_var(--color-ink)]">
        <p className="font-ledger text-xs tracking-widest text-signal">NIGRANI</p>
        <h1 className="mt-2 font-display text-4xl uppercase">Checkpoint sign in</h1>
        <form onSubmit={submit} className="mt-6 flex flex-col gap-4">
          <label className="flex flex-col gap-1 text-sm">
            Callsign (username)
            <input
              className="border border-ink px-3 py-2"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            Passphrase
            <input
              type="password"
              className="border border-ink px-3 py-2"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          {error ? (
            <p role="alert" className="border border-deny bg-red-50 px-3 py-2 text-sm text-deny">
              {error}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={busy}
            className="bg-ink px-4 py-2 font-display text-lg uppercase tracking-wide text-paper disabled:opacity-50"
          >
            {busy ? 'Verifying…' : 'Enter checkpoint'}
          </button>
        </form>
        <p className="mt-4 font-ledger text-xs text-neutral-500">
          Seeded sign-ins: superadmin · commander · gate · verifier · analyst (password: password)
        </p>
      </section>
    </main>
  )
}

interface LoginBody {
  access_token: string
  refresh_token: string
  user: { id: string; username: string; role: string }
}

function isLoginBody(body: unknown): body is LoginBody {
  if (body === null || typeof body !== 'object') return false
  if (!('access_token' in body) || !('user' in body)) return false
  const { access_token, user } = body
  if (typeof access_token !== 'string') return false
  if (user === null || typeof user !== 'object') return false
  return (
    'id' in user &&
    'username' in user &&
    'role' in user &&
    typeof user.id === 'string' &&
    typeof user.username === 'string' &&
    typeof user.role === 'string'
  )
}
