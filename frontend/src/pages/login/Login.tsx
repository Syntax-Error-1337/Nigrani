import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSession, type SessionUser } from '@/shared/session'

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
    <main id="main-content" className="flex min-h-screen bg-paper p-6">
      <section
        className="relative hidden w-1/2 flex-col justify-between overflow-hidden rounded-2xl bg-navy p-10 text-white md:flex"
        aria-hidden="true"
      >
        <div className="font-semibold text-lg tracking-tight">
          <span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-saffron" /> Nigrani
          <span className="ml-2 text-xs font-normal text-white/60">सेंटिनेल-गार्ड</span>
        </div>
        <div
          className="absolute inset-0 opacity-[0.14]"
          style={{
            backgroundImage:
              'repeating-linear-gradient(90deg, #fff 0 1px, transparent 1px 48px), repeating-linear-gradient(0deg, #fff 0 1px, transparent 1px 64px)',
          }}
        />
        <div className="relative max-w-sm">
          <p className="text-4xl font-semibold leading-tight tracking-tight">
            Every crossing, accounted for.
          </p>
          <p className="mt-3 text-sm leading-relaxed text-slate-300">
            Gate access management for protest sites — press vetting, live crossings, incidents
            and the audit chain, from one console.
          </p>
        </div>
      </section>
      <section className="flex w-full items-center md:w-1/2">
        <div className="mx-auto w-full max-w-sm">
          <p className="font-semibold text-lg tracking-tight md:hidden">
            <span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-saffron" /> Nigrani
          </p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">Sign in</h1>
          <p className="mt-1 text-sm text-slate-500">Use your operations callsign.</p>
          <form onSubmit={submit} className="mt-6 flex flex-col gap-4">
            <label className="flex flex-col gap-1 text-sm">
              Username
              <input
                className="border border-slate-300 bg-white px-3 py-2.5 shadow-sm"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              Password
              <input
                type="password"
                className="border border-slate-300 bg-white px-3 py-2.5 shadow-sm"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </label>
            {error ? (
              <p role="alert" className="rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
                {error}
              </p>
            ) : null}
            <button
              type="submit"
              disabled={busy}
              className="mt-1 bg-signal px-4 py-2.5 text-base font-semibold text-white hover:bg-signal-deep disabled:opacity-50"
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
          <p className="mt-6 rounded-md border border-slate-200 bg-white px-3 py-2 font-ledger text-xs text-slate-500">
            Seeded sign-ins: superadmin · commander · gate · verifier · analyst (password:
            password)
          </p>
        </div>
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
