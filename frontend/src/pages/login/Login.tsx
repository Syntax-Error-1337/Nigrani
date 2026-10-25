import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, ShieldCheck, XCircle } from 'lucide-react'
import { useSession, type SessionUser } from '@/shared/session'

export default function Login() {
  const navigate = useNavigate()
  const login = useSession((s) => s.login)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
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
          <span className="ml-2 text-xs font-normal text-white/60">निगरानी</span>
        </div>
        <div
          className="absolute inset-0 opacity-[0.14]"
          style={{
            backgroundImage:
              'repeating-linear-gradient(90deg, #fff 0 1px, transparent 1px 48px), repeating-linear-gradient(0deg, #fff 0 1px, transparent 1px 64px)',
          }}
        />
        <div className="relative max-w-md">
          <div className="mb-6 h-1 w-16 rounded-full bg-gradient-to-r from-saffron via-white to-emerald-500" />
          <p className="text-4xl font-semibold leading-tight tracking-tight">
            Every crossing, accounted for.
          </p>
          <p className="mt-3 text-sm leading-relaxed text-slate-300">
            Gate access management for protest sites — press vetting, live crossings, incidents
            and the audit chain, from one console.
          </p>
          <div className="mt-8 rounded-xl border border-white/10 bg-white/5 p-4 font-ledger text-[11px] leading-relaxed text-white/70 backdrop-blur-sm">
            <p className="flex items-center gap-1.5 text-white/90">
              <ShieldCheck className="h-3.5 w-3.5 text-saffron" /> audit chain · live
            </p>
            <ul className="mt-2 space-y-1">
              <li><span className="text-white/40">#612</span> gate.event <span className="text-saffron/80">a3f9…c21e</span></li>
              <li><span className="text-white/40">#611</span> kyc.decided <span className="text-saffron/80">77b2…90d4</span></li>
              <li><span className="text-white/40">#610</span> site.capacity_set <span className="text-saffron/80">f0c8…31aa</span></li>
            </ul>
            <p className="mt-2 text-white/40">verify → ok · 612 checked · anchored</p>
          </div>
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
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              Password
              <span className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  className="input pr-10"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
                >
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </span>
            </label>
            {error ? (
              <p role="alert" className="flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
                <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                {error}
              </p>
            ) : null}
            <button
              type="submit"
              disabled={busy}
              className="btn btn-primary mt-1 !py-2.5 !text-base !font-semibold disabled:opacity-50"
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
          <div className="mt-6 rounded-xl border border-slate-200 bg-white p-3">
            <p className="font-ledger text-[10px] uppercase tracking-wide text-slate-400">Demo callsigns · password: password</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {['superadmin', 'commander', 'gate', 'verifier', 'analyst'].map((c) => (
                <button
                  key={c}
                  type="button"
                  onClick={() => { setUsername(c); setPassword('password') }}
                  className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 font-ledger text-[11px] text-slate-600 transition-colors hover:border-signal hover:text-signal"
                >
                  {c}
                </button>
              ))}
            </div>
          </div>
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
