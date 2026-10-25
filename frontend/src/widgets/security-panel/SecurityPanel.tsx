import { useState } from 'react'
import { Lock } from 'lucide-react'
import { apiFetch } from '@/shared/api'

interface SessionRow {
  session_id: string
  started: string
  expires: string
  current: boolean
}

/// Per-user security console: TOTP 2FA enrollment and per-device session
/// revocation (s-H2). Shown to every signed-in operator.
export default function SecurityPanel() {
  const [sessions, setSessions] = useState<SessionRow[] | null>(null)
  const [totpUri, setTotpUri] = useState<string | null>(null)
  const [totpSecret, setTotpSecret] = useState<string | null>(null)
  const [enabled, setEnabled] = useState(false)
  const [code, setCode] = useState('')
  const [notice, setNotice] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)

  async function loadSessions() {
    setNotice(null)
    const res = await apiFetch('/auth/sessions')
    if (!res.ok) {
      setNotice(`Sessions refused (${res.status})`)
      return
    }
    const body: unknown = await res.json()
    if (body !== null && typeof body === 'object' && 'sessions' in body) {
      setSessions(body.sessions as SessionRow[])
    }
  }

  async function beginTotp() {
    setNotice(null)
    setOk(null)
    const res = await apiFetch('/auth/totp/setup', { method: 'POST' })
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      const err = body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' ? err : `Setup refused (${res.status})`)
      if (res.status === 409) setEnabled(true)
      return
    }
    if (body !== null && typeof body === 'object' && 'otpauth_uri' in body && 'secret' in body) {
      setTotpUri(body.otpauth_uri as string)
      setTotpSecret(body.secret as string)
    }
  }

  async function confirmTotp() {
    setNotice(null)
    const res = await apiFetch('/auth/totp/enable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      const err = body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' ? err : 'Enable refused')
      return
    }
    setEnabled(true)
    setTotpUri(null)
    setTotpSecret(null)
    setCode('')
    setOk('2FA enabled — logins now need your authenticator code')
  }

  async function disableTotp() {
    setNotice(null)
    const res = await apiFetch('/auth/totp/disable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
    if (!res.ok) {
      setNotice('Disable refused — code did not verify')
      return
    }
    setEnabled(false)
    setCode('')
    setOk('2FA disabled')
  }

  async function revoke(sid: string) {
    setNotice(null)
    const res = await apiFetch(`/auth/sessions/${sid}/revoke`, { method: 'POST' })
    if (!res.ok) {
      setNotice(`Revoke refused (${res.status})`)
      return
    }
    setOk('Session revoked')
    void loadSessions()
  }

  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        <h2 className="flex items-center gap-1.5 text-lg font-semibold tracking-tight">
          <Lock className="h-4 w-4 text-slate-400" /> Security
        </h2>
        <button onClick={loadSessions} className="btn btn-secondary">
          List sessions
        </button>
        <button onClick={beginTotp} className="btn btn-secondary">
          Set up 2FA
        </button>
      </div>
      {notice ? <p className="mt-2 text-sm text-deny">{notice}</p> : null}
      {ok ? <p className="mt-2 text-sm text-ok">{ok}</p> : null}
      {totpUri && totpSecret ? (
        <div className="mt-3 max-w-md rounded-xl border border-slate-200 bg-white p-4 shadow-sm text-sm">
          <p className="font-medium">Add Nigrani to your authenticator app</p>
          <p className="mt-2 break-all font-mono text-xs text-slate-600">{totpUri}</p>
          <p className="mt-1 text-xs text-slate-500">Manual key: <span className="font-mono">{totpSecret}</span></p>
          <div className="mt-3 flex gap-2">
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="6-digit code"
              inputMode="numeric"
              className="w-32 rounded-md border border-slate-300 px-2 py-1 text-sm"
            />
            <button onClick={confirmTotp} className="btn btn-primary !px-3 !py-1 !text-xs">
              Confirm
            </button>
          </div>
        </div>
      ) : null}
      {enabled ? (
        <div className="mt-3 flex items-center gap-2 text-sm">
          <span className="rounded-full bg-ok/10 px-2 py-0.5 text-xs font-medium text-ok">2FA active</span>
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="6-digit code"
            inputMode="numeric"
            className="w-32 rounded-md border border-slate-300 px-2 py-1 text-sm"
          />
          <button onClick={disableTotp} className="btn btn-secondary">
            Disable 2FA
          </button>
        </div>
      ) : null}
      {sessions ? (
        <ol className="mt-3 divide-y divide-slate-200 rounded-xl border border-slate-200 bg-white shadow-sm">
          {sessions.map((s) => (
            <li key={s.session_id} className="flex items-center gap-3 px-4 py-2 text-xs">
              <span className="font-ledger">
                started {new Date(s.started).toLocaleString()}
              </span>
              <span className="text-slate-500">expires {new Date(s.expires).toLocaleString()}</span>
              {s.current ? (
                <span className="rounded-full bg-saffron-mist px-2 py-0.5 text-[10px] font-medium text-saffron-ink">this device</span>
              ) : (
                <button onClick={() => revoke(s.session_id)} className="ml-auto btn-chip">
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ol>
      ) : null}
    </section>
  )
}
