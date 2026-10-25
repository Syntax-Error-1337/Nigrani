import { useEffect, useState } from 'react'
import { Eye, EyeOff, KeyRound, Users } from 'lucide-react'
import { safeApi } from '@/shared/api'
import { STORAGE_KEY, useSession } from '@/shared/session'

interface Operator {
  id: string
  username: string
  role: string
  active: boolean
  failed_logins: number
  locked_until: string | null
}

function apiError(body: unknown, fallback: string): string {
  if (body !== null && typeof body === 'object' && 'error' in body) {
    const err: unknown = body.error
    if (typeof err === 'string' && err.length > 0) return err
  }
  return fallback
}

function PwField({
  label, id, value, onChange, autoComplete,
}: {
  label: string
  id: string
  value: string
  onChange: (v: string) => void
  autoComplete: string
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="flex flex-col gap-1 text-sm">
      <label htmlFor={id}>{label}</label>
      <span className="relative">
        <input
          id={id}
          type={show ? 'text' : 'password'}
          className="input pr-10"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
        />
        <button
          type="button"
          aria-label={show ? 'Hide password text' : 'Show password text'}
          onClick={() => setShow((v) => !v)}
          className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
        >
          {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </span>
    </div>
  )
}

export default function OperatorsPanel() {
  const [rows, setRows] = useState<Operator[] | null>(null)
  const [form, setForm] = useState({ username: '', password: '', role: 'GateOperator' })
  const [notice, setNotice] = useState<string | null>(null)

  async function load() {
  try {
      setNotice(null)
      const res = await safeApi('/users')
      if (!res.ok) {
        setNotice(apiError(await res.json().catch(() => ({})), 'Operators would not load'))
        return
      }
      setRows((await res.json()) as Operator[])
  } catch {
    setNotice('Network error — is the API running?')
  }
  }

  async function create(e: React.FormEvent) {
    e.preventDefault()
    setNotice(null)
    const res = await safeApi('/users', { method: 'POST', body: JSON.stringify(form) })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Could not create operator'))
      return
    }
    setForm({ username: '', password: '', role: 'GateOperator' })
    load()
  }

  async function flip(op: Operator) {
    setNotice(null)
    const action = op.active ? 'deactivate' : 'reactivate'
    const res = await safeApi(`/users/${op.id}/${action}`, { method: 'POST' })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), `Could not ${action}`))
      return
    }
    load()
  }

  async function unlock(op: Operator) {
    setNotice(null)
    const res = await safeApi(`/users/${op.id}/unlock`, { method: 'POST' })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Could not unlock'))
      return
    }
    load()
  }

  // Roster loads on open — no blank panel waiting on a button.
  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        <h2 className="flex items-center gap-1.5 text-lg font-semibold tracking-tight">
          <Users className="h-4 w-4 text-slate-400" /> Operators
        </h2>
        <button onClick={load} className="btn btn-secondary">
          Load operators
        </button>
      </div>
      {notice ? <p className="mt-2 text-sm text-deny">{notice}</p> : null}
      <ol className="mt-3 card divide-y divide-slate-100">
        {(rows ?? []).map((op) => (
          <li key={op.id} className="flex items-baseline gap-3 px-4 py-2 font-ledger text-xs">
            <span className={op.active ? '' : 'text-neutral-400 line-through'}>{op.username}</span>
            <span className="uppercase">{op.role}</span>
            {op.locked_until ? (
              <span className="border border-rose-200 bg-rose-50 px-1 text-xs font-medium text-deny" title={`Locked until ${op.locked_until} · ${op.failed_logins} strikes`}>
                locked
              </span>
            ) : null}
            <button onClick={() => flip(op)} className="ml-auto btn-chip">
              {op.active ? 'Deactivate' : 'Reactivate'}
            </button>
            {op.locked_until ? (
              <button onClick={() => unlock(op)} className="border-transparent bg-ink px-2 py-1 text-xs font-medium text-white hover:border-slate-700">
                Unlock
              </button>
            ) : null}
          </li>
        ))}
      </ol>
      <form onSubmit={create} className="mt-3 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          Username (a-z0-9_, 3–32)
          <input
            className="input"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
          />
        </label>
        <PwField
          label="Password (12+ chars)"
          id="op-new-password"
          value={form.password}
          onChange={(v) => setForm({ ...form, password: v })}
          autoComplete="new-password"
        />
        <label className="flex flex-col gap-1 text-sm">
          Role
          <select
            className="input"
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
          >
            <option>SuperAdmin</option>
            <option>SiteCommander</option>
            <option>GateOperator</option>
            <option>VerificationOfficer</option>
            <option>ForensicAnalyst</option>
          </select>
        </label>
        <button type="submit" className="btn btn-primary">
          Provision
        </button>
      </form>
    </section>
  )
}

export function PasswordDialog() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [msg, setMsg] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setMsg(null)
    const res = await safeApi('/auth/password', {
      method: 'POST',
      body: JSON.stringify({ current, new: next }),
    })
    if (!res.ok) {
      setMsg(apiError(await res.json().catch(() => ({})), 'Password change failed'))
      return
    }
    setCurrent('')
    setNext('')
    setMsg('Password changed — other sessions signed out')
  }

  async function signOutAll() {
    const res = await safeApi('/auth/logout/all', { method: 'POST' })
    if (!res.ok) {
      setMsg(`Sign-out refused (${res.status})`)
      return
    }
    // Server already revoked every session; wipe local copy without another
    // (now-dead) /auth/logout call.
    localStorage.removeItem(STORAGE_KEY)
    useSession.setState({ accessToken: null, refreshToken: null, user: null })
  }

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-1.5 text-lg font-semibold tracking-tight">
        <KeyRound className="h-4 w-4 text-slate-400" /> Change password
      </h2>
      <form onSubmit={submit} className="mt-2 flex flex-wrap items-end gap-3">
        <PwField
          label="Current"
          id="pw-current"
          value={current}
          onChange={setCurrent}
          autoComplete="current-password"
        />
        <PwField
          label="New (12+ chars)"
          id="pw-new"
          value={next}
          onChange={setNext}
          autoComplete="new-password"
        />
        <button type="submit" className="btn btn-primary">
          Change
        </button>
        <button
          type="button"
          onClick={signOutAll}
          className="btn btn-secondary"
        >
          Sign out all sessions
        </button>
      </form>
      {msg ? <p className="mt-2 text-sm">{msg}</p> : null}
    </section>
  )
}
