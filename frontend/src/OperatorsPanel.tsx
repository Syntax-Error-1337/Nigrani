import { useState } from 'react'
import { apiFetch } from './session'

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

export default function OperatorsPanel() {
  const [rows, setRows] = useState<Operator[] | null>(null)
  const [form, setForm] = useState({ username: '', password: '', role: 'GateOperator' })
  const [notice, setNotice] = useState<string | null>(null)

  async function load() {
    setNotice(null)
    const res = await apiFetch('/users')
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Operators would not load'))
      return
    }
    setRows((await res.json()) as Operator[])
  }

  async function create(e: React.FormEvent) {
    e.preventDefault()
    setNotice(null)
    const res = await apiFetch('/users', { method: 'POST', body: JSON.stringify(form) })
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
    const res = await apiFetch(`/users/${op.id}/${action}`, { method: 'POST' })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), `Could not ${action}`))
      return
    }
    load()
  }

  async function unlock(op: Operator) {
    setNotice(null)
    const res = await apiFetch(`/users/${op.id}/unlock`, { method: 'POST' })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Could not unlock'))
      return
    }
    load()
  }

  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        <h2 className="font-display text-2xl uppercase">Operators</h2>
        <button onClick={load} className="border border-ink px-3 py-1 font-ledger text-xs uppercase">
          Load operators
        </button>
      </div>
      {notice ? <p className="mt-2 text-sm text-deny">{notice}</p> : null}
      <ol className="mt-3 divide-y divide-neutral-200 border-y-2 border-ink bg-white">
        {(rows ?? []).map((op) => (
          <li key={op.id} className="flex items-baseline gap-3 px-4 py-2 font-ledger text-xs">
            <span className={op.active ? '' : 'text-neutral-400 line-through'}>{op.username}</span>
            <span className="uppercase">{op.role}</span>
            {op.locked_until ? (
              <span className="border border-deny bg-red-50 px-1 uppercase text-deny" title={`Locked until ${op.locked_until} · ${op.failed_logins} strikes`}>
                locked
              </span>
            ) : null}
            <button onClick={() => flip(op)} className="ml-auto border border-ink px-2 py-1 uppercase">
              {op.active ? 'Deactivate' : 'Reactivate'}
            </button>
            {op.locked_until ? (
              <button onClick={() => unlock(op)} className="border border-ink bg-ink px-2 py-1 uppercase text-paper">
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
            className="border border-ink px-3 py-2"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Password (12+ chars)
          <input
            type="password"
            className="border border-ink px-3 py-2"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            autoComplete="new-password"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Role
          <select
            className="border border-ink px-3 py-2"
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
        <button type="submit" className="bg-ink px-4 py-2 text-sm uppercase text-paper">
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
    const res = await apiFetch('/auth/password', {
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

  return (
    <section className="mt-8">
      <h2 className="font-display text-2xl uppercase">Change password</h2>
      <form onSubmit={submit} className="mt-2 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          Current
          <input
            type="password"
            className="border border-ink px-3 py-2"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          New (12+ chars)
          <input
            type="password"
            className="border border-ink px-3 py-2"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        <button type="submit" className="bg-ink px-4 py-2 text-sm uppercase text-paper">
          Change
        </button>
      </form>
      {msg ? <p className="mt-2 text-sm">{msg}</p> : null}
    </section>
  )
}
