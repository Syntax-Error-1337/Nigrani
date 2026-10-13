import { useState } from 'react'

export default function PressApply() {
  const [form, setForm] = useState({
    full_name: '',
    organization: '',
    document_type: 'press_id',
    document_number: '',
    photo_url: '',
  })
  const [status, setStatus] = useState<'idle' | 'sending' | 'done' | 'error'>('idle')
  const [message, setMessage] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setStatus('sending')
    setMessage(null)
    try {
      const res = await fetch('/kyc/applications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const body: unknown = await res.json().catch(() => ({}))
      if (!res.ok) {
        const err =
          body !== null && typeof body === 'object' && 'error' in body ? body.error : null
        setMessage(typeof err === 'string' && err.length > 0 ? err : 'Application rejected')
        setStatus('error')
        return
      }
      setStatus('done')
    } catch {
      setMessage('Network error — try again shortly')
      setStatus('error')
    }
  }

  if (status === 'done') {
    return (
      <main className="flex min-h-screen items-center justify-center bg-paper p-6">
        <section className="max-w-md border-2 border-ink bg-white p-8">
          <p className="font-ledger text-xs tracking-widest text-signal">NIGRANI</p>
          <h1 className="mt-2 font-display text-3xl uppercase">Application received</h1>
          <p className="mt-3">
            Your press accreditation request is in the review queue. Bring your original
            document to the gate on the event day.
          </p>
        </section>
      </main>
    )
  }

  const field = 'border border-ink px-3 py-2 w-full'
  return (
    <main className="flex min-h-screen items-center justify-center bg-paper p-6">
      <section className="w-full max-w-md border-2 border-ink bg-white p-8 shadow-[6px_6px_0_0_var(--color-ink)]">
        <p className="font-ledger text-xs tracking-widest text-signal">NIGRANI</p>
        <h1 className="mt-2 font-display text-3xl uppercase">Press accreditation</h1>
        <form onSubmit={submit} className="mt-6 flex flex-col gap-4">
          <label className="flex flex-col gap-1 text-sm">
            Full name
            <input
              className={field}
              value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              autoComplete="name"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            Organization
            <input
              className={field}
              value={form.organization}
              onChange={(e) => setForm({ ...form, organization: e.target.value })}
              placeholder="Outlet or agency"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            Document type
            <select
              className={field}
              value={form.document_type}
              onChange={(e) => setForm({ ...form, document_type: e.target.value })}
            >
              <option value="press_id">Press ID</option>
              <option value="aadhaar">Aadhaar</option>
              <option value="pan">PAN</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            Document number
            <input
              className={field}
              value={form.document_number}
              onChange={(e) => setForm({ ...form, document_number: e.target.value })}
            />
          </label>
          {message ? (
            <p role="alert" className="border border-deny bg-red-50 px-3 py-2 text-sm text-deny">
              {message}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={status === 'sending'}
            className="bg-ink px-4 py-2 font-display text-lg uppercase text-paper disabled:opacity-50"
          >
            {status === 'sending' ? 'Filing…' : 'File application'}
          </button>
        </form>
      </section>
    </main>
  )
}
