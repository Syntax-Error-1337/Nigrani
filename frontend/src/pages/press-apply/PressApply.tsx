import { CheckCircle2, XCircle } from 'lucide-react'
import { useState } from 'react'

export default function PressApply() {
  const [form, setForm] = useState({
    full_name: '',
    organization: '',
    document_type: 'press_id',
    document_number: '',
    photo_url: '',
    photo_consent: false,
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
      <main id="main-content" className="flex min-h-screen items-center justify-center bg-paper p-6">
        <section className="max-w-md rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-lg">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-50">
            <CheckCircle2 className="h-6 w-6 text-ok" />
          </span>
          <p className="mt-4 font-semibold text-sm text-signal">Nigrani</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight">Application received</h1>
          <p className="mt-3 text-sm text-slate-600">
            Your press accreditation request is in the review queue. Bring your original
            document to the gate on the event day.
          </p>
        </section>
      </main>
    )
  }

  const field = 'input w-full'
  return (
    <main id="main-content" className="flex min-h-screen flex-col items-center justify-center bg-paper p-6">
      <div className="tricolor-strip fixed inset-x-0 top-0 h-1.5" />
      <section className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-8 shadow-lg">
        <p className="font-semibold text-sm text-signal">Nigrani · निगरानी</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">Press accreditation</h1>
        <p className="mt-1 text-sm text-slate-500">प्रेस प्रवेश — media access request, reviewed by the verification desk.</p>
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
          <label className="flex flex-col gap-1 text-sm">
            Photo (≤ 2 MB; reused photos are flagged as duplicates)
            <input
              className={field}
              type="file"
              accept="image/*"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (!file) return
                const reader = new FileReader()
                reader.onload = () => setForm((p) => ({ ...p, photo_url: String(reader.result) }))
                reader.readAsDataURL(file)
              }}
            />
          </label>
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.photo_consent}
              onChange={(e) => setForm({ ...form, photo_consent: e.target.checked })}
              className="mt-0.5"
            />
            <span>
              मैं सहमत हूँ — I consent to my photo being used for identity
              verification at the gates (biometric processing).
            </span>
          </label>
          {message ? (
            <p role="alert" className="flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
              <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
              {message}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={status === 'sending'}
            className="btn btn-primary !py-2\.5 !text-base !font-semibold disabled:opacity-50"
          >
            {status === 'sending' ? 'Filing…' : 'File application'}
          </button>
        </form>
      </section>
    </main>
  )
}
