import { useSyncExternalStore } from 'react'
import { apiFetch } from './session'
import type { PressCard } from './api'

/// Kiosk offline outbox: crossings that failed on network/5xx/429 wait in
/// localStorage instead of dying. 4xx verdicts NEVER queue (validation or
/// denial — retrying would duplicate or fight the server).
///
/// Card payloads rest here alongside the session JWT (same sensitivity,
/// same store). Snapshot keys reference already-uploaded S3 objects; a
/// never-flushed item's key ages into a regular orphan for the s25
/// collector.
export interface OutboxItem {
  id: string
  siteId: string
  gateId: string
  direction: 'entry' | 'exit'
  method: 'press_card' | 'manual'
  press_card: PressCard | null
  snapshot_key: string | null
  queued_at: string
  attempts: number
}

const STORAGE_KEY = 'sg-outbox'
const MAX_DELAY_MS = 30_000

type Listener = () => void
const listeners = new Set<Listener>()

function read(): OutboxItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter(
      (x): x is OutboxItem =>
        x !== null &&
        typeof x === 'object' &&
        typeof (x as OutboxItem).id === 'string' &&
        typeof (x as OutboxItem).siteId === 'string' &&
        typeof (x as OutboxItem).gateId === 'string',
    )
  } catch {
    return []
  }
}

/// Referentially stable snapshot: useSyncExternalStore re-renders while
/// getSnapshot() returns a fresh reference, so the cache refreshes ONLY in
/// write() (the single mutation point). Without this the kiosk render-loops.
let cached: OutboxItem[] = read()

function write(items: OutboxItem[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items))
  } catch {
    // Quota-full: state still updates in memory for this session.
  }
  cached = items
  listeners.forEach((fn) => fn())
}

export function subscribeOutbox(fn: Listener): () => void {
  listeners.add(fn)
  return () => {
    listeners.delete(fn)
  }
}

export function getOutboxSnapshot(): OutboxItem[] {
  return cached
}

export function enqueueCrossing(item: Omit<OutboxItem, 'id' | 'queued_at' | 'attempts'>): OutboxItem {
  const items = read()
  const full: OutboxItem = {
    ...item,
    id:
      typeof crypto !== 'undefined' && 'randomUUID' in crypto
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.floor(Math.random() * 1e9)}`,
    queued_at: new Date().toISOString(),
    attempts: 0,
  }
  items.push(full)
  // Bound the queue (100): a kiosk deeper than that needs ops, not RAM.
  while (items.length > 100) items.shift()
  write(items)
  return full
}

function drop(id: string) {
  write(read().filter((x) => x.id !== id))
}

function bump(id: string) {
  write(read().map((x) => (x.id === id ? { ...x, attempts: x.attempts + 1 } : x)))
}

/// Post one item. Returns 'sent' | 'retry' (network/5xx/429) | 'drop'
/// (4xx verdict — caller surfaces the reason; 410 = gate retired).
async function postItem(item: OutboxItem): Promise<'sent' | 'retry' | 'drop'> {
  let res: Response
  try {
    res = await apiFetch(`/sites/${item.siteId}/gates/${item.gateId}/events`, {
      method: 'POST',
      body: JSON.stringify({
        direction: item.direction,
        method: item.method,
        press_card: item.press_card,
        snapshot_key: item.snapshot_key,
      }),
    })
  } catch {
    return 'retry'
  }
  if (res.ok) return 'sent'
  if (res.status === 410) return 'drop'
  if (res.status === 429 || res.status >= 500) return 'retry'
  return 'drop'
}

let flushing = false

/// FIFO flush; stops at the first retryable failure (stable order, no
/// thundering retry). Returns {sent, dropped, pending}.
export async function flushOutbox(): Promise<{ sent: number; dropped: number; pending: number }> {
  if (flushing) return { sent: 0, dropped: 0, pending: read().length }
  flushing = true
  try {
    let sent = 0
    let dropped = 0
    for (;;) {
      const head = read()[0]
      if (!head) break
      const outcome = await postItem(head)
      if (outcome === 'sent') {
        drop(head.id)
        sent += 1
      } else if (outcome === 'drop') {
        drop(head.id)
        dropped += 1
      } else {
        bump(head.id)
        break
      }
    }
    return { sent, dropped, pending: read().length }
  } finally {
    flushing = false
  }
}

/// Backoff for the manual RETRY button (2s × attempts, cap 30s).
export function retryDelayMs(attempts: number): number {
  return Math.min(2000 * Math.max(1, attempts), MAX_DELAY_MS)
}

export function useOutbox(): OutboxItem[] {
  return useSyncExternalStore(subscribeOutbox, getOutboxSnapshot, getOutboxSnapshot)
}
