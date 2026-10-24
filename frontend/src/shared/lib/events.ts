import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useSession } from '@/shared/session'

interface HubEvent {
  kind: 'crossing' | 'kyc_decided' | 'topology' | 'incident'
  site_id?: string
  gate_id?: string
  incident_id?: string
  action?: string
}

function isHubEvent(body: unknown): body is HubEvent {
  if (body === null || typeof body !== 'object' || !('kind' in body)) return false
  const kind: unknown = body.kind
  return kind === 'crossing' || kind === 'kyc_decided' || kind === 'topology' || kind === 'incident'
}

export interface IncidentWire {
  site_id?: string
  incident_id?: string
  action?: string
}

/// Bench-side subscribers: ForensicBench keeps incidents in local useState
/// (not react-query), so incident events fan out through this set instead
/// of query invalidation. Returns an unsubscribe closure.
const incidentListeners = new Set<(ev: IncidentWire) => void>()

export function onIncidentEvent(fn: (ev: IncidentWire) => void): () => void {
  incidentListeners.add(fn)
  return () => {
    incidentListeners.delete(fn)
  }
}

// Single shared event stream: invalidates tanstack-query keys so panels
// update live. Reconnects with backoff; the stream is a hint — REST reads
// stay the source of truth after lag or drops.
export function useEventStream() {
  const accessToken = useSession((s) => s.accessToken)
  const queryClient = useQueryClient()
  const backoff = useRef(1000)

  useEffect(() => {
    if (!accessToken) return
    let socket: WebSocket | null = null
    let closed = false
    let timer = 0

    function connect() {
      const token: string = accessToken as string
      socket = new WebSocket(`/events?token=${encodeURIComponent(token)}`)
      socket.onmessage = (e: MessageEvent) => {
        let body: unknown
        try {
          body = JSON.parse(String(e.data))
        } catch {
          return
        }
        if (!isHubEvent(body)) return
        backoff.current = 1000
        if (body.kind === 'crossing') {
          queryClient.invalidateQueries({ queryKey: ['gate-log'] })
          queryClient.invalidateQueries({ queryKey: ['heatmap'] })
        } else if (body.kind === 'kyc_decided') {
          queryClient.invalidateQueries({ queryKey: ['kyc'] })
        } else if (body.kind === 'incident') {
          const wire: IncidentWire = { site_id: body.site_id, incident_id: body.incident_id, action: body.action }
          incidentListeners.forEach((fn) => fn(wire))
        } else {
          queryClient.invalidateQueries({ queryKey: ['sites'] })
          queryClient.invalidateQueries({ queryKey: ['gates'] })
          queryClient.invalidateQueries({ queryKey: ['my-duty'] })
        }
      }
      socket.onclose = () => {
        if (closed) return
        timer = window.setTimeout(connect, backoff.current)
        backoff.current = Math.min(backoff.current * 2, 15000)
      }
    }

    connect()
    return () => {
      closed = true
      window.clearTimeout(timer)
      socket?.close()
    }
  }, [accessToken, queryClient])
}
