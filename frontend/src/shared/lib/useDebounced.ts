import { useEffect, useState } from 'react'

// Debounced mirror of a fast-changing input: queries fire 250ms after pause.
export function useDebounced(value: string, delayMs = 250): string {
  const [mirrored, setMirrored] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setMirrored(value), delayMs)
    return () => window.clearTimeout(timer)
  }, [value, delayMs])
  return mirrored
}
