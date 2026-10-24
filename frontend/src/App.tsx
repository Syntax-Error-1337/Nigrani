import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useEffect } from 'react'
import { Navigate, Route, BrowserRouter, Routes } from 'react-router-dom'
import Dashboard from './Dashboard'
import { useEventStream } from './events'
import Login from './Login'
import PressApply from './PressApply'
import { refreshNow, useSession } from './session'
const queryClient = new QueryClient()
// Network blips (API restart, laptop sleep): retry those a few times, and
// refetch on window focus so a dropped API connection heals itself without
// a manual reload. HTTP errors (401/403/404/409...) must NOT retry — they
// would hammer the server and mask the real status.
queryClient.setDefaultOptions({
  queries: {
    retry: (failureCount, error) => failureCount < 3 && error instanceof TypeError,
    refetchOnWindowFocus: true,
  },
})

function LiveUpdates() {
  useEventStream()
  // Proactive rotation every 5 min (access TTL is 15): steady use never
  // meets a 401. Skips when logged out; single-flight inside refreshNow
  // covers tick/request races.
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (useSession.getState().accessToken) void refreshNow()
    }, 5 * 60 * 1000)
    return () => window.clearInterval(timer)
  }, [])
  return null
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const user = useSession((s) => s.user)
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <a href="#main-content" className="skip-link">
          Skip to main content
        </a>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/press" element={<PressApply />} />
          <Route
            path="/dashboard"
            element={
              <RequireAuth>
                <LiveUpdates />
                <Dashboard />
              </RequireAuth>
            }
          />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
