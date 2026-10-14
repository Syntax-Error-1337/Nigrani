import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useEffect } from 'react'
import { Navigate, Route, BrowserRouter, Routes } from 'react-router-dom'
import Dashboard from './Dashboard'
import { useEventStream } from './events'
import Login from './Login'
import PressApply from './PressApply'
import { refreshNow, useSession } from './session'
const queryClient = new QueryClient()

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
