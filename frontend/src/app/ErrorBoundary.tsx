import { Component, type ErrorInfo, type ReactNode } from 'react'

/// Console-wide crash guard (round 30): a panel that throws renders a
/// recoverable card instead of unmounting the whole tree to a white screen.
interface State {
  error: Error | null
}

export default class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Component stack pinpoints the panel; console keeps it visible in devtools.
    console.error('Console crashed:', error.message, info.componentStack)
  }

  render() {
    if (this.state.error === null) return this.props.children
    return (
      <main id="main-content" className="flex min-h-screen items-center justify-center bg-paper p-6">
        <section className="max-w-md rounded-2xl border border-rose-200 bg-white p-8 text-center shadow-lg">
          <p className="font-semibold text-sm text-signal">Nigrani</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">The console hit an error</h1>
          <p className="mt-2 break-all font-ledger text-xs text-slate-500">{this.state.error.message}</p>
          <p className="mt-2 text-sm text-slate-600">
            The rest of the console is fine — retry the view, or reload if it persists.
          </p>
          <div className="mt-4 flex justify-center gap-2">
            <button type="button" className="btn btn-primary" onClick={() => this.setState({ error: null })}>
              Try again
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => window.location.reload()}>
              Reload console
            </button>
          </div>
        </section>
      </main>
    )
  }
}
