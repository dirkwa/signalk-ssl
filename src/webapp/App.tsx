import React, { useEffect, useState } from 'react'
import { getStatus, type Status } from './api.js'
import Wizard from './components/Wizard.js'
import StatusDashboard from './components/StatusDashboard.js'
import Distribution from './components/Distribution.js'
import UnlockPanel from './components/UnlockPanel.js'
import RotatePanel from './components/RotatePanel.js'

type View = 'loading' | 'wizard' | 'dashboard' | 'unlock' | 'error'

const App = (): React.JSX.Element => {
  const [view, setView] = useState<View>('loading')
  const [status, setStatus] = useState<Status | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refresh = async (): Promise<void> => {
    try {
      const s = await getStatus()
      setStatus(s)
      setView(s.hasCa && s.hasLeaf ? 'dashboard' : 'wizard')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
      setView('error')
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  return (
    <div className="mx-auto max-w-3xl px-4 py-6 sm:py-10">
      <header className="mb-6 flex items-center gap-3">
        <ShieldIcon className="h-8 w-8 text-sky-600" />
        <h1 className="text-2xl font-semibold tracking-tight">SignalK SSL</h1>
      </header>

      {view === 'loading' && <p className="text-slate-500">Loading…</p>}
      {view === 'error' && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-red-800">
          {error ?? 'Unknown error'}
        </div>
      )}

      {view === 'wizard' && (
        <Wizard
          existingStatus={status}
          onComplete={() => {
            void refresh()
          }}
          onNeedsUnlock={() => {
            setView('unlock')
          }}
        />
      )}

      {view === 'dashboard' && status !== null && (
        <div className="space-y-6">
          <StatusDashboard
            status={status}
            onChange={() => {
              void refresh()
            }}
          />
          <Distribution status={status} />
          <RotatePanel />
        </div>
      )}

      {view === 'unlock' && (
        <UnlockPanel
          onUnlocked={() => {
            void refresh()
          }}
        />
      )}
    </div>
  )
}

const ShieldIcon = ({ className }: { className?: string }): React.JSX.Element => (
  <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
    <path d="M12 2 4 5v6c0 4.97 3.33 9.5 8 11 4.67-1.5 8-6.03 8-11V5l-8-3Zm0 5c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3Zm0 14c-2.39-1.06-4.31-3.07-5.42-5.41A6.005 6.005 0 0 1 12 13a6.005 6.005 0 0 1 5.42 2.59C16.31 17.93 14.39 19.94 12 21Z" />
  </svg>
)

export default App
