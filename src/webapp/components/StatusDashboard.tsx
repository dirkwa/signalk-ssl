import React, { useState } from 'react'
import { renew, type Status } from '../api.js'

interface Props {
  status: Status
  onChange: () => void
}

const expiryLight = (days: number | null): { color: string; label: string } => {
  if (days === null) return { color: 'bg-slate-300', label: 'unknown' }
  if (days < 30) return { color: 'bg-red-500', label: 'expiring soon' }
  if (days < 90) return { color: 'bg-amber-500', label: 'within 90 days' }
  return { color: 'bg-emerald-500', label: 'healthy' }
}

const StatusDashboard = ({ status, onChange }: Props): React.JSX.Element => {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const light = expiryLight(status.leafDaysRemaining)

  const handleRenew = async (): Promise<void> => {
    setBusy(true)
    setError(null)
    try {
      const out = await renew()
      if (out.kind === 'error') {
        setError(out.message)
      } else if (out.kind === 'locked') {
        setError('CA is locked — unlock the plugin first.')
      } else {
        onChange()
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      {status.restartRequired && (
        <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-amber-900">
          <p className="font-medium">Certificate updated — restart SignalK to activate it.</p>
          <p className="mt-1 text-sm text-amber-800">
            The new certificate is installed at the configured TLS path. SignalK reads it at boot;
            restart the server to pick it up.
          </p>
        </div>
      )}

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold">Certificate Authority</h2>
        <dl className="mt-3 grid grid-cols-1 gap-2 text-sm sm:grid-cols-[10rem_1fr]">
          <dt className="text-slate-500">Created</dt>
          <dd className="font-mono">{status.caCreatedAt ?? '—'}</dd>
          <dt className="text-slate-500">SHA-256 fingerprint</dt>
          <dd className="break-all font-mono text-xs">{status.caFingerprint ?? '—'}</dd>
        </dl>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Server certificate</h2>
          <span
            className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium text-white ${light.color}`}
          >
            <span className="h-2 w-2 rounded-full bg-white/80" />
            {light.label}
          </span>
        </div>
        <dl className="mt-3 grid grid-cols-1 gap-2 text-sm sm:grid-cols-[10rem_1fr]">
          <dt className="text-slate-500">Days remaining</dt>
          <dd className="font-mono">{status.leafDaysRemaining ?? '—'}</dd>
          <dt className="text-slate-500">Expires</dt>
          <dd className="font-mono">{status.leafExpiresAt ?? '—'}</dd>
          <dt className="text-slate-500">DNS names</dt>
          <dd className="font-mono text-xs">
            {status.leafSansDns.length === 0 ? '—' : status.leafSansDns.join(', ')}
          </dd>
          <dt className="text-slate-500">IP addresses</dt>
          <dd className="font-mono text-xs">
            {status.leafSansIp.length === 0 ? '—' : status.leafSansIp.join(', ')}
          </dd>
        </dl>
        {error !== null && (
          <p className="mt-3 rounded-md bg-red-50 p-3 text-sm text-red-800">{error}</p>
        )}
        <button
          type="button"
          onClick={() => {
            void handleRenew()
          }}
          disabled={busy}
          className="mt-4 inline-flex items-center justify-center rounded-lg border border-sky-600 px-4 py-2 text-sm font-medium text-sky-700 hover:bg-sky-50 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? 'Renewing…' : 'Renew now'}
        </button>
      </section>
    </div>
  )
}

export default StatusDashboard
