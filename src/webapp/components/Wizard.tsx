import React, { useEffect, useState } from 'react'
import { getLocalIps, renew, type IssueOutcome, type Status } from '../api.js'

interface Props {
  existingStatus: Status | null
  onComplete: () => void
  onNeedsUnlock: () => void
}

const Wizard = ({ existingStatus, onComplete, onNeedsUnlock }: Props): React.JSX.Element => {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ips, setIps] = useState<string[]>([])
  const [dnsName, setDnsName] = useState<string | null>(null)

  useEffect(() => {
    void getLocalIps()
      .then((r) => {
        setIps(r.ipAddresses)
        setDnsName(r.dnsName)
      })
      .catch(() => {
        setIps([])
        setDnsName(null)
      })
  }, [])

  const handleIssue = async (): Promise<void> => {
    setBusy(true)
    setError(null)
    try {
      const out: IssueOutcome = await renew()
      if (out.kind === 'error') {
        setError(out.message)
      } else if (out.kind === 'locked') {
        onNeedsUnlock()
      } else {
        onComplete()
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const noSans =
    (existingStatus?.leafSansDns.length ?? 0) + (existingStatus?.leafSansIp.length ?? 0) === 0

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold">Welcome</h2>
        <p className="mt-2 text-slate-600">
          Configure a local Certificate Authority and HTTPS certificates for this SignalK server.
          When you finish, devices on the boat can install the CA root by scanning a QR code.
        </p>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold">1. Configure SANs in the plugin settings</h2>
        <p className="mt-2 text-slate-600">
          Open the SignalK plugin configuration screen for{' '}
          <span className="font-mono">signalk-ssl</span> and add at least one DNS name and/or IP
          address.
        </p>
        {dnsName !== null && (
          <p className="mt-3 text-slate-600">
            This server is advertising on mDNS as <span className="font-mono">{dnsName}</span> —
            adding it as a DNS SAN matches what phones and tablets see when they discover the server
            on the local network.
          </p>
        )}
        <p className="mt-3 text-slate-600">
          This server reports the following local IPv4 addresses:
        </p>
        <ul className="mt-3 list-inside list-disc space-y-1 font-mono text-sm text-slate-700">
          {ips.length === 0 ? (
            <li className="font-sans italic text-slate-500">none discovered</li>
          ) : (
            ips.map((ip) => <li key={ip}>{ip}</li>)
          )}
        </ul>
        {noSans && (
          <p className="mt-3 rounded-md bg-amber-50 p-3 text-sm text-amber-800">
            No SANs are currently configured. Save the plugin config, then return here.
          </p>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold">2. Choose a passphrase mode</h2>
        <p className="mt-2 text-slate-600">
          The CA private key on disk is always encrypted. Pick the mode in the plugin settings:
        </p>
        <ul className="mt-3 list-inside list-disc space-y-1 text-slate-700">
          <li>
            <span className="font-semibold">convenience</span> (default) — the wrapping key is
            derived from this host's identity. No typing, just works on each restart.
          </li>
          <li>
            <span className="font-semibold">env</span> — read{' '}
            <span className="font-mono">SIGNALK_SSL_PASSPHRASE</span> at startup.
          </li>
          <li>
            <span className="font-semibold">webapp</span> — unlock here on each restart.
          </li>
        </ul>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold">3. Issue certificate</h2>
        <p className="mt-2 text-slate-600">
          When you're ready, click below. The plugin will create the CA if needed, sign a leaf
          certificate for your SANs, and install it at the SignalK TLS path.
        </p>
        {error !== null && (
          <p className="mt-3 rounded-md bg-red-50 p-3 text-sm text-red-800">{error}</p>
        )}
        <button
          type="button"
          onClick={() => {
            void handleIssue()
          }}
          disabled={busy || noSans}
          className="mt-4 inline-flex items-center justify-center rounded-lg bg-sky-600 px-5 py-3 text-base font-medium text-white shadow-sm hover:bg-sky-700 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {busy ? 'Issuing…' : 'Issue certificate'}
        </button>
      </section>
    </div>
  )
}

export default Wizard
