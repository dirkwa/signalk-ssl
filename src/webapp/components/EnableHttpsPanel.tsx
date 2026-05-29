import React from 'react'
import type { Status } from '../api.js'

interface Props {
  status: Status
}

/**
 * Show the help only when there's a usable cert but the server isn't actually
 * serving HTTPS — that's the trap: the plugin succeeded, yet browsing https://…
 * fails because signalk-server's settings.ssl is false.
 *
 * Suppressed when:
 *   - hasLeaf is false (nothing to use anyway, the wizard/dashboard covers it)
 *   - serverSslEnabled is null (older server that doesn't report state — we
 *     can't make a reliable claim)
 *   - serverSslEnabled is true (everything's already set up)
 */
export const shouldShowEnableHttps = (status: Status): boolean =>
  status.hasLeaf && status.serverSslEnabled === false

const EnableHttpsPanel = ({ status }: Props): React.JSX.Element | null => {
  if (!shouldShowEnableHttps(status)) {
    return null
  }
  const port = status.serverSslPort ?? 443
  return (
    <section className="rounded-xl border border-amber-300 bg-amber-50 p-5 shadow-sm">
      <h2 className="text-lg font-semibold text-amber-900">
        Your certificate is ready — but the server is still serving plain HTTP
      </h2>
      <p className="mt-2 text-amber-900">
        signalk-ssl has issued a valid certificate and installed it where SignalK looks for it, but{' '}
        <code className="rounded bg-amber-100 px-1">settings.ssl</code> is still off — so the server
        keeps serving HTTP and browsers can&apos;t use the cert. Two things tend to switch this off
        unexpectedly: a fresh install, and reinstalling the plugin from the Appstore.
      </p>
      <h3 className="mt-4 font-semibold text-amber-900">Enable HTTPS</h3>
      <ol className="mt-2 list-inside list-decimal space-y-1 text-amber-900">
        <li>
          Open the SignalK admin UI → <strong>Server → Settings</strong>.
        </li>
        <li>
          Turn on <strong>Use SSL</strong> and save.
        </li>
        <li>
          Restart SignalK. The server will rebind on port <code>{port}</code> with the certificate
          this plugin installed.
        </li>
      </ol>
      <p className="mt-3 text-sm text-amber-800">
        Container restart note: if SignalK runs in a container with restart policy <code>no</code>,
        the in-UI restart will stop the server without bringing it back — restart the container
        directly (e.g. <code>podman restart signalk-server</code>).
      </p>
      <p className="mt-3 text-sm text-amber-800">
        Alternative: edit <code>~/.signalk/settings.json</code> and set{' '}
        <code>&quot;ssl&quot;: true</code>, then restart.
      </p>
    </section>
  )
}

export default EnableHttpsPanel
