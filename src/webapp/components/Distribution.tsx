import React, { useMemo } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { caCrtUrl, caMobileconfigUrl, detectPlatform, type Status } from '../api.js'

interface Props {
  status: Status
}

const Distribution = ({ status }: Props): React.JSX.Element => {
  const platform = useMemo(() => detectPlatform(), [])

  // For phones to fetch the cert we need an absolute URL, not just the path.
  const origin = window.location.origin
  const absMobile = `${origin}${caMobileconfigUrl()}`
  const absCrt = `${origin}${caCrtUrl()}`
  // iOS prefers .mobileconfig; Android needs a .crt with the right MIME.
  const qrTarget = platform === 'ios' || platform === 'ipados' ? absMobile : absCrt

  if (!status.hasCa) {
    return (
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold">Install on your devices</h2>
        <p className="mt-2 text-slate-600">
          Create the CA first; then this panel will show a QR code.
        </p>
      </section>
    )
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold">Install on your devices</h2>
      <p className="mt-2 text-slate-600">
        Scan this QR with the device you want to trust. The OS-detected target is:{' '}
        <span className="font-mono">{platform}</span>.
      </p>

      <div className="mt-4 flex flex-col items-center gap-3 rounded-lg bg-slate-50 p-5">
        <QRCodeSVG value={qrTarget} size={240} marginSize={2} level="M" />
        <a
          href={qrTarget}
          className="break-all text-center text-xs font-mono text-sky-700 underline"
        >
          {qrTarget}
        </a>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
        <a
          href={absMobile}
          className="inline-flex items-center justify-center rounded-lg border border-slate-300 px-4 py-3 text-sm font-medium hover:bg-slate-50"
        >
          Download for iPhone / iPad (.mobileconfig)
        </a>
        <a
          href={absCrt}
          className="inline-flex items-center justify-center rounded-lg border border-slate-300 px-4 py-3 text-sm font-medium hover:bg-slate-50"
        >
          Download for Android / desktop (.crt)
        </a>
      </div>

      <details className="mt-6 rounded-md bg-slate-50 p-3 text-sm text-slate-700">
        <summary className="cursor-pointer font-medium">Per-OS install instructions</summary>
        <div className="mt-3 space-y-3">
          <div>
            <h3 className="font-semibold">iOS / iPadOS</h3>
            <ol className="list-inside list-decimal text-sm text-slate-600">
              <li>Tap the .mobileconfig download and allow it.</li>
              <li>Open Settings → General → VPN &amp; Device Management → install the profile.</li>
              <li>
                Open Settings → General → About → Certificate Trust Settings → enable the new CA.
              </li>
            </ol>
          </div>
          <div>
            <h3 className="font-semibold">Android</h3>
            <ol className="list-inside list-decimal text-sm text-slate-600">
              <li>Tap the .crt download.</li>
              <li>Settings → Security → Install from storage (path varies by vendor).</li>
              <li>Pick the .crt and name it something memorable.</li>
            </ol>
          </div>
          <div>
            <h3 className="font-semibold">macOS</h3>
            <ol className="list-inside list-decimal text-sm text-slate-600">
              <li>Double-click the downloaded .crt to open Keychain Access.</li>
              <li>Add it to the "System" keychain.</li>
              <li>
                Find it in the keychain, double-click, expand "Trust", and set "When using this
                certificate" to "Always Trust".
              </li>
            </ol>
          </div>
          <div>
            <h3 className="font-semibold">Windows</h3>
            <ol className="list-inside list-decimal text-sm text-slate-600">
              <li>Double-click the downloaded .crt.</li>
              <li>Click "Install Certificate" → "Local Machine" → "Trusted Root CAs".</li>
            </ol>
          </div>
          <div>
            <h3 className="font-semibold">Linux (Debian/Ubuntu)</h3>
            <ol className="list-inside list-decimal text-sm text-slate-600">
              <li>
                <span className="font-mono">sudo cp ca.crt /usr/local/share/ca-certificates/</span>
              </li>
              <li>
                <span className="font-mono">sudo update-ca-certificates</span>
              </li>
            </ol>
          </div>
        </div>
      </details>

      <details className="mt-3 rounded-md bg-slate-50 p-3 text-sm text-slate-700">
        <summary className="cursor-pointer font-medium">Out-of-band verification</summary>
        {status.caFingerprint !== null && (
          <div className="mt-3 space-y-3">
            <p>
              Confirm the CA fingerprint on each device after install — if they match, you know
              there's no man-in-the-middle on the boat network.
            </p>
            <code className="block break-all rounded bg-white p-2 text-xs">
              {status.caFingerprint}
            </code>
            <div className="flex justify-center bg-white p-3">
              <QRCodeSVG value={status.caFingerprint} size={160} level="L" />
            </div>
          </div>
        )}
      </details>
    </section>
  )
}

export default Distribution
