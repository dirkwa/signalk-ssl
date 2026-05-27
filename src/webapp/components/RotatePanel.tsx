import React, { useState } from 'react'
import { rotate } from '../api.js'

const RotatePanel = (): React.JSX.Element => {
  const [open, setOpen] = useState(false)
  const [oldPassphrase, setOldPassphrase] = useState('')
  const [newPassphrase, setNewPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  const mismatch = newPassphrase.length > 0 && confirm.length > 0 && newPassphrase !== confirm
  const canSubmit =
    !busy && oldPassphrase.length > 0 && newPassphrase.length > 0 && newPassphrase === confirm

  const handle = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    setDone(false)
    try {
      const out = await rotate(oldPassphrase, newPassphrase)
      switch (out.kind) {
        case 'rotated':
          setOldPassphrase('')
          setNewPassphrase('')
          setConfirm('')
          setDone(true)
          break
        case 'wrong-passphrase':
          setError('Current passphrase is incorrect.')
          break
        case 'no-ca':
          setError('No CA exists yet — nothing to rotate.')
          break
        case 'error':
          setError(out.message)
          break
      }
    } catch (e2: unknown) {
      setError(e2 instanceof Error ? e2.message : String(e2))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <button
        type="button"
        onClick={() => {
          setOpen((v) => !v)
        }}
        className="flex w-full items-center justify-between text-left"
        aria-expanded={open}
      >
        <h2 className="text-lg font-semibold">Change passphrase</h2>
        <span className="text-slate-400">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <>
          <p className="mt-2 text-slate-600">
            Re-encrypts the CA private key under a new passphrase. The certificate itself does not
            change — devices that already trust your CA keep working, and no restart is needed.
          </p>
          <p className="mt-2 text-sm text-slate-500">
            In <span className="font-mono">env</span> mode you must also update the{' '}
            <span className="font-mono">SIGNALK_SSL_PASSPHRASE</span> environment variable to the
            new value, or the next restart will fail to decrypt the CA.
          </p>

          <form
            onSubmit={(e) => {
              void handle(e)
            }}
            className="mt-4 space-y-3"
          >
            <input
              type="password"
              value={oldPassphrase}
              onChange={(e) => {
                setOldPassphrase(e.target.value)
              }}
              className="block w-full rounded-lg border border-slate-300 px-4 py-3 font-mono shadow-sm focus:border-sky-500 focus:outline-none focus:ring-sky-500"
              placeholder="current passphrase"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
            />
            <input
              type="password"
              value={newPassphrase}
              onChange={(e) => {
                setNewPassphrase(e.target.value)
              }}
              className="block w-full rounded-lg border border-slate-300 px-4 py-3 font-mono shadow-sm focus:border-sky-500 focus:outline-none focus:ring-sky-500"
              placeholder="new passphrase"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
            />
            <input
              type="password"
              value={confirm}
              onChange={(e) => {
                setConfirm(e.target.value)
              }}
              className="block w-full rounded-lg border border-slate-300 px-4 py-3 font-mono shadow-sm focus:border-sky-500 focus:outline-none focus:ring-sky-500"
              placeholder="confirm new passphrase"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
            />
            {mismatch && <p className="text-sm text-amber-700">New passphrases don’t match.</p>}
            {error !== null && (
              <p className="rounded-md bg-red-50 p-3 text-sm text-red-800">{error}</p>
            )}
            {done && (
              <p className="rounded-md bg-green-50 p-3 text-sm text-green-800">
                Passphrase rotated. The CA key is now encrypted with the new passphrase.
              </p>
            )}
            <button
              type="submit"
              disabled={!canSubmit}
              className="inline-flex w-full items-center justify-center rounded-lg bg-sky-600 px-5 py-3 text-base font-medium text-white shadow-sm hover:bg-sky-700 disabled:cursor-not-allowed disabled:bg-slate-300"
            >
              {busy ? 'Rotating…' : 'Change passphrase'}
            </button>
          </form>
        </>
      )}
    </section>
  )
}

export default RotatePanel
