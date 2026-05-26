import React, { useState } from 'react'
import { unlock } from '../api.js'

interface Props {
  onUnlocked: () => void
}

const UnlockPanel = ({ onUnlocked }: Props): React.JSX.Element => {
  const [passphrase, setPassphrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handle = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const out = await unlock(passphrase)
      if (out.kind === 'error') {
        setError(out.message)
      } else if (out.kind === 'locked') {
        setError('Still locked — passphrase rejected or env var missing.')
      } else {
        setPassphrase('')
        onUnlocked()
      }
    } catch (e2: unknown) {
      setError(e2 instanceof Error ? e2.message : String(e2))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold">Unlock</h2>
      <p className="mt-2 text-slate-600">
        The CA private key is encrypted. Enter the passphrase to decrypt it. The passphrase is held
        in memory only — never written to disk.
      </p>
      <form
        onSubmit={(e) => {
          void handle(e)
        }}
        className="mt-4 space-y-3"
      >
        <label htmlFor="signalk-ssl-passphrase" className="sr-only">
          Passphrase
        </label>
        <input
          id="signalk-ssl-passphrase"
          type="password"
          value={passphrase}
          onChange={(e) => {
            setPassphrase(e.target.value)
          }}
          className="block w-full rounded-lg border border-slate-300 px-4 py-3 font-mono shadow-sm focus:border-sky-500 focus:outline-none focus:ring-sky-500"
          placeholder="passphrase"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
        />
        {error !== null && <p className="rounded-md bg-red-50 p-3 text-sm text-red-800">{error}</p>}
        <button
          type="submit"
          disabled={busy || passphrase.length === 0}
          className="inline-flex w-full items-center justify-center rounded-lg bg-sky-600 px-5 py-3 text-base font-medium text-white shadow-sm hover:bg-sky-700 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {busy ? 'Unlocking…' : 'Unlock'}
        </button>
      </form>
    </section>
  )
}

export default UnlockPanel
