import { hostname } from 'node:os'
import { createHash, randomBytes } from 'node:crypto'
import type { CertStore, ConveniencePassphraseEnvelope, PassphraseMode } from './storage.js'

const ENV_VAR = 'SIGNALK_SSL_PASSPHRASE'

export type PassphraseResolveResult =
  | { readonly kind: 'ok'; readonly passphrase: string }
  | { readonly kind: 'unlock-required' }
  | { readonly kind: 'missing-env'; readonly envVar: string }

export interface PassphraseSourceOptions {
  readonly env?: NodeJS.ProcessEnv
  readonly machineId?: string
  readonly convenienceIterations?: number
}

export class PassphraseSource {
  private inMemory: string | null = null
  private readonly env: NodeJS.ProcessEnv
  private readonly machineId: string
  private readonly convenienceIterations: number

  constructor(
    private readonly mode: PassphraseMode,
    private readonly store: CertStore,
    options: PassphraseSourceOptions = {}
  ) {
    this.env = options.env ?? process.env
    this.machineId = options.machineId ?? hostname()
    this.convenienceIterations = options.convenienceIterations ?? 200_000
  }

  unlockWith(passphrase: string): void {
    this.inMemory = passphrase
  }

  lock(): void {
    this.inMemory = null
  }

  async resolve(): Promise<PassphraseResolveResult> {
    switch (this.mode) {
      case 'env': {
        const value = this.env[ENV_VAR]
        if (value === undefined || value === '') {
          return { kind: 'missing-env', envVar: ENV_VAR }
        }
        return { kind: 'ok', passphrase: value }
      }
      case 'webapp': {
        if (this.inMemory === null) {
          return { kind: 'unlock-required' }
        }
        return { kind: 'ok', passphrase: this.inMemory }
      }
      case 'convenience': {
        const passphrase = await this.deriveConvenience()
        return { kind: 'ok', passphrase }
      }
    }
  }

  private async deriveConvenience(): Promise<string> {
    let envelope = await this.store.readConvenienceEnvelope()
    if (envelope === null) {
      envelope = {
        salt: randomBytes(16).toString('hex'),
        iterations: this.convenienceIterations
      }
      await this.store.writeConvenienceEnvelope(envelope)
    }
    return derivePassphraseFromMachine(this.machineId, envelope)
  }
}

const derivePassphraseFromMachine = (
  machineId: string,
  envelope: ConveniencePassphraseEnvelope
): string => {
  // Convenience mode binds the wrapping passphrase to host identity. The
  // resulting string is *not* user-typeable — it's a deterministic 32-byte
  // hex digest fed to Node's PKCS#8 cipher just like a real passphrase. The
  // upshot is "convenience" mode encrypts the CA key with material that
  // never lives on disk in plaintext, but doesn't require the user to type
  // anything on each server restart.
  let buf = createHash('sha256').update(`${machineId}|${envelope.salt}`).digest()
  for (let i = 0; i < envelope.iterations; i += 1) {
    buf = createHash('sha256').update(buf).digest()
  }
  return buf.toString('hex')
}
