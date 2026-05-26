import { readFile } from 'node:fs/promises'
import { networkInterfaces } from 'node:os'
import {
  computeSpkiFingerprint,
  decryptPrivateKeyPkcs8,
  encryptPrivateKeyPkcs8,
  generateCa,
  signLeaf
} from './crypto.js'
import { needsRenewal, type RenewalDecision } from './needs-renewal.js'
import { parseSans, sanitizeHostname } from './sans.js'
import type { ParsedSans } from './types.js'
import type { CaStateOnDisk, CertStore, LeafStateOnDisk } from './storage.js'
import type { PassphraseSource } from './passphrase-source.js'
import type { SignalkSslConfig } from './schema.js'
import { defaultTargets, installCerts, type InstallTargets } from './cert-installer.js'

export type IssueOutcome =
  | { readonly kind: 'no-op'; readonly reason: 'still-valid'; readonly decision: RenewalDecision }
  | { readonly kind: 'issued'; readonly reason: RenewalDecision['reason'] | 'first-run' }
  | { readonly kind: 'locked'; readonly reason: 'passphrase-required' | 'env-missing' }
  | { readonly kind: 'error'; readonly message: string }

export interface ServiceStatus {
  readonly hasCa: boolean
  readonly caFingerprint: string | null
  readonly caCreatedAt: string | null
  readonly hasLeaf: boolean
  readonly leafExpiresAt: string | null
  readonly leafDaysRemaining: number | null
  readonly leafSansDns: readonly string[]
  readonly leafSansIp: readonly string[]
  readonly restartRequired: boolean
}

export interface SslServiceDeps {
  readonly store: CertStore
  readonly passphrase: PassphraseSource
  readonly config: SignalkSslConfig
  readonly configPath: string
}

const MS_PER_DAY = 24 * 60 * 60 * 1000

export class SslService {
  private restartRequired = false

  constructor(private readonly deps: SslServiceDeps) {}

  targets(): InstallTargets {
    return defaultTargets(this.deps.configPath)
  }

  private resolveSans(): ParsedSans {
    return parseSans([...this.deps.config.sans.dnsNames, ...this.deps.config.sans.ipAddresses])
  }

  async issueIfNeeded(): Promise<IssueOutcome> {
    const passphrase = await this.deps.passphrase.resolve()
    if (passphrase.kind === 'unlock-required') {
      return { kind: 'locked', reason: 'passphrase-required' }
    }
    if (passphrase.kind === 'missing-env') {
      return { kind: 'locked', reason: 'env-missing' }
    }

    const requiredSans = this.resolveSans()
    if (requiredSans.dnsNames.length + requiredSans.ipAddresses.length === 0) {
      return { kind: 'error', message: 'At least one SAN (DNS or IP) must be configured' }
    }

    const caState =
      (await this.deps.store.readCaState()) ?? (await this.bootstrapCa(passphrase.passphrase))

    const caPrivateKey = await decryptPrivateKeyPkcs8(
      caState.encryptedKeyPem,
      passphrase.passphrase
    )
    const existing = await this.deps.store.readLeafState()
    const subjectCn = pickPrimaryCn(requiredSans)

    if (existing !== null) {
      const decision = needsRenewal(
        existing.certificatePem,
        requiredSans,
        this.deps.config.renewalThresholdDays
      )
      if (!decision.needsRenewal) {
        await this.ensureFilesOnDisk(existing, caState)
        return { kind: 'no-op', reason: 'still-valid', decision }
      }
      const newLeaf = await this.signAndStoreLeaf(caState, caPrivateKey, requiredSans, subjectCn)
      await this.ensureFilesOnDisk(newLeaf, caState)
      this.restartRequired = true
      return { kind: 'issued', reason: decision.reason }
    }

    const newLeaf = await this.signAndStoreLeaf(caState, caPrivateKey, requiredSans, subjectCn)
    await this.ensureFilesOnDisk(newLeaf, caState)
    this.restartRequired = true
    return { kind: 'issued', reason: 'first-run' }
  }

  private async bootstrapCa(passphrase: string): Promise<CaStateOnDisk> {
    if (this.deps.config.mode === 'import') {
      return this.importCa(passphrase)
    }
    const ca = await generateCa({
      commonName: this.deps.config.commonName,
      organization: this.deps.config.organization,
      validityDays: this.deps.config.validityDaysCA
    })
    const encryptedKey = await encryptPrivateKeyPkcs8(ca.privateKey, passphrase)
    const fingerprint = await computeSpkiFingerprint(ca.certificatePem, 'sha256')
    const state: CaStateOnDisk = {
      certificatePem: ca.certificatePem,
      encryptedKeyPem: encryptedKey,
      fingerprintSha256: fingerprint,
      createdAt: new Date().toISOString(),
      mode: 'generate'
    }
    await this.deps.store.writeCaState(state)
    return state
  }

  private async importCa(passphrase: string): Promise<CaStateOnDisk> {
    const importCfg = this.deps.config.import
    if (importCfg === undefined) {
      throw new Error('import mode selected but no import paths configured')
    }
    const [certificatePem, encryptedKeyPem] = await Promise.all([
      readFile(importCfg.caCertPath, 'utf8'),
      readFile(importCfg.caKeyPath, 'utf8')
    ])
    // Validate the key actually decrypts before persisting — fail fast.
    await decryptPrivateKeyPkcs8(encryptedKeyPem, passphrase)
    const fingerprint = await computeSpkiFingerprint(certificatePem, 'sha256')
    const state: CaStateOnDisk = {
      certificatePem,
      encryptedKeyPem,
      fingerprintSha256: fingerprint,
      createdAt: new Date().toISOString(),
      mode: 'import'
    }
    await this.deps.store.writeCaState(state)
    return state
  }

  private async signAndStoreLeaf(
    caState: CaStateOnDisk,
    caPrivateKey: CryptoKey,
    sans: ParsedSans,
    subjectCommonName: string
  ): Promise<LeafStateOnDisk> {
    const signed = await signLeaf({
      issuer: { certificatePem: caState.certificatePem, privateKey: caPrivateKey },
      subjectCommonName,
      organization: this.deps.config.organization,
      sans,
      validityDays: this.deps.config.validityDaysLeaf,
      clockSkewHours: this.deps.config.clockSkewHours
    })
    const state: LeafStateOnDisk = {
      certificatePem: signed.certificatePem,
      privateKeyPem: signed.privateKeyPem,
      sansHash: hashSans(sans),
      issuedAt: new Date().toISOString()
    }
    await this.deps.store.writeLeafState(state)
    return state
  }

  private async ensureFilesOnDisk(leaf: LeafStateOnDisk, ca: CaStateOnDisk): Promise<void> {
    await installCerts(this.targets(), leaf.certificatePem, leaf.privateKeyPem, ca.certificatePem)
  }

  async status(): Promise<ServiceStatus> {
    const caState = await this.deps.store.readCaState()
    const leafState = await this.deps.store.readLeafState()
    if (leafState === null) {
      return {
        hasCa: caState !== null,
        caFingerprint: caState?.fingerprintSha256 ?? null,
        caCreatedAt: caState?.createdAt ?? null,
        hasLeaf: false,
        leafExpiresAt: null,
        leafDaysRemaining: null,
        leafSansDns: [],
        leafSansIp: [],
        restartRequired: this.restartRequired
      }
    }
    const decision = needsRenewal(
      leafState.certificatePem,
      this.resolveSans(),
      this.deps.config.renewalThresholdDays
    )
    return {
      hasCa: caState !== null,
      caFingerprint: caState?.fingerprintSha256 ?? null,
      caCreatedAt: caState?.createdAt ?? null,
      hasLeaf: true,
      leafExpiresAt: new Date(Date.now() + decision.daysUntilExpiry * MS_PER_DAY).toISOString(),
      leafDaysRemaining: Math.round(decision.daysUntilExpiry),
      leafSansDns: this.deps.config.sans.dnsNames.map((d) => sanitizeHostname(d).toLowerCase()),
      leafSansIp: this.deps.config.sans.ipAddresses,
      restartRequired: this.restartRequired
    }
  }

  acknowledgeRestart(): void {
    this.restartRequired = false
  }
}

const pickPrimaryCn = (sans: ParsedSans): string => {
  const firstDns = sans.dnsNames[0]
  if (firstDns !== undefined) {
    return firstDns
  }
  const firstIp = sans.ipAddresses[0]
  if (firstIp !== undefined) {
    return firstIp
  }
  return 'signalk-server'
}

const hashSans = (sans: ParsedSans): string => {
  return [...sans.dnsNames, ...sans.ipAddresses].sort().join('|')
}

export const discoverLocalIps = (): string[] => {
  const out = new Set<string>()
  for (const addrs of Object.values(networkInterfaces())) {
    if (!addrs) {
      continue
    }
    for (const addr of addrs) {
      if (addr.internal) {
        continue
      }
      if (addr.family === 'IPv4') {
        out.add(addr.address)
      }
    }
  }
  return [...out]
}
