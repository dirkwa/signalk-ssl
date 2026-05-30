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
import { checkPermissions } from './container-env.js'

export type IssueOutcome =
  | { readonly kind: 'no-op'; readonly reason: 'still-valid'; readonly decision: RenewalDecision }
  | { readonly kind: 'issued'; readonly reason: RenewalDecision['reason'] | 'first-run' }
  | { readonly kind: 'locked'; readonly reason: 'passphrase-required' | 'env-missing' }
  | { readonly kind: 'error'; readonly message: string }

export type RotateOutcome =
  | { readonly kind: 'rotated' }
  | { readonly kind: 'no-ca' }
  | { readonly kind: 'wrong-passphrase' }
  | { readonly kind: 'error'; readonly message: string }

/** Runtime snapshot of signalk-server's HTTP/HTTPS binding state. */
export interface ServerNetState {
  /** True/false when signalk-server reports settings.ssl, null when it doesn't
   * (older server, or any case where the runtime can't tell). The webapp only
   * shows the enable-HTTPS help on an explicit `false`, never on null. */
  readonly sslEnabled: boolean | null
  /** Plain-HTTP port (signalk-server settings.port; default 3000). */
  readonly httpPort: number | null
  /** HTTPS port (signalk-server settings.sslport; default 443). */
  readonly sslPort: number | null
}

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
  readonly permissionWarning: string | null
  /** Whether signalk-server is actually serving HTTPS. The plugin can install a
   * cert and the server still serve plain HTTP if settings.ssl is false — the
   * webapp surfaces help for that case. Null when the runtime can't tell. */
  readonly serverSslEnabled: boolean | null
  /** Ports the server reports for the help/URL hints. Both null when unknown. */
  readonly serverHttpPort: number | null
  readonly serverSslPort: number | null
}

export interface SslServiceDeps {
  readonly store: CertStore
  readonly passphrase: PassphraseSource
  readonly config: SignalkSslConfig
  readonly configPath: string
  /** Snapshot of signalk-server's net state, evaluated at request time so a
   * settings flip is reflected immediately. Optional — when absent the status
   * exposes nulls and the webapp suppresses the help. */
  readonly getServerNetState?: () => ServerNetState
}

const MS_PER_DAY = 24 * 60 * 60 * 1000

export class SslService {
  private restartRequired = false
  private permissionWarning: string | null = null

  constructor(private readonly deps: SslServiceDeps) {}

  /**
   * Probe write access to the data dir and the cert install path. On a
   * rootless-Podman UID-shift the bind-mounted host dir looks present but
   * rejects child creation; this surfaces that as an operator-facing warning
   * (logged at start, exposed via /status) rather than failing silently on
   * the first cert write. Idempotent — safe to call on every start.
   */
  async checkWritePermissions(): Promise<string | null> {
    this.permissionWarning = await checkPermissions({
      dataDir: this.deps.store.dataDir,
      configPath: this.deps.configPath
    })
    return this.permissionWarning
  }

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

  /**
   * Re-encrypt the CA private key under a new passphrase. The CA key is the
   * only passphrase-protected artifact (leaf keys are written plaintext at
   * 0o600 to the TLS path), so rotation is a single re-wrap: decrypt with the
   * old passphrase, re-encrypt with the new one, write back atomically.
   *
   * `oldPassphrase` must match whatever the CA key is currently wrapped with
   * — for `env`/`webapp` modes that's the operator's typed value; for
   * `convenience` mode it's the machine-derived digest, which the caller
   * can't type, so this route is only meaningful for env/webapp installs.
   * We verify by attempting decryption and never touch disk on a mismatch.
   */
  async rotatePassphrase(oldPassphrase: string, newPassphrase: string): Promise<RotateOutcome> {
    const caState = await this.deps.store.readCaState()
    if (caState === null) {
      return { kind: 'no-ca' }
    }
    let caPrivateKey: CryptoKey
    try {
      caPrivateKey = await decryptPrivateKeyPkcs8(caState.encryptedKeyPem, oldPassphrase)
    } catch {
      return { kind: 'wrong-passphrase' }
    }
    try {
      const reEncrypted = await encryptPrivateKeyPkcs8(caPrivateKey, newPassphrase)
      await this.deps.store.writeCaState({ ...caState, encryptedKeyPem: reEncrypted })
    } catch (e: unknown) {
      return { kind: 'error', message: e instanceof Error ? e.message : String(e) }
    }
    // The in-memory passphrase (webapp mode) must follow the re-wrap, or the
    // next resolve() would still hand back the old value and fail to decrypt.
    this.deps.passphrase.unlockWith(newPassphrase)
    return { kind: 'rotated' }
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
    const caCertPath = importCfg?.caCertPath ?? ''
    const caKeyPath = importCfg?.caKeyPath ?? ''
    if (caCertPath === '' || caKeyPath === '') {
      throw new Error(
        'import mode requires both "Import → CA certificate file path" and ' +
          '"Import → CA private-key file path (encrypted PKCS#8)" to be set in the plugin config.'
      )
    }
    const [certificatePem, encryptedKeyPem] = await Promise.all([
      readFile(caCertPath, 'utf8'),
      readFile(caKeyPath, 'utf8')
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

  private serverState(): {
    sslEnabled: boolean | null
    httpPort: number | null
    sslPort: number | null
  } {
    if (this.deps.getServerNetState === undefined) {
      return { sslEnabled: null, httpPort: null, sslPort: null }
    }
    const s = this.deps.getServerNetState()
    return { sslEnabled: s.sslEnabled, httpPort: s.httpPort, sslPort: s.sslPort }
  }

  async status(): Promise<ServiceStatus> {
    const caState = await this.deps.store.readCaState()
    const leafState = await this.deps.store.readLeafState()
    const net = this.serverState()
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
        restartRequired: this.restartRequired,
        permissionWarning: this.permissionWarning,
        serverSslEnabled: net.sslEnabled,
        serverHttpPort: net.httpPort,
        serverSslPort: net.sslPort
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
      restartRequired: this.restartRequired,
      permissionWarning: this.permissionWarning,
      serverSslEnabled: net.sslEnabled,
      serverHttpPort: net.httpPort,
      serverSslPort: net.sslPort
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
  // libuv's getifaddrs() throws ERR_SYSTEM_ERROR (errno 95, EOPNOTSUPP) on
  // some sandboxed environments — observed on GitHub-hosted ubuntu-latest
  // under `firejail --net=none` in the dirkwa SignalK plugin registry CI.
  // The plugin's SAN-suggestion flow treats "no interfaces" as a no-op
  // already; mirror that for "interface enumeration failed".
  let ifaces: ReturnType<typeof networkInterfaces>
  try {
    ifaces = networkInterfaces()
  } catch {
    return []
  }
  for (const addrs of Object.values(ifaces)) {
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

/**
 * True for RFC-1918 private IPv4 ranges (10/8, 172.16/12, 192.168/16) — the
 * address space a boat LAN actually uses. Public IPs are excluded so we never
 * bake a routable address into a long-lived cert.
 */
const isPrivateIpv4 = (ip: string): boolean => {
  const octets = ip.split('.').map(Number)
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    return false
  }
  const [a, b] = octets as [number, number, number, number]
  if (a === 10) {
    return true
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true
  }
  if (a === 192 && b === 168) {
    return true
  }
  return false
}

/**
 * Discovered LAN IPv4 addresses suitable for seeding into the cert's
 * `ipAddresses` SAN default — same source as {@link discoverLocalIps} but
 * filtered to RFC-1918 private ranges. Returned as a non-forcing suggestion;
 * the user can trim any (e.g. a VPN-overlay address) in the config form before
 * saving.
 */
export const discoverPrivateLanIps = (): string[] => discoverLocalIps().filter(isPrivateIpv4)

/**
 * Derive a DNS-name suggestion to add as a SAN, given the raw hostname
 * signalk-server uses for its mDNS advertisement
 * (`app.config.getExternalHostname()`).
 *
 * Two flavours of input come through that source:
 *
 *   1. A bare host like `pi5radar` or `pi5radar.local` — signalk-server's
 *      `mdns.js` strips trailing `.` and `.local` then advertises as
 *      `<stripped>.local`. We mirror that and return `pi5radar.local`.
 *   2. An FQDN like `signalk.example.com` (typically from `EXTERNALHOST=` or
 *      `settings.proxy_host` — a reverse-proxied deploy). Suggesting
 *      `signalk.example.com.local` would be wrong; the public FQDN is
 *      already the right SAN. Return it unchanged.
 *
 * Returns `null` when no useful suggestion can be made:
 *
 *   - 12-hex-digit container IDs (`os.hostname()` inside a bridge-network
 *     container without `--hostname` is the random container ID).
 *   - `localhost` / `hostname_not_available` (signalk-server's fallback when
 *     `os.hostname()` throws).
 *   - Empty or whitespace-only strings.
 */
export const discoverAdvertisedHostname = (rawHostname: string): string | null => {
  const trimmed = rawHostname.trim().replace(/\.$/, '')
  if (trimmed.length === 0) {
    return null
  }
  if (trimmed === 'localhost' || trimmed === 'hostname_not_available') {
    return null
  }
  // Bare hostname or `<host>.local` → suggest `<host>.local`.
  if (/\.local$/i.test(trimmed)) {
    const bare = trimmed.replace(/\.local$/i, '')
    if (/^[0-9a-f]{12}$/.test(bare)) {
      return null
    }
    return `${bare}.local`
  }
  if (trimmed.includes('.')) {
    // FQDN — suggest as-is. Reverse-proxied deploys want the public name.
    return trimmed
  }
  if (/^[0-9a-f]{12}$/.test(trimmed)) {
    return null
  }
  return `${trimmed}.local`
}
