import { SubjectAlternativeNameExtension, X509Certificate } from '@peculiar/x509'
import type { ParsedSans } from './types.js'

export type RenewalReason = 'expired' | 'expiring-soon' | 'san-mismatch' | 'ok'

export interface RenewalDecision {
  readonly needsRenewal: boolean
  readonly reason: RenewalReason
  readonly daysUntilExpiry: number
  readonly missingDnsNames: readonly string[]
  readonly missingIpAddresses: readonly string[]
}

const MS_PER_DAY = 24 * 60 * 60 * 1000

const extractSans = (cert: X509Certificate): ParsedSans => {
  const ext = cert.getExtension(SubjectAlternativeNameExtension)
  if (ext === null) {
    return { dnsNames: [], ipAddresses: [] }
  }
  const names = ext.names.toJSON()
  return {
    dnsNames: names.filter((n) => n.type === 'dns').map((n) => n.value.toLowerCase()),
    ipAddresses: names.filter((n) => n.type === 'ip').map((n) => n.value)
  }
}

export const needsRenewal = (
  certificatePem: string,
  requiredSans: ParsedSans,
  thresholdDays: number,
  now: Date = new Date()
): RenewalDecision => {
  const cert = new X509Certificate(certificatePem)
  const daysUntilExpiry = (cert.notAfter.getTime() - now.getTime()) / MS_PER_DAY

  if (daysUntilExpiry <= 0) {
    return {
      needsRenewal: true,
      reason: 'expired',
      daysUntilExpiry,
      missingDnsNames: [],
      missingIpAddresses: []
    }
  }

  if (daysUntilExpiry < thresholdDays) {
    return {
      needsRenewal: true,
      reason: 'expiring-soon',
      daysUntilExpiry,
      missingDnsNames: [],
      missingIpAddresses: []
    }
  }

  const present = extractSans(cert)
  const presentDns = new Set(present.dnsNames)
  const presentIp = new Set(present.ipAddresses)
  const missingDnsNames = requiredSans.dnsNames.filter((d) => !presentDns.has(d))
  const missingIpAddresses = requiredSans.ipAddresses.filter((ip) => !presentIp.has(ip))

  if (missingDnsNames.length > 0 || missingIpAddresses.length > 0) {
    return {
      needsRenewal: true,
      reason: 'san-mismatch',
      daysUntilExpiry,
      missingDnsNames,
      missingIpAddresses
    }
  }

  return {
    needsRenewal: false,
    reason: 'ok',
    daysUntilExpiry,
    missingDnsNames: [],
    missingIpAddresses: []
  }
}
