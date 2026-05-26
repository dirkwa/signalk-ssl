import { Type, type Static } from '@sinclair/typebox'

export const SansSchema = Type.Object(
  {
    dnsNames: Type.Array(Type.String(), { default: [] }),
    ipAddresses: Type.Array(Type.String(), { default: [] })
  },
  { title: 'Subject Alternative Names' }
)

export const ImportSchema = Type.Object({
  caCertPath: Type.String({ title: 'CA certificate file path' }),
  caKeyPath: Type.String({ title: 'CA private-key file path (encrypted PKCS#8)' })
})

export const ConfigSchema = Type.Object(
  {
    mode: Type.Union([Type.Literal('generate'), Type.Literal('import')], {
      title: 'CA mode',
      description: '"generate" creates a fresh local CA; "import" loads an existing one from disk.',
      default: 'generate'
    }),
    commonName: Type.String({
      title: 'CA common name',
      default: 'SignalK Local CA',
      minLength: 1
    }),
    organization: Type.String({
      title: 'Organisation',
      default: 'SignalK',
      minLength: 1
    }),
    validityDaysCA: Type.Integer({
      title: 'CA validity (days)',
      default: 3650,
      minimum: 30,
      maximum: 7300
    }),
    validityDaysLeaf: Type.Integer({
      title: 'Leaf cert validity (days)',
      description: 'Apple/Chrome reject leaf certs > 398 days; 397 is the safe ceiling.',
      default: 397,
      minimum: 7,
      maximum: 398
    }),
    sans: SansSchema,
    passphraseMode: Type.Union(
      [Type.Literal('env'), Type.Literal('webapp'), Type.Literal('convenience')],
      {
        title: 'Passphrase mode',
        description:
          '"convenience" derives a key from host identity (no typing). "webapp" prompts in the UI on each restart. "env" reads SIGNALK_SSL_PASSPHRASE.',
        default: 'convenience'
      }
    ),
    import: Type.Optional(ImportSchema),
    renewalThresholdDays: Type.Integer({
      title: 'Auto-renew when fewer than N days remain',
      default: 30,
      minimum: 1,
      maximum: 90
    }),
    clockSkewHours: Type.Integer({
      title: 'Clock-skew backdate (hours)',
      description: 'notBefore = now - this. Defeats offline-boat phone clock drift.',
      default: 24,
      minimum: 0,
      maximum: 168
    })
  },
  {
    title: 'SignalK SSL',
    description: 'Manage a local Certificate Authority and HTTPS leaf certificates for this server.'
  }
)

export type SignalkSslConfig = Static<typeof ConfigSchema>

export const DEFAULT_CONFIG: SignalkSslConfig = {
  mode: 'generate',
  commonName: 'SignalK Local CA',
  organization: 'SignalK',
  validityDaysCA: 3650,
  validityDaysLeaf: 397,
  sans: { dnsNames: [], ipAddresses: [] },
  passphraseMode: 'convenience',
  renewalThresholdDays: 30,
  clockSkewHours: 24
}
