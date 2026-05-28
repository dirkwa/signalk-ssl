// `@peculiar/x509` v2 wires `tsyringe` for DI, which requires the
// reflect-metadata polyfill loaded before any peculiar/x509 import is
// resolved. Putting it first in this file guarantees the side-effect
// runs ahead of every other import the module-graph pulls below.
import 'reflect-metadata'
import { createPrivateKey, type KeyObject, randomBytes, webcrypto } from 'node:crypto'
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  cryptoProvider,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509CertificateGenerator,
  type JsonGeneralNames
} from '@peculiar/x509'
import type { JsonName } from '@peculiar/x509'
import type {
  FingerprintAlgorithm,
  GenerateCaInput,
  GeneratedCa,
  ParsedSans,
  SignLeafInput,
  SignedLeaf
} from './types.js'

// Build the DN as a structured JsonName so @peculiar/x509 handles RFC 4514
// escaping internally. Hand-rolled `CN=${name}, O=${org}` interpolation
// would break on common names containing comma, equals, plus, backslash, etc.
const dn = (commonName: string, organization: string): JsonName => [
  { CN: [commonName] },
  { O: [organization] }
]

// Node's `webcrypto.Crypto` and the WebWorker lib's global `Crypto` diverge on
// the Ed25519 overload; the runtime objects are identical but the structural
// types aren't compatible. @peculiar/x509 v1 only declares the global type.
cryptoProvider.set(webcrypto as unknown as Crypto)

const EC_ALGORITHM: EcKeyGenParams & EcdsaParams = {
  name: 'ECDSA',
  namedCurve: 'P-256',
  hash: 'SHA-256'
}

const MS_PER_DAY = 24 * 60 * 60 * 1000
const MS_PER_HOUR = 60 * 60 * 1000
const PBKDF2_DEFAULT_ITERATIONS = 600_000

const generateSerialNumber = (): string => {
  const bytes = randomBytes(16)
  // Two constraints on byte 0:
  //  - bit 7 must be clear, so DER reads the value as a positive INTEGER
  //    (a leading byte ≥ 0x80 would otherwise be misread as negative).
  //  - it must be non-zero, otherwise X.509 parsers (including @peculiar/x509)
  //    strip the leading 0x00 padding and our reported serial drifts away
  //    from what we asked for — fine for uniqueness but it makes the
  //    "first hex pair < 0x80" round-trip assertion flake on ~1-in-128 runs.
  const firstByte = bytes[0] ?? 0
  bytes[0] = (firstByte & 0x7f) | 0x01
  return bytes.toString('hex')
}

export const generateKeyPair = async (): Promise<CryptoKeyPair> => {
  return webcrypto.subtle.generateKey(EC_ALGORITHM, true, ['sign', 'verify'])
}

export const generateCa = async (input: GenerateCaInput): Promise<GeneratedCa> => {
  const keys = await generateKeyPair()
  const notBefore = new Date()
  const notAfter = new Date(notBefore.getTime() + input.validityDays * MS_PER_DAY)
  const distinguishedName = dn(input.commonName, input.organization)

  const cert = await X509CertificateGenerator.create({
    serialNumber: generateSerialNumber(),
    subject: distinguishedName,
    issuer: distinguishedName,
    notBefore,
    notAfter,
    publicKey: keys.publicKey,
    signingKey: keys.privateKey,
    signingAlgorithm: EC_ALGORITHM,
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
      await SubjectKeyIdentifierExtension.create(keys.publicKey)
    ]
  })

  return {
    certificatePem: cert.toString('pem'),
    privateKey: keys.privateKey
  }
}

const sansToJsonGeneralNames = (sans: ParsedSans): JsonGeneralNames => {
  return [
    ...sans.dnsNames.map((value) => ({ type: 'dns' as const, value })),
    ...sans.ipAddresses.map((value) => ({ type: 'ip' as const, value }))
  ]
}

export const signLeaf = async (input: SignLeafInput): Promise<SignedLeaf> => {
  const issuerCert = new X509Certificate(input.issuer.certificatePem)
  const keys = await generateKeyPair()

  // Clock-skew defence: a phone whose clock lags the server's would reject a
  // cert whose notBefore is "right now". Backdating by clockSkewHours lets the
  // common offline-boat scenario work without manual NTP intervention.
  const now = Date.now()
  const notBefore = new Date(now - input.clockSkewHours * MS_PER_HOUR)
  const notAfter = new Date(now + input.validityDays * MS_PER_DAY)

  const subject = dn(input.subjectCommonName, input.organization)

  const cert = await X509CertificateGenerator.create({
    serialNumber: generateSerialNumber(),
    subject,
    issuer: issuerCert.subject,
    notBefore,
    notAfter,
    publicKey: keys.publicKey,
    signingKey: input.issuer.privateKey,
    signingAlgorithm: EC_ALGORITHM,
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment, true),
      new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth], false),
      new SubjectAlternativeNameExtension(sansToJsonGeneralNames(input.sans), false),
      await SubjectKeyIdentifierExtension.create(keys.publicKey),
      await AuthorityKeyIdentifierExtension.create(issuerCert.publicKey)
    ]
  })

  const privateKeyPem = await exportPrivateKeyPlainPkcs8(keys.privateKey)

  return {
    certificatePem: cert.toString('pem'),
    privateKey: keys.privateKey,
    privateKeyPem
  }
}

const cryptoKeyToKeyObject = async (key: CryptoKey): Promise<KeyObject> => {
  const exported = await webcrypto.subtle.exportKey('pkcs8', key)
  return createPrivateKey({
    key: Buffer.from(exported),
    format: 'der',
    type: 'pkcs8'
  })
}

const keyObjectToCryptoKey = async (
  keyObject: KeyObject,
  usages: KeyUsage[]
): Promise<CryptoKey> => {
  const pkcs8 = keyObject.export({ type: 'pkcs8', format: 'der' })
  return webcrypto.subtle.importKey('pkcs8', pkcs8, EC_ALGORITHM, true, usages)
}

const exportPrivateKeyPlainPkcs8 = async (key: CryptoKey): Promise<string> => {
  const keyObject = await cryptoKeyToKeyObject(key)
  return keyObject.export({ type: 'pkcs8', format: 'pem' }) as string
}

/**
 * Encrypt a CryptoKey as PBES2 / PBKDF2-SHA256 / AES-256-CBC PKCS#8 PEM.
 * (Node's openssl bindings don't expose AES-GCM as a PBES2 cipher; AES-256-CBC
 * is the strongest cipher Node will emit and is what `openssl pkcs8 -topk8`
 * produces by default for `-v2 aes-256-cbc`.)
 */
export const encryptPrivateKeyPkcs8 = async (
  key: CryptoKey,
  passphrase: string
): Promise<string> => {
  const keyObject = await cryptoKeyToKeyObject(key)
  return keyObject.export({
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase
  }) as string
}

export const decryptPrivateKeyPkcs8 = async (
  pem: string,
  passphrase: string
): Promise<CryptoKey> => {
  const keyObject = createPrivateKey({
    key: pem,
    format: 'pem',
    passphrase
  })
  return keyObjectToCryptoKey(keyObject, ['sign'])
}

export const derivePassphraseKey = async (
  passphrase: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_DEFAULT_ITERATIONS
): Promise<CryptoKey> => {
  const keyMaterial = await webcrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  )
  return webcrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

const DIGEST_ALG: Record<FingerprintAlgorithm, string> = {
  sha256: 'SHA-256'
}

export const computeSpkiFingerprint = async (
  certificatePem: string,
  algorithm: FingerprintAlgorithm
): Promise<string> => {
  const cert = new X509Certificate(certificatePem)
  const spki = await webcrypto.subtle.exportKey('spki', await cert.publicKey.export())
  const digest = await webcrypto.subtle.digest(DIGEST_ALG[algorithm], spki)
  const bytes = new Uint8Array(digest)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':')
}

export const verifyChain = async (
  leafPem: string,
  caPem: string,
  atDate: Date = new Date()
): Promise<boolean> => {
  const leaf = new X509Certificate(leafPem)
  const ca = new X509Certificate(caPem)
  return leaf.verify({ publicKey: ca.publicKey, date: atDate })
}
