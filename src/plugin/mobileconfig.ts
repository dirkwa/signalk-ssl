import { randomUUID } from 'node:crypto'

export interface MobileconfigOptions {
  readonly caName: string
  readonly organization: string
}

const escapeXml = (s: string): string =>
  s.replace(/[<>&'"]/g, (ch) => {
    switch (ch) {
      case '<':
        return '&lt;'
      case '>':
        return '&gt;'
      case '&':
        return '&amp;'
      case "'":
        return '&apos;'
      case '"':
        return '&quot;'
      default:
        return ch
    }
  })

const pemToDerBase64 = (pem: string): string =>
  pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '')

/**
 * Build an unsigned .mobileconfig profile that installs `caCertPem` as a
 * trusted root on iOS/iPadOS. Localised consent text mirrors what Keeper
 * ships in https-service.ts:227-297 (en/de/fr/es/nl).
 */
export const buildMobileconfig = (caCertPem: string, options: MobileconfigOptions): string => {
  const der = pemToDerBase64(caCertPem)
  const profileUuid = randomUUID().toUpperCase()
  const certUuid = randomUUID().toUpperCase()
  const name = escapeXml(options.caName)
  const org = escapeXml(options.organization)

  const consent = {
    en: `After installing this profile, enable full trust: Settings → General → About → Certificate Trust Settings → enable "${options.caName}".`,
    de: `Nach der Installation dieses Profils aktivieren Sie volles Vertrauen: Einstellungen → Allgemein → Info → Zertifikatsvertrauenseinstellungen → "${options.caName}" aktivieren.`,
    fr: `Après l'installation de ce profil, activez la confiance totale : Réglages → Général → Informations → Réglages des certificats → activer « ${options.caName} ».`,
    es: `Después de instalar este perfil, habilite la confianza total: Ajustes → General → Información → Ajustes de certificados → activar "${options.caName}".`,
    nl: `Schakel na installatie van dit profiel volledig vertrouwen in: Instellingen → Algemeen → Info → Instellingen vertrouwde certificaten → "${options.caName}" inschakelen.`
  }

  const consentXml = Object.entries(consent)
    .map(([lang, text]) => `\t\t<key>${lang}</key>\n\t\t<string>${escapeXml(text)}</string>`)
    .join('\n')

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>PayloadCertificateFileName</key>
\t\t\t<string>signalk-ssl-ca.crt</string>
\t\t\t<key>PayloadContent</key>
\t\t\t<data>${der}</data>
\t\t\t<key>PayloadDescription</key>
\t\t\t<string>Adds the ${name} root certificate</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>${name}</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>com.signalk.ssl.ca-cert</string>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.security.root</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>${certUuid}</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t</dict>
\t</array>
\t<key>PayloadDescription</key>
\t<string>Installs the ${name} certificate so your device trusts HTTPS connections to your SignalK server.</string>
\t<key>PayloadDisplayName</key>
\t<string>SignalK Secure Connection</string>
\t<key>PayloadIdentifier</key>
\t<string>com.signalk.ssl.https-profile</string>
\t<key>PayloadOrganization</key>
\t<string>${org}</string>
\t<key>PayloadRemovalDisallowed</key>
\t<false/>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadUUID</key>
\t<string>${profileUuid}</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
\t<key>ConsentText</key>
\t<dict>
\t\t<key>default</key>
\t\t<string>${escapeXml(consent.en)}</string>
${consentXml}
\t</dict>
</dict>
</plist>`
}
