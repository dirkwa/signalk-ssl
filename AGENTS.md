# Agent guidance

This file is read by AI coding agents (Claude Code, Cursor, Codex, etc.) when working in this repo. `CLAUDE.md` re-references it.

## Project at a glance

`signalk-ssl` — SignalK Node Server plugin that manages a local Certificate Authority and HTTPS leaf certificates for the server.

Three responsibilities:

1. **CA + leaf cert management** — generates an EC P-256 CA (or imports an existing one), signs leaf certs covering configured DNS + IP SANs, auto-renews 30 days before expiry. Encrypts the CA private key at rest with PBES2 / PBKDF2-SHA256 / AES-256-CBC PKCS#8.
2. **Cert installation** — atomically writes `ssl-cert.pem` / `ssl-key.pem` / `ssl-chain.pem` to `${app.config.configPath}` with strict `0600` perms on the key (signalk-server refuses to start otherwise).
3. **CA distribution UX** — React 19 / Tailwind v4 webapp with a setup wizard, status dashboard, and a "scan this QR" panel that downloads the CA as `.mobileconfig` (iOS) or `.crt` (Android / desktop).

No sidecar containers, no `signalk-container` dependency. Pure in-process Node, runs on bare-metal and the SignalK Docker image equally.

## Commands

Build cycle order (preferred): `npm run format` → `npm run build:all` → `npm run test`.

- `npm run format` — prettier (writes) + (no eslint --fix here — use `lint:fix` separately)
- `npm run format:check` — non-mutating CI check
- `npm run lint` / `npm run lint:fix` — ESLint flat config, typescript-eslint `strictTypeChecked` on `src/plugin/**`
- `npm run typecheck` — `tsc --noEmit` for both plugin and webapp tsconfigs
- `npm run build:plugin` — `tsc` to `dist/plugin/`
- `npm run build:webapp` — Vite build to `public/`
- `npm run build:all` (alias `build`) — both, in order
- `npm run test` / `npm run test:watch` — vitest
- `npx vitest run --coverage` — coverage on `src/plugin/**`; target >90% on crypto/sans/needs-renewal

## Install contract (CRITICAL)

**The SignalK Appstore installs plugins with `npm install --ignore-scripts`.** This means:

- No `postinstall` / `prepare` lifecycle scripts run on the user's machine.
- The published tarball is what executes. `dist/plugin/` and `public/` **must** be pre-built and shipped in the package.
- `prepublishOnly` runs in **our** CI before `npm publish`, which is where the build happens.
- Runtime `dependencies` must be **pure JS** — no native modules, no `node-gyp` users, no `sharp`. Build-time deps (Vite, Tailwind, sharp, etc.) live in `devDependencies` only.

Test before every release: `npm pack` → `npm install --ignore-scripts ./signalk-ssl-X.Y.Z.tgz` into a fresh signalk-server. The plugin must start without errors.

## Pull request workflow

**One logical change per PR.** Refactors, behavior changes, doc updates, and dependency bumps belong in separate PRs. If a single change would produce two distinct lines in the auto-generated GitHub Release notes, it should be two PRs.

A bundled PR that "while I was in here, I also fixed X" is **not** acceptable — even if X is small. Open a second PR for X.

### Version bumps

`chore(release): X.Y.Z` is its **own** PR. Don't include a version bump in a feature or fix PR.

Workflow:

1. Open and merge feature/fix PRs (no version bump in any of them).
2. Open a separate `release-X.Y.Z` branch with only `package.json` bumped, with a `chore(release): X.Y.Z` commit.
3. Merge that PR.
4. Tag `vX.Y.Z` from `main` and push the tag — this triggers `publish.yml`.

### Branch naming

- No `/` in branch names (Signal K maintainers' convention). Use hyphens: `fix-leaf-renewal`, not `fix/leaf-renewal`.

### Commit messages

Angular conventional commits: `<type>(<scope>): <subject>` (`feat`, `fix`, `chore`, `docs`, `ci`, `test`, `refactor`). Subject in imperative mood ("add" not "added"), no trailing period.

No `Co-Authored-By` lines. No "Generated with Claude Code" attribution.

### PR descriptions

`## Summary` (bullets, why-not-what) and `## Tested` (only what was actually verified — no speculative test plans, no checkbox lists).

## CI / publishing

- **Plugin CI** (`.github/workflows/signalk-ci.yml`) calls the upstream `SignalK/signalk-server` reusable workflow. Runs on push and pull_request.
- **Publish** (`.github/workflows/publish.yml`) fires on `v*` tag push. Creates a GitHub Release with auto-generated notes (one line per PR since the previous tag), then `npm publish --provenance --access public`.
- **Trusted publishing only** — no `NPM_TOKEN` secret. Configure trusted publishing on npmjs.com for this package.
- **`repository.url` must exactly match the GitHub repo URL** (npm provenance OIDC requirement). Currently `git+https://github.com/dirkwa/signalk-ssl.git`.

## Plugin-specific gotchas

### Two route surfaces, two auth policies

signalk-server applies `adminAuthenticationMiddleware` to everything under `/plugins/*` with no opt-out (see `tokensecurity.ts:762`). The QR-code flow needs `ca.crt` and `ca.mobileconfig` to be reachable by phones without SignalK accounts.

Solution implemented in `src/plugin/api.ts`:

- Admin routes (`/status`, `/renew`, `/unlock`, `/lock`, `/api/local-ips`) — via `plugin.registerWithRouter`, mounted at `/plugins/signalk-ssl/*`, admin auth enforced.
- Public read-only routes (`/ssl/ca.crt`, `/ssl/ca.mobileconfig`) — via `plugin.signalKApiRoutes`, mounted at `/signalk/v1/api/*` where the server applies only `http_authorize(false)` (no admin required). `PUT`/`POST` on `/signalk/v1/api/*` is auto-protected by `writeAuthenticationMiddleware`, so accidentally exposing a destructive endpoint via this surface is structurally impossible.

When adding new routes, decide which surface they belong to:

- Mutation or sensitive read → `registerWithRouter`.
- Truly public read-only → `signalKApiRoutes`. (If in doubt, default to admin auth — it's reversible to move a route out later, but a leaked secret isn't.)

### Idempotency on plugin enable

`start()` must never regenerate the CA if one already exists, never re-issue a leaf that still covers all configured SANs. `SslService.issueIfNeeded()` is the single entry point and handles this:

1. Read existing CA state; bootstrap if missing.
2. Read existing leaf state; if `needsRenewal()` returns ok, just re-install the files in case they were modified externally, mark no-op, return.
3. Only sign a new leaf when expiry < threshold OR a required SAN is missing.

Toggling the plugin off and on in the admin UI must be a no-op for crypto state. Regression-test in `tests/service.test.ts` ("second call is a no-op").

### Clock skew backdate

`signLeaf` sets `notBefore = now - clockSkewHours * 1h` (default 24h). This is the single most useful one-line defence against the "offline boat's phone clock is behind the server" problem: iOS Safari rejects leaf certs with a `notBefore` in the device's future, even by seconds. Don't remove this. Tested in `tests/crypto/leaf.test.ts`.

### Encrypted PKCS#8, not custom envelope

The CA private key is stored as **encrypted PKCS#8 PEM** (PBES2 / PBKDF2-SHA256 / AES-256-CBC). Standard format; `openssl pkcs8` can decrypt it. Don't be tempted to roll a JSON envelope — the standard one is what every CLI knows how to handle.

Node's `crypto.createPrivateKey({ ..., passphrase })` and `keyObject.export({ ..., cipher, passphrase })` do this round-trip. AES-256-CBC is the strongest PBES2 cipher Node will emit — AES-GCM as a PBES2 cipher isn't exposed by Node's OpenSSL bindings.

### Three passphrase modes

`src/plugin/passphrase-source.ts`:

- `convenience` (default) — derives a stable wrapping passphrase from `hostname` + on-disk salt + N iterations of SHA-256. Boater-friendly: no typing, survives restart. The wrapping passphrase is _not_ user-typeable; it's a deterministic 32-byte hex digest fed to PKCS#8.
- `env` — reads `SIGNALK_SSL_PASSPHRASE` at startup. For Compose / systemd.
- `webapp` — prompts in the webapp on each restart. In-memory only, never written.

If you change the convenience derivation function, you change the wrapping passphrase. **That means every existing convenience-mode install can't decrypt its CA key anymore.** Don't change it lightly; bump the storage schema version and write a migration if you must.

### SAN provenance for auto-renewal-on-IP-change

Keeper's existing code auto-renewed whenever DHCP gave the server a new LAN IP. For signalk-ssl, the renewal logic in `needsRenewal` is purely "do required SANs match cert SANs". Users explicitly enter SANs in the plugin config — if you add auto-discovery of LAN IPs that gets folded into the renewed SAN list, **store provenance** (auto vs user-entered) so a user removing an auto-IP doesn't see it auto-re-added next renewal.

Currently the codebase doesn't auto-discover IPs into the SAN list; the webapp shows discovered IPs as a suggestion but the user must explicitly enter them.

### Cert destination path lives outside per-plugin data dir

The plugin's data lives under `app.getDataDirPath()` (`~/.signalk/plugin-config-data/signalk-ssl/`). But the actual TLS cert that signalk-server reads at boot must go to `${app.config.configPath}/ssl-{cert,key,chain}.pem` — that's where `master-signalk-server/src/security.ts:349-393` looks.

`SslService.targets()` returns the config-path-based InstallTargets. `app.config` is **not** in `@signalk/server-api`'s typed surface — it's a runtime field. `src/plugin/index.ts` defines `ExtendedServerAPI` to access it without `any`. When adding more runtime-only fields, extend that interface rather than casting.

### `0600` enforcement on the leaf key

`installCerts` writes the key with `mode: 0o600` and then `chmod`s it again. The chmod is belt-and-braces for filesystems where the inherited umask might widen the mode (some bind-mounted volumes do). Don't drop it.

### Webapp build location

Vite builds `src/webapp/` into `public/` at the repo root. signalk-server serves `public/` at `/plugins/signalk-ssl/`. Both `dist/` and `public/` must ship in the published tarball per the `--ignore-scripts` contract.

If you add new assets, put them under `src/webapp/` so Vite picks them up — don't drop static files directly into `public/` (they'll be wiped by `emptyOutDir: true`).

### Test isolation for crypto

CA generation and leaf signing are expensive (~50-100ms each). When writing tests, reuse a single CA across test cases in the same file via a shared setup function; don't re-generate per-test. See `tests/crypto/leaf.test.ts` for the pattern.

The convenience-mode SHA-256 iteration count is parameterised (`convenienceIterations`) so tests can use 100 instead of 200_000.

## Dependencies

- Signal K Server ≥ 2.0 (`@signalk/server-api` ^2)
- Node ≥ 22.5.0 (`webcrypto` + native ESM-via-require unwrap in signalk-server)
- Pure-JS deps only at runtime: `@peculiar/x509`, `@sinclair/typebox`, `qrcode`. No native modules.

When bumping the Node engines floor, update **all** of: `package.json` engines, `package.json` `@types/node` devDep, `.github/dependabot.yml` comment, and the README prerequisites line.
