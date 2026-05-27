@AGENTS.md

# Claude Code session notes

The full project guidance is in [AGENTS.md](AGENTS.md) above (loaded via
the `@` import). This file adds Claude Code workflow notes that don't
belong in language-agnostic AGENTS.md.

## Build cycle on every change

```
npm run format
npm run build:all
npm run test
```

In that order. The test suite is fast (~3s for ~50 tests) — there's no
reason to skip it. `lint` and `typecheck` are independently worth
running before opening a PR.

## Verifying a change against a real signalk-server

Tests cover the crypto and route logic, but the plugin only really
"works" when signalk-server reloads it, reads `app.config.configPath`,
and serves HTTPS with the issued cert. The cheapest way to verify
end-to-end:

1. `npm run build:all` in this repo.
2. Copy `dist`, `public`, `package.json`, `README.md` into the
   running server's `~/.signalk/node_modules/signalk-ssl/`.
3. Restart signalk-server. The admin UI's "Restart" button does a
   clean `process.exit(0)`; an `Restart=always` systemd policy
   (or `docker restart`) recovers from that.
4. Tail the server's log and look for "signalk-ssl initial issueIfNeeded"
   (debug-level) or a `cert installed` line.

If signalk-server fails to start with `must be accessible only by the
user that is running the server, refusing to start`, the cert mode got
widened past `0o600`. This plugin is the only writer of those files
under normal operation — see the `0600 enforcement` section of
AGENTS.md.

## Plugin runs in two environments — keep code portable

The plugin runs identically inside the SignalK Docker image (Node
container, `~/.signalk` bind-mounted) and on bare-metal installs
(signalk-server as a systemd user service, or as a foreground process).
Don't introduce code that assumes one:

- No `process.env.SIGNALK_CONTAINER` branches.
- No `/var/run/docker.sock` access.
- All paths come from `app.config.configPath` and
  `app.getDataDirPath()`, never hard-coded.
- No host-OS-specific commands (no `systemctl`, no `launchctl`).

## Tarball smoke-test before tagging a release

The SignalK Appstore installs plugins with `npm install
--ignore-scripts`. A release that builds locally can still ship broken
if `dist/` or `public/` got `.gitignore`d, or if `package.json` `files`
doesn't list them. Verify before tagging:

```
npm pack
tar tzf signalk-ssl-*.tgz | grep -E '(dist/plugin/index\.js|public/index\.html)'
```

Both paths must appear. Then drop the tarball into a fresh
signalk-server and enable the plugin — that's the only test that
matches what users get from the Appstore.

## Standing rule for this file

CLAUDE.md re-exports AGENTS.md (`@AGENTS.md` at the top) and adds
session-ergonomic notes only. Don't duplicate AGENTS.md content here.
If a fact applies to any AI coding agent (Cursor, Codex, OpenAI Codex,
etc.), it goes in AGENTS.md. If it only matters during a Claude Code
session — slash-command invocation, the build-cycle order convention,
the verify-locally recipe — it goes here.
