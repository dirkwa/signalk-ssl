# Contributing

Bug reports, feature requests and pull requests are welcome.

Before opening a PR, please run the checks the CI runs:

```bash
npm run format
npm run build:all
npm run test
```

`npm run lint` and `npm run typecheck` are worth running separately too — the
plugin sources are linted with typescript-eslint `strictTypeChecked`.

**One logical change per PR.** Refactors, behaviour changes, doc updates and
dependency bumps belong in separate PRs; a version bump is its own PR again.
Commits follow [Angular conventional commit](https://www.conventionalcommits.org/)
format (`fix(service): tolerate libuv EOPNOTSUPP`), and branch names use hyphens
rather than slashes.

Crypto changes deserve particular care: the convenience-mode passphrase
derivation is load-bearing, and changing it makes every existing install unable
to decrypt its own CA key. See AGENTS.md before touching it.

## Licensing of contributions

By submitting a pull request or patch, you grant Dirk Wahrheit a perpetual,
worldwide, non-exclusive, royalty-free, irrevocable license to use, reproduce,
modify, publish, sublicense and distribute your contribution, and to relicense
it under any terms, including as part of signalk-ssl releases. You confirm that
you have the right to grant this.

This keeps future licensing decisions for the project in one pair of hands. It
does not affect what you may do with your own contribution elsewhere — you keep
your copyright in it.
