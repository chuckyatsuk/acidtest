# Release checklist — v1.1.0 (owner-executed)

Everything below is prepared but **not run**. The worker never executes
`npm publish`, never changes GitHub settings, and never touches DNS. Run
these yourself, in order.

The branch `revival-2026` must be merged to `main` first (owner review of
the README diff + PR). All commands assume you are in `~/Dev/acidtest` on
the merged `main` at the release commit.

## 0. Pre-flight (should all already be true)

```bash
npm ci
npm test                    # 176 passing
npm run validate:patterns   # 134 patterns, PASSED
npm run test:corpus         # 12/12 vulnerable, 6/6 legitimate
npm run build               # dist/ builds
npm audit                   # 0 vulnerabilities
npm pack --dry-run          # 123 files, dist only — no .github/fixtures/corpus
```

## 1. Git tag

The repo tags releases as `vX.Y.Z`:

```bash
git tag -a v1.1.0 -m "AcidTest v1.1.0 — 2026 threat-model update"
git push origin v1.1.0
```

## 2. npm publish (with provenance)

You are not currently logged in on this machine (`npm whoami` → 401), so:

```bash
npm login          # authenticate as the acidtest package owner
npm whoami         # confirm it shows your npm user
```

Then publish. `prepublishOnly` is not configured, so build explicitly first:

```bash
npm run build
npm publish --provenance --access public
```

Notes on `--provenance`:
- Provenance works out of the box when publishing from a CI runner with
  OIDC (e.g. GitHub Actions). Publishing **locally** with `--provenance`
  requires a recent npm and may prompt for 2FA/OTP — have your authenticator
  ready. If a local `--provenance` publish is rejected for lack of a
  supported CI environment, either publish from a GitHub Actions release
  workflow, or drop `--provenance` for this release and add the CI publish
  workflow next.
- `--access public` is explicit-safe; the package is unscoped so it is
  public regardless, but this makes intent clear.

Verify:

```bash
npm view acidtest version    # should print 1.1.0
```

## 3. GitHub repo metadata (owner-executed)

Set the description and topics (from the brief). Requires `gh` authed as a
repo admin (your `currentlycurrently` login is):

```bash
gh repo edit currentlycurrently/acidtest \
  --description "Security scanner for AI agent skills and MCP servers — static analysis, taint tracking, prompt-injection detection" \
  --add-topic security \
  --add-topic static-analysis \
  --add-topic mcp \
  --add-topic ai-agents \
  --add-topic supply-chain-security \
  --add-topic prompt-injection \
  --add-topic typescript
```

## 4. GitHub Release (optional but recommended)

```bash
gh release create v1.1.0 \
  --title "v1.1.0 — 2026 threat-model update" \
  --notes-file <(sed -n '/## \[1.1.0\]/,/## \[1.0.0\]/p' CHANGELOG.md | sed '$d')
```

## Not done by the worker (by design)

- `npm publish` — prepared above, you run it.
- GitHub repo settings / topics — `gh` command prepared above, you run it.
- DNS / domain — `acidtest.currently.website` already resolves; no DNS
  change needed for this release.
