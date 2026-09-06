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

Done: `v1.1.0` is already tagged and pushed (on merge commit `762cbd7`).
Because the release workflow was added *after* that tag, publishing
requires re-pushing the tag — see step 2's "Trigger the release".

## 2. npm publish (with provenance, via CI Trusted Publishing)

We publish from GitHub Actions using **npm Trusted Publishing (OIDC)** —
no token is stored anywhere, and provenance is generated automatically.
The workflow is `.github/workflows/release.yml` (already on `main`); it
runs on any `v*` tag push.

Local `npm publish --provenance` does NOT work from a laptop —
provenance needs a CI/OIDC provider, which is why we use the workflow.

### One-time: configure the trusted publisher (owner, on npmjs.com)

1. Log in to npmjs.com as the `acidtest` package owner.
2. Go to the **acidtest** package → **Settings** → **Publishing access**
   (a.k.a. Trusted Publishers).
3. Add a **GitHub Actions** trusted publisher:
   - Organization / user: `chuckyatsuk`
   - Repository: `acidtest`
   - Workflow filename: `release.yml` (exactly, case-sensitive)
   - Environment: leave blank (the workflow uses none)
4. Save.

### Trigger the release

The `v1.1.0` tag was pushed before the workflow existed, so re-point it to
a commit that includes the workflow and re-push — that fires the release
job:

```bash
git fetch origin
git checkout main && git pull            # main includes release.yml
git tag -d v1.1.0                        # remove the old local tag
git push origin :refs/tags/v1.1.0        # remove the old remote tag
git tag -a v1.1.0 -m "AcidTest v1.1.0 — 2026 threat-model update"
git push origin v1.1.0                   # this push triggers release.yml
```

Watch it:

```bash
gh run watch --exit-status $(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

Verify:

```bash
npm view acidtest version    # should print 1.1.0
```

> For future releases (v1.1.1+) the flow is just: bump version, commit,
> `git tag vX.Y.Z && git push origin vX.Y.Z`. No local publish, no token.

## 3. GitHub repo metadata (owner-executed)

Set the description and topics (from the brief). Requires `gh` authed as a
repo admin (your `chuckyatsuk` login is):

```bash
gh repo edit chuckyatsuk/acidtest \
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
