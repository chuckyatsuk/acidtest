# Maintaining AcidTest

This is a low-effort maintenance plan. The goal is to keep a security tool
credibly alive and correct without it becoming a job. Most of the work is
automated; your part is review.

## What runs on its own

- **CI** (`.github/workflows/test.yml`) — tests + pattern validation on every
  push and PR, Node 20/22/24.
- **Release** (`.github/workflows/release.yml`) — publishes to npm with
  provenance when you push a `vX.Y.Z` tag. No manual publish.
- **Dependabot** (`.github/dependabot.yml`) — weekly grouped dependency PRs.
- **Health check** (`.github/workflows/health-check.yml`) — Mondays; opens an
  issue only if the suite breaks or a production advisory appears. Silence
  means healthy.

## Weekly (~15-30 min, only when there's something to do)

1. **Merge green Dependabot PRs.** CI runs on them; if it's green and the
   bump isn't a major, merge. Batch them.
2. **Check for a `health-check` issue.** If one exists, run `npm audit` and
   `npm audit fix` (or bump the dep), verify green, close the issue.
3. **Glance at any new issues/PRs** from users. Reply or triage; you don't
   owe anyone a fix on a free tool, but a one-line acknowledgement keeps it
   from looking abandoned.

## Monthly (~30 min)

- **New attack classes.** Skim what's new in MCP/agent security (a couple of
  searches). If a genuinely new class of tool-description or manifest attack
  has emerged, that's a candidate for a new pattern. Only add one if you can
  write a **testable fixture** for it — same rule as always: no pattern
  without a fixture and a test.
- **Precision check.** Re-run the false-positive test against the official
  reference servers (see `docs/fp-test-official-servers.md`). If a new pattern
  started flagging them, tighten it. Staying quiet on legitimate code is the
  whole value.

## Cutting a release

```bash
# bump version in package.json + the three VERSION constants
# (src/index.ts, src/scanner.ts, src/mcp-server.ts)
npm test && npm run validate:patterns && npm run build
# add a CHANGELOG entry
git commit -am "release: X.Y.Z — <summary>"
git tag -aX.Y.Z -m "AcidTest X.Y.Z"
git push && git push origin vX.Y.Z   # release.yml publishes automatically
```

## The one rule that matters

Every claim in the README/METHODOLOGY must be regenerable by running
something in this repo. Pattern counts come from `npm run validate:patterns`;
corpus numbers from `npm run test:corpus`. If you can't regenerate a number,
don't write it.
