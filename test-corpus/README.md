# AcidTest Test Corpus

A small, hand-built corpus used to regression-test detection. It is **not
shipped in the npm package** (`files` in package.json is `dist` only) —
these directories contain intentionally malicious patterns that would be
flagged if they landed in a consumer's `node_modules`.

Run it with:

```bash
npm run test:corpus
```

## Layout

```
test-corpus/
  vulnerable/
    skills/       whole skill/MCP-server directories (markdown + manifest threats)
    typescript/   standalone vulnerable .ts files (code-layer threats)
    python/       standalone vulnerable .py files
  legitimate/
    skills/       clean skill/MCP-server directories (false-positive guards)
    typescript/   clean .ts files
    python/       clean .py files
```

- **vulnerable** examples must scan as `FAIL` or `DANGER`.
- **legitimate** examples must scan as `PASS` or `WARN`.

Legitimate standalone code files are scanned as code-only (no synthetic
manifest is wrapped around them), because that is how a bare downloaded
file is actually encountered — wrapping them in an empty-permission
SKILL.md would manufacture a cross-reference mismatch that the scanner
does not produce on the file itself.

## What the numbers mean

`npm run test:corpus` reports detection percentages against *this* corpus.
100% means "every attack we wrote a fixture for is caught, and every clean
example we wrote passes." It is a regression guard, not a claim about
detection in the wild — a novel technique with no matching pattern will
pass. The number to watch is whether it ever drops below 100% (a
regression), not the percentage itself. See [METHODOLOGY.md](../METHODOLOGY.md).

## Adding coverage

When you add a detection pattern, add at least one vulnerable example that
exercises it and (where a legitimate construct could trip it) one clean
example that must not be flagged.
