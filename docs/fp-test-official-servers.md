# False-positive test: official MCP reference servers

Date: 2026-09-05. Reproducible: clone `modelcontextprotocol/servers` and run
`acidtest scan` (v1.1.0) on each server under `src/`.

These seven are the official reference MCP servers — the most known-good
corpus that exists. Every FAIL/DANGER here is, by definition, a false
positive.

## Result

| Server | Status | Score | Notes |
|---|---|---|---|
| everything | DANGER | 0/100 | 7× path-traversal (all false) |
| fetch | WARN | 69/100 | |
| filesystem | FAIL | 45/100 | fs-unlink (it's a file server; deleting files is its job) |
| git | WARN | 69/100 | |
| memory | FAIL | 23/100 | dynamic-require, fs-unlink |
| sequentialthinking | WARN | 54/100 | |
| time | PASS | 92/100 | the only clean pass |

**Hard false positives (FAIL/DANGER): 3 of 7 (43%).**
**Clean PASS: 1 of 7.**

## What drives the noise (HIGH/CRITICAL findings across all seven)

| Count | Finding |
|---|---|
| 8 | path-traversal (matched `../` in imports and resource paths) |
| 2 | fs-unlink (file deletion — expected for a filesystem/memory server) |
| 2 | dynamic-require |
| 2 | Dynamic require() detected |

## Reading

The precision problem the reimagining memo cited from the wider industry is
present in our own tool, and it is coarse: the scanner flags legitimate,
expected behavior for what the tool is (a filesystem server deleting files,
`../` in an import path). It is currently too noisy to be trusted against
real servers.

This is the strongest single argument for the memo's "precision is the
wedge" thesis — and also a caveat: as shipped, the tool would cry wolf on
the official Anthropic servers, so precision is not just a growth
opportunity, it is a correctness problem to fix before the tool is
recommendable at all.
