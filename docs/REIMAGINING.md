# Reimagining AcidTest: direction, salvage audit, and a v2 spec

Status: exploratory. This is a decision document, not a plan of record. It
draws on two research passes (a market/pain scan and a code salvage audit,
Sept 2026) plus direct verification against the current codebase. Nothing
here has been built; the v2 spec is a proposal.

---

## 1. The short version

The tool is real and works. The *framing* was tied to a dead news cycle
(the Feb 2026 OpenClaw/ClawHub incident), and the *category* it competes in
— "another MCP/skill scanner" — is now crowded and partly owned by funded
players (Snyk/Invariant, Cisco, Anthropic's own in-terminal scanner).

There is still a durable, free-OSS niche, but it is narrow and specific:

> **A low-false-positive, MCP-native pre-publish gate that server and skill
> authors run before they list — shipped as an MCP server (so agents can
> self-scan on install) plus a SARIF-emitting GitHub Action.**

The defensible edge is **precision** (the documented industry problem is
~78% false positives on pattern-based scanners) and **author-side
positioning** (the one segment incumbents and registries have left
unowned), not coverage or runtime enforcement — those lanes are lost.

If AcidTest can out-precision the pattern-matchers and get referenced by a
registry as "run this first," there's a real niche. If it can't do both,
the honest answer is that it's a solid portfolio piece but not a
depended-on tool — and that's still a legitimate outcome.

---

## 2. Where the pain actually is (market scan)

The threat model is now mainstream and documented, not incident-specific:

- MCP adoption is large (tens of millions of monthly SDK downloads,
  thousands of servers), and security is consistently cited as the top
  adoption blocker in builder surveys.
- Real, exploited incidents exist: a trojanized MCP server submitted to a
  legitimate registry (Feb 2026), a shell-injection flaw in official MCP
  SDKs (April 2026), and at least one actively-exploited MCP CVE.
- Agent skills are a parallel, arguably hotter front: tens of thousands of
  skills listed within months, with independent audits finding prompt
  injection in a large fraction of them.

Two findings matter most for direction:

1. **The attacks are real but not novel.** They are supply-chain
   poisoning, config injection, and confused-deputy applied to MCP. The
   hard, under-solved problem is **semantic false positives**, not
   detecting the patterns. Legitimate MCP tool docs routinely say things
   like "you must call this first," which naive injection rules flag.

2. **The under-served segment is authors, pre-publish.** Registries are
   pushing security onto authors (scan-on-publish), and at least one major
   directory explicitly does *not* security-audit submissions. Nobody free
   clearly owns "the thing you run before you list your server."

The consuming-org and enterprise ends are contested by commercial gateways
and vaults. A free OSS tool competes uphill there. The author/pre-publish
end is where OSS + MCP-native distribution has a natural advantage.

### Competitive reality (sobering)

The generic-scanner category is crowded: Snyk (via the Invariant/mcp-scan
acquisition, free tier + commercial), Cisco's OSS mcp-scanner and skill
scanner, Anthropic's own free in-terminal security scanner, plus a long
tail of OSS scanners and GitHub Actions. Rebuilding "a scanner that flags
tool poisoning / injection / rug-pulls" is moot — that exists, free, from
better-funded teams.

What none of them has cleanly solved, and what is widely complained about:
**precision.** That is the only wedge worth chasing.

---

## 3. Salvage audit: what survives an MCP-first rebuild

The codebase is ~8,800 LOC TS + ~2,100 LOC pattern JSON, 176 tests. It is
built around a 5-layer pipeline that scans a local skill/MCP *directory*.

### The single strongest asset

**The MCP-specific detection content and the thin plumbing that runs it:**
`patterns/mcp-tool-poisoning.json` (tp-*), `mcp-shadowing.json` (cs-*),
`mcp-exfil.json` (me-*), driven by `layers/injection.ts` and fed by
`loaders/mcp-loader.ts`. This is the only part that encodes MCP-domain
knowledge a generic SAST tool can't: hidden `<IMPORTANT>` tags in tool
descriptions, covert `sidenote`-style parameters, "use this instead of the
official server" shadowing, and exfil through MCP-native channels
(`ReadResourceRequestSchema`, `createMessage` sampling). It's small
(~210 LOC JSON + a 156-LOC layer), cheap, and well-tested.

Runner-up: **`diff.ts`** (rug-pull detection) — a clean capability-class
diff that maps directly onto the real threat of auto-updating servers
turning malicious.

### Keep / cut / rebuild

| Component | Verdict | Why |
|---|---|---|
| MCP patterns (tp-/cs-/me-) + `injection.ts` | **KEEP** | The differentiator. Regex-over-text, which is a feature — cheap and durable. |
| `mcp-loader.ts` | **KEEP + EXTEND** | Most MCP-native module. Gap: static files only; needs a *live* introspection path. |
| `diff.ts` (rug-pull) | **KEEP** | Distinctive, on-point for MCP supply chain. |
| `scoring.ts`, `reporter.ts` | **KEEP (recalibrate)** | Sound; thresholds need MCP tuning; JSON output is the real product surface. |
| `demo-pack.ts` | **KEEP** | 3 of 4 cases are MCP/agent attacks; good demo + test harness. |
| pattern loader + schema + validator | **KEEP** | Good hygiene (schema-validated patterns, build gate). |
| `config.ts` | **KEEP** | ignore/thresholds/failOn are CI-useful. |
| `scanner.ts` orchestrator | **REBUILD** | Sound shape, but hardwired to the "skill" abstraction; an MCP server should be the primary object, not a degenerate skill. |
| `mcp-server.ts` (serve mode) | **REBUILD** | Real but shallow — a thin wrapper that scans local *paths* only. An agent can't hand it a server URL or a tool list. |
| `layers/code.ts` | **KEEP (trim)** | Best-tested workhorse; carries Python AST logic peripheral to MCP. |
| dataflow/taint engine (`analysis/*`, `layers/dataflow.ts`, ~1,090 LOC) | **CUT (defer)** | Best-engineered subsystem, but wrong investment: TS/JS-only, single-file, intraprocedural, "confidence" is just path length. The MCP exfil it would catch is already caught by cheaper `me-*` regexes. ~12% of the code for non-differentiating capability. |
| `layers/permissions.ts` | **CUT/REBUILD** | Built for the AgentSkills permission model; literally self-disables for MCP. |
| `layers/crossref.ts` | **CUT** | Nearly every check is `!isMCP`-guarded off. |
| Python parser + tree-sitter native deps | **CUT** | Adds native build friction for marginal MCP value. |
| watch mode | **CUT** | Skill-dev-loop feature, little MCP-first value. |
| **6 dead pattern files** (sql-injection, xss-injection, prototype-pollution, insecure-crypto, regex-dos, python-deserialization) | **CUT NOW** | **Verified: loaded by nothing** (`loadPatterns` has zero non-test references for all six). ~570 LOC of web-app-scanner residue. See §5. |

### The honest structural gap

The whole tool **cannot inspect a running or remote MCP server.**
Everything routes through reading files off local disk. The tool-poisoning
patterns — the crown jewel — can only see a poisoned tool description if it
happens to sit in a local `mcp.json`. The single highest-leverage rebuild
is **live MCP introspection**: connect to a server, call `listTools`, and
run the patterns against the descriptions the server *actually advertises
at runtime*. That is what turns this from "a skill scanner with MCP regexes
bolted on" into a genuine MCP-first tool.

---

## 4. Proposed v2: "AcidTest for MCP"

A focused tool, smaller than today, built around the durable core.

### Primary object: a live MCP server

v2's main input is not a directory — it's a server reference (a stdio
command, an HTTP/SSE URL, or a client config entry). The flow:

1. **Connect** to the server as an MCP client.
2. **Introspect**: `listTools`, `listResources`, `listPrompts`.
3. **Scan the advertised surface** with the tp-/cs-/me- patterns: tool and
   parameter descriptions, resource templates, prompt templates.
4. **Optionally scan source** (when a local path/repo is given) with the
   trimmed code layer + `me-*` code patterns.
5. **Score + report** JSON-first, with a precision-tuned rubric.

### The three surfaces (this is the distribution story)

- **CLI** — `acidtest scan <url|path|config>` for humans and CI.
- **MCP server mode (rebuilt)** — exposes a `scan_mcp_server` tool that
  takes a server reference, so an agent can scan a server *before adding
  it*. This is the viral, MCP-native loop.
- **GitHub Action** — emits **SARIF** into GitHub code scanning, so an
  author gets a pre-publish gate in CI. Table stakes, but proven.

### The wedge: precision

This is the whole bet, so it gets first-class engineering:

- A curated **allowlist of legitimate tool-description phrasings** ("call
  this first," "you must provide," etc.) so the injection rules stop
  flagging honest docs.
- **Context-aware severity**: a directive inside a tool description an
  agent will read is high-signal; the same string in a README is not.
- **Test-fixture awareness**: mock keys in `test/`/`fixtures/` don't trip
  secret rules.
- A **false-positive corpus**: a set of known-good, popular MCP servers
  that must scan clean, run in CI alongside the malicious corpus. The
  headline metric becomes "0 false positives on N real servers," which is
  the number this market actually cares about.

### MVP scope (what to build first)

1. Live MCP introspection path in `mcp-loader.ts` (connect → listTools).
2. Rebuilt `mcp-server.ts` tool that accepts a server reference.
3. The precision layer (allowlist + FP corpus) around the existing tp-/cs-/
   me- patterns.
4. SARIF output in `reporter.ts` + a published GitHub Action.
5. Keep `diff.ts` (rug-pull) as a distinctive second command.

### Explicitly out of scope for v2

Runtime enforcement / gateways (lost to commercial players), the dataflow
engine (defer), Python skill scanning, the permissions/crossref layers,
watch mode.

---

## 5. Things to decide (owner)

These are judgment calls, several adjacent to the "escalate, don't decide"
list, so they are flagged rather than acted on:

1. **Cut the 6 dead pattern files?** Verified dead (loaded by nothing).
   Cutting them is safe *and* makes the pattern count honest — but it drops
   the headline from 134 to ~90 executed patterns, which touches the
   public "134 patterns" claim. Recommended: cut them and restate the
   count to what actually runs. **This is a real honesty fix regardless of
   the reimagining.**
2. **How far to teardown?** The audit supports a deep teardown (drop
   dataflow, permissions, crossref, Python). That is a big, mostly-additive
   change of direction, not a bugfix. Confirm appetite before anyone
   rewrites `scanner.ts`.
3. **Is v2 a new major (2.0.0) or a new tool?** If scan targets change from
   "directory" to "server reference," CLI behavior changes — that's a
   breaking change and a 2.0.0, per the release rules.
4. **`sp-004 openclaw-credentials`**: keep (real credential path) or cut
   (dead-ecosystem specific)? Low stakes; recommend keep.
5. **Distribution bet**: is the "get referenced by a registry as the
   pre-publish check" path worth pursuing actively (outreach), or just
   build the Action + MCP mode and let it be found?

---

## 6. Honest bottom line

Not moot. The market is durable (structural, not incident-driven), and the
codebase has a genuine differentiated core (MCP patterns + rug-pull diff)
worth ~a few hundred lines. But the winning move is **subtraction and
precision**, not more features: cut half the code, add live introspection,
obsess over false positives, and ship it where authors and agents already
are. If that gets even mild traction, invest more. If not, it remains a
clean, honest demonstration of real security engineering — which for a
hiring-visibility asset is already a win.
