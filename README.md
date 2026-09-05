# AcidTest

Security scanner for MCP servers and AI agent skills. Scan third-party code before your agent runs it.

<p align="center">
  <a href="https://www.npmjs.com/package/acidtest">
    <img src="https://img.shields.io/npm/v/acidtest" alt="npm version">
  </a>
  <a href="https://github.com/currentlycurrently/acidtest/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/currentlycurrently/acidtest/test.yml?branch=main" alt="build status">
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="license">
  </a>
</p>

## Scan before you install

```bash
npx acidtest scan ./mcp-server
npx acidtest scan ./downloaded-skill
```

No install required. No API keys. No configuration.

## Example: Detecting malicious code

```
AcidTest v2.0.0

Scanning: system-helper
Source:   test-fixtures/fixture-danger

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TRUST SCORE: 0/100 ░░░░░░░░░░ DANGER

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FINDINGS

  ✖ CRITICAL instruction-override
    SKILL.md:4
    Attempts to override agent instructions

  ✖ CRITICAL eval-usage
    handler.ts:12
    Uses eval() function

  ✖ HIGH     maintenance-mode
    SKILL.md:4
    Claims the system is in maintenance mode

  ... 13 more findings (9 CRITICAL, 3 HIGH, 2 MEDIUM, 1 LOW, 1 INFO total)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECOMMENDATION: Do not install. Prompt injection attempt detected.
```

Abridged output from `acidtest scan test-fixtures/fixture-danger` — one of the fixtures bundled in this repo, so you can reproduce it after cloning.

## What it catches

- **Command & Code Injection** - `eval()`, `exec()`, shell injection, unsafe deserialization
- **Data Exfiltration** - Tracks data flow from env vars/secrets to network calls
- **Credential Theft** - Hardcoded API keys, SSH key injection, token leaks, MCP-channel env exfil
- **C2 Callbacks** - Suspicious network requests to raw IPs or sketchy domains
- **Obfuscation** - Base64/hex payloads, entropy analysis, invisible-Unicode/Trojan-Source hiding
- **Prompt Injection** - Instruction override in SKILL.md body and frontmatter, plus 2026 phrasings (fake system-reminder blocks, embedded tool-call JSON)
- **MCP Tool Poisoning** - Instructions smuggled into tool/parameter descriptions; cross-server shadowing
- **Rug-Pull Updates** - `acidtest diff` flags a new version that adds capability the old one lacked
- **Permission Escalation** - Undeclared filesystem/network/shell access

**84 security patterns** across 12 category files, plus TypeScript/JavaScript AST and version-diff analysis. Scans MCP manifests, SKILL.md, and Python/TypeScript/JavaScript source. Run `npm run validate:patterns` to regenerate the count.

## Install

```bash
npm install -g acidtest
```

Or run without installing:

```bash
npx acidtest scan ./path-to-skill
```

## For MCP server authors: lint before you publish

If you write an MCP server, run `acidtest lint` on it before you publish.
It checks your own tool and parameter descriptions for the things a
consumer's security scanner will flag — injected-looking instructions,
`<IMPORTANT>`-style tags, "do not tell the user" directives, covert
parameter names, and "use this instead of the official server" phrasing —
and points at the exact line so you can fix it or confirm it's intentional.

```bash
# Lint a manifest, a source file, or a whole server directory
acidtest lint ./my-server
acidtest lint ./src/tools/weather.ts
```

It reads descriptions both from a static `mcp.json` and from
`description:` string literals in your TypeScript/JavaScript/Python source,
because that's where real servers declare them. Output is eslint-shaped and
it exits non-zero on error-level findings, so it drops into a pre-commit
hook or CI.

The point is precision: it stays quiet on legitimate wording. Run against
the seven official `modelcontextprotocol/servers` reference servers, it
reports zero findings — while still catching a poisoned description. It
does not cry wolf on "you must provide a valid input."

## Usage

```bash
# Lint your own MCP server before publishing
acidtest lint ./my-server

# Walk the Q4-2026 attack classes with the real scanner
# (fixtures are generated on the fly, nothing is left on disk)
acidtest demo

# Scan a skill or MCP server
acidtest scan ./my-skill
acidtest scan ./my-mcp-server

# Scan all skills in a directory
acidtest scan-all ./skills

# Check an update for a rug-pull (new version adds capability the old lacked)
acidtest diff ./skill-v1 ./skill-v2

# Show remediation suggestions
acidtest scan ./my-skill --fix

# JSON output
acidtest scan ./my-skill --json
```

## How it works

AcidTest runs two analysis layers:

1. **Injection scan** - checks tool and parameter descriptions, MCP manifests,
   and markdown for instruction-override attempts, tool poisoning, covert
   parameters, cross-server shadowing, and invisible-Unicode payloads
2. **Code analysis** - regex patterns (dangerous imports, exfil sinks,
   credentials, Python sinks) plus TypeScript/JavaScript AST checks for
   `eval`, dynamic `require`, the Function constructor, and bracket-notation
   bypasses

A single CRITICAL finding — an env exfil, a poisoned tool description —
floors the result to at least FAIL, so a real attack is never reported as
a mere warning.

See [METHODOLOGY.md](./METHODOLOGY.md) for the details and limits.

## Tested on real code

AcidTest has been run against 2,386 public agent skills from a large open skills repository. On that corpus it flagged live malicious payloads, including:

- C2 callbacks to raw IPs (`91.92.242.30`)
- SSH key injection into `~/.ssh/authorized_keys`
- Namespace squatting attacks
- Base64-encoded remote code execution

These are the same classes of attack that now show up in MCP servers and agent skills across the ecosystem.

## Daily use

Every command below exits non-zero on `FAIL` or `DANGER`, so hooks and scripts can gate on the result.

### Scan installed plugins and skills

```bash
acidtest scan-all ~/.claude/plugins
acidtest scan-all ~/.claude/skills
```

This exits 1 if any skill is `FAIL` or `DANGER`, so it works in a cron job or shell alias.

### Claude Code hook: scan on install

Block a skill or plugin before it runs. A Claude Code `PreToolUse` hook receives the tool call as JSON on stdin and blocks the action by exiting with code 2. This hook watches `Bash` calls that look like an install, scans the target directory, and refuses if the score is bad.

Install the ready-made hook:

```bash
mkdir -p ~/.claude/hooks
curl -o ~/.claude/hooks/acidtest-preinstall.sh \
  https://raw.githubusercontent.com/currentlycurrently/acidtest/main/hooks/claude-code-preinstall.sh
chmod +x ~/.claude/hooks/acidtest-preinstall.sh
```

Or write it yourself — this is the whole thing:

```bash
#!/usr/bin/env bash
# Blocks a Claude Code install action when AcidTest flags the target.
set -euo pipefail

# PreToolUse passes the tool call as JSON on stdin.
payload="$(cat)"
cmd="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty')"

# Only act on install-shaped commands; let everything else through (exit 0).
case "$cmd" in
  *"acidtest"*) exit 0 ;;                       # don't scan our own scans
  *install*|*"plugin add"*|*clone*) ;;          # scan these
  *) exit 0 ;;
esac

# Scan the project directory the session is running in.
target="${CLAUDE_PROJECT_DIR:-.}"
if ! acidtest scan "$target" --json > /tmp/acidtest-preinstall.json 2>/dev/null; then
  status="$(jq -r '.status' /tmp/acidtest-preinstall.json)"
  {
    echo "🛑 AcidTest blocked this action: $target is $status"
    jq -r '.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH")
           | "  [\(.severity)] \(.title): \(.detail)"' /tmp/acidtest-preinstall.json
  } >&2
  exit 2   # exit 2 is what tells Claude Code to block the tool call
fi
exit 0
```

Wire it into `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/acidtest-preinstall.sh" }
        ]
      }
    ]
  }
}
```

Two things make this work: reading the tool call from stdin, and `exit 2` to block (any other exit lets the action proceed). Adjust the `case` matcher to match your install flow. `acidtest` and `jq` must be on `PATH`.

For a postinstall check instead of a live hook, run the scan as a plain script. `acidtest scan <dir>` exits non-zero on `FAIL` or `DANGER`, so `acidtest scan ./new-skill || echo blocked` is enough.

### Check an update before upgrading

```bash
# Diff two versions; exits 1 on a RUG_PULL verdict
acidtest diff ./skill-v1 ./skill-v2
```

## CI/CD

### GitHub Actions

Add to `.github/workflows/acidtest.yml`:

```yaml
name: Security Scan

on: [pull_request, push]

jobs:
  acidtest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx acidtest@latest scan . --json > results.json
      - run: |
          STATUS=$(jq -r '.status' results.json)
          if [ "$STATUS" = "FAIL" ] || [ "$STATUS" = "DANGER" ]; then
            echo "❌ Security scan failed"
            exit 1
          fi
```

See [`.github/workflows/acidtest-pr-comment.yml`](.github/workflows/acidtest-pr-comment.yml) for a full example with PR comments.

### Pre-commit Hook

```bash
curl -o .git/hooks/pre-commit https://raw.githubusercontent.com/currentlycurrently/acidtest/main/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Every commit now runs a scan first.

### Security Badge

```markdown
[![Security: AcidTest](https://img.shields.io/badge/security-AcidTest-brightgreen)](https://github.com/currentlycurrently/acidtest)
```

Displays: [![Security: AcidTest](https://img.shields.io/badge/security-AcidTest-brightgreen)](https://github.com/currentlycurrently/acidtest)

## Run as an MCP server

AcidTest can run as an MCP server so an agent like Claude can scan skills before installing them.

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "acidtest": {
      "command": "npx",
      "args": ["-y", "acidtest", "serve"]
    }
  }
}
```

Then Claude can scan skills:

```
User: "Can you scan this skill before I install it?"
Claude: [Uses acidtest scan_skill tool to analyze]
```

## Configuration

Create `.acidtest.json` in your skill directory:

```json
{
  "ignore": {
    "patterns": ["di-008"],
    "categories": ["obfuscation"],
    "files": ["vendor/**", "*.min.js"]
  },
  "thresholds": {
    "minScore": 80,
    "failOn": ["CRITICAL", "HIGH"]
  },
  "output": {
    "format": "detailed",
    "showRemediation": true
  }
}
```

CLI flags override config file settings.

## Scoring

Starts at 100, deducts by severity:
- **CRITICAL**: -25 points
- **HIGH**: -15 points
- **MEDIUM**: -8 points
- **LOW**: -3 points

**Ratings:**
- **80-100**: PASS (green)
- **50-79**: WARN (yellow)
- **20-49**: FAIL (orange)
- **0-19**: DANGER (red)

## What it doesn't catch

- Zero-day exploits in the Node.js or Python runtime
- Vulnerabilities in npm/pip dependencies (use `npm audit` / `pip-audit`)
- Runtime behavior that static analysis can't see
- Advanced obfuscation or VM-level evasion

[METHODOLOGY.md](./METHODOLOGY.md) covers the limits in detail.

## Use it alongside other tools

AcidTest is static analysis. It pairs with:

- **npm audit / pip-audit** - dependency vulnerabilities
- **VirusTotal** - known malware signatures
- **Sandboxing** - runtime isolation (Docker, VMs, Firecracker)

No single tool catches everything.

## Contributing

Detection patterns are JSON files in `src/patterns/`. To add a new pattern:

1. Add pattern to the appropriate category file
2. Test with `npm test`
3. Submit a PR

See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## Documentation

- [Methodology](./METHODOLOGY.md) - Technical details and limitations
- [Changelog](./CHANGELOG.md) - Version history
- [Contributing](./CONTRIBUTING.md) - How to add patterns
- [Security Policy](./SECURITY.md) - Responsible disclosure
- [Template Repository](./template-repo/) - Starter kit

## Links

- **Website**: https://acidtest.currently.website
- **NPM**: https://www.npmjs.com/package/acidtest
- **GitHub**: https://github.com/currentlycurrently/acidtest
- **Issues**: https://github.com/currentlycurrently/acidtest/issues

## License

MIT
