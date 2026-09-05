# AcidTest

Security scanner for AI agent skills and MCP servers.

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
npx acidtest scan ./downloaded-skill
```

No install required. No API keys. No configuration.

## Example: Detecting malicious code

```
AcidTest v1.0.1

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

  ✖ CRITICAL Undeclared shell execution
    Code executes shell commands but skill does not declare
    shell permissions

  ✖ HIGH     env-var-secret
    SKILL.md
    Requests credential environment variable: AWS_SECRET

  ... 16 more findings (10 CRITICAL, 6 HIGH, 2 MEDIUM, 1 LOW, 1 INFO total)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECOMMENDATION: Do not install. Undeclared data exfiltration detected.
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

**134 security patterns** across 19 category files, plus AST, dataflow, and version-diff analysis. Supports Python and TypeScript/JavaScript. Run `npm run validate:patterns` to regenerate the count.

## Install

```bash
npm install -g acidtest
```

Or run without installing:

```bash
npx acidtest scan ./path-to-skill
```

## Usage

```bash
# See demo with example malicious skills
acidtest demo

# Scan a skill or MCP server
acidtest scan ./my-skill
acidtest scan ./my-mcp-server

# Scan all skills in a directory
acidtest scan-all ./skills

# Watch mode - auto re-scan on file changes
acidtest scan ./my-skill --watch

# Show remediation suggestions
acidtest scan ./my-skill --fix

# JSON output
acidtest scan ./my-skill --json
```

## How it works

AcidTest runs five analysis layers:

1. **Permission Audit** - Analyzes declared permissions (bins, env, tools)
2. **Prompt Injection Scan** - Detects instruction override attempts
3. **Code Analysis** - AST parsing + pattern matching for both Python and TypeScript
4. **Cross-Reference** - Catches code behavior not matching declared permissions
5. **Dataflow Analysis** - Tracks taint propagation from sources (env vars, user input) to dangerous sinks (exec, fetch)

**Example of multi-step attack detection:**

```python
# Simple pattern matching: "subprocess imported" → MEDIUM
# Dataflow analysis: "user input → subprocess shell=True" → CRITICAL

cmd = sys.argv[1]                           # SOURCE (user input)
subprocess.call(f"echo {cmd}", shell=True)  # SINK (command injection)

# AcidTest detects the 2-step path and flags as CRITICAL
```

See [METHODOLOGY.md](./METHODOLOGY.md) for technical details and limitations.

## Field validation

AcidTest scanned **2,386 public OpenClaw skills** from the openclaw-skills repository during the February 2026 ClawHub incident. It surfaced multiple live malicious payloads, including:

- C2 callbacks to raw IPs (`91.92.242.30`)
- SSH key injection into `~/.ssh/authorized_keys`
- Namespace squatting attacks
- Base64-encoded remote code execution

## CI/CD Integration

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
# Install pre-commit hook
curl -o .git/hooks/pre-commit https://raw.githubusercontent.com/currentlycurrently/acidtest/main/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Now every commit scans automatically
git commit -m "Add feature"  # Runs AcidTest first
```

### Security Badge

```markdown
[![Security: AcidTest](https://img.shields.io/badge/security-AcidTest-brightgreen)](https://github.com/currentlycurrently/acidtest)
```

Displays: [![Security: AcidTest](https://img.shields.io/badge/security-AcidTest-brightgreen)](https://github.com/currentlycurrently/acidtest)

## Use as MCP Server

AcidTest can run as an MCP server, letting AI agents like Claude scan skills before installation.

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

## What we don't catch

- Zero-day exploits in Node.js/Python runtimes
- Vulnerabilities in npm/pip dependencies (use `npm audit`/`pip-audit` for this)
- Runtime behavior outside static analysis scope
- Advanced obfuscation or VM-level evasion

We're honest about our limitations. See [METHODOLOGY.md](./METHODOLOGY.md) for full transparency.

## Defense-in-depth

Use AcidTest **with** other tools:

- **npm audit / pip-audit** - Dependency vulnerabilities
- **VirusTotal** - Known malware signatures
- **Sandboxing** - Runtime isolation (Docker, VMs, Firecracker)
- **Snapper / Clawhatch** - Complementary security tools

No single tool catches everything. Layer your defenses.

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

- **NPM**: https://www.npmjs.com/package/acidtest
- **GitHub**: https://github.com/currentlycurrently/acidtest
- **Issues**: https://github.com/currentlycurrently/acidtest/issues

## License

MIT
