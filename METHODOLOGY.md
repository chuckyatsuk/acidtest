# AcidTest Security Methodology

This document covers AcidTest's detection capabilities, limitations, and the security threats it addresses.

## What AcidTest Does

AcidTest performs **static analysis** on AI agent skills and MCP servers using five layers:

1. **Permission Analysis** - Audits declared permissions in YAML frontmatter
2. **Injection Detection** - Scans markdown for prompt injection patterns
3. **Code Analysis** - Multi-language AST analysis (TypeScript + Python) + regex patterns
4. **Cross-Reference** - Validates permissions match actual behavior
5. **Dataflow Analysis** - Tracks taint flow from sources (env vars, user input) to dangerous sinks (exec, fetch)

### Detection Capabilities

AcidTest ships **134 detection patterns across 19 category files**, plus
AST-based and heuristic checks that have no JSON representation (dataflow
taint tracking, entropy analysis, version-diff rug-pull detection). To
regenerate the pattern count: `npm run validate:patterns`.

**What We Catch:**
- Direct calls to dangerous APIs (`exec`, `eval`, `Function`)
- Prompt injection, including the 2026 vocabulary (fake system-reminder
  and tool-result blocks, embedded tool-call JSON, direct address to the
  reviewing AI, claimed vendor provenance)
- MCP tool poisoning (instructions smuggled into tool/parameter descriptions)
- Cross-server shadowing / confused-deputy claims
- Credential exfiltration through MCP resource and sampling channels
- SKILL.md frontmatter injection (description/trigger fields)
- Rug-pull updates (a new version that adds network/exec/credential
  capability absent from the prior version — see `acidtest diff`)
- Unicode/invisible-character obfuscation (zero-width, bidi/Trojan-Source,
  U+E0000 tag characters, mixed-script homoglyphs)
- Hardcoded credentials and API keys
- Data exfiltration to undeclared domains
- Standard obfuscation (base64, hex, high-entropy strings)
- Dynamic requires, string-concatenation and template-literal import
  bypasses, property-access bypasses, Function-constructor abuse
- Undeclared network calls and suspicious file system operations

**What We May Miss:**
- Advanced control flow obfuscation (multi-step indirection)
- Encrypted or polymorphic payloads
- Time-delayed execution
- Data leaks via timing side channels
- Behavioral analysis (runtime-only detection)
- Supply chain attacks (dependency vulnerabilities)
- Zero-day exploitation techniques

### Measured Detection (test corpus)

We do not publish a single headline "detection rate" — a rate is only
meaningful against a stated corpus, and a corpus we control can be tuned
to produce any number we like. Instead we ship the corpus and let you
regenerate the result: `npm run test:corpus`.

Against the bundled corpus (`test-corpus/`), the current version scores:

| Class                | Examples | Correct |
|----------------------|----------|---------|
| Vulnerable (detected as FAIL/DANGER) | 12 | 12 (100%) |
| Legitimate (passed as PASS/WARN)     | 6  | 6 (100%)  |

This corpus is deliberately small and hand-built to cover the threat
classes above with at least one true-positive and matched
false-positive guard each. **100% here means "we catch the attacks we
wrote fixtures for and don't flag the clean examples we wrote" — it is a
regression guard, not a claim about detection in the wild.** A real-world
skill using a novel technique we have no pattern for will pass. The
corpus grows as new patterns are added; the honest number to watch is
whether it ever drops below 100% (a regression), not the percentage itself.

## How Static Analysis Works

### Strengths

1. **Zero Runtime Overhead** - Scans code before execution, no sandboxing needed
2. **Fast** - Completes in seconds, suitable for CI/CD pipelines
3. **Deterministic** - Same code always produces same results
4. **No Network Required** - Works offline, no API keys needed
5. **Language-Aware** - Uses TypeScript compiler API for AST analysis

### Limitations

1. **Cannot Execute Code** - Cannot detect behavior that emerges only at runtime
2. **Limited Context** - Cannot track complex dataflows across files
3. **Bypass Potential** - Determined attackers can evade pattern-based detection
4. **False Positives** - Legitimate code may trigger security warnings
5. **No Dependency Analysis** - Does not scan npm packages or transitive dependencies

## Known Bypass Techniques

We mitigate common bypasses, but sophisticated attackers may use others.

### Detected Bypasses

**String Concatenation**
```javascript
require('child_' + 'process')  // CAUGHT by AST-based detection
```

**Template Literals**
```javascript
const mod = `child_${x}`;
require(mod);  // CAUGHT as dynamic require
```

**Property Access**
```javascript
global['child_process']  // CAUGHT by bracket notation detection
```

**Function Constructor**
```javascript
new Function('return eval')()  // CAUGHT by AST pattern matching
```

**Invisible Unicode / Trojan Source**
```javascript
const safe​ = false;  // zero-width char CAUGHT (uo-001)
// bidi override CAUGHT in code and markdown (uo-002/uo-003)
```

### Potentially Missed Bypasses

**Multi-Step Indirection**
```javascript
const getModule = () => 'child_' + 'process';
setTimeout(() => require(getModule()), 1000);  // May evade detection
```

**WebAssembly Execution**
```javascript
const wasm = await WebAssembly.instantiate(buffer);  // Not analyzed
```

**External Code Loading**
```javascript
const remote = await fetch(url).then(r => r.text());
eval(remote);  // eval() caught, but remote source not analyzed
```

## When to Use AcidTest

### Good Use Cases

- **Pre-Installation Screening** - Quick security check before installing skills
- **CI/CD Integration** - Automated scanning in pull request workflows
- **Bulk Auditing** - Scan entire directories of skills/servers
- **Trust Score Comparison** - Compare security profiles of similar tools
- **Education** - Learn about common attack patterns in AI agent code

### Not Recommended For

- **Production Security** - Should not be your only defense
- **Compliance Certification** - Not a substitute for professional security audits
- **Malware Forensics** - Not designed for analyzing known malicious code
- **Dependency Vulnerabilities** - Use `npm audit` for package CVEs
- **Runtime Protection** - Does not sandbox or monitor execution

## Threat Model

### In-Scope Threats

1. **Malicious Skills** - Deliberately crafted to exfiltrate data or execute commands
2. **Backdoored Tools** - Legitimate-looking skills with hidden malicious code
3. **Prompt Injection** - Attempts to manipulate AI agent behavior via markdown
4. **Credential Theft** - Harvesting API keys, tokens, environment variables
5. **Privilege Escalation** - Undeclared file system or network access

### Out-of-Scope Threats

1. **Supply Chain Attacks** - Compromised npm dependencies (use `npm audit`)
2. **Zero-Day Exploits** - Unknown vulnerabilities in Node.js or libraries
3. **Social Engineering** - Tricking users into approving malicious prompts
4. **Physical Access** - Adversary with direct access to the system
5. **Advanced Persistent Threats** - Nation-state level sophistication

## Scoring Methodology

AcidTest uses a **100-point trust score** system:

### Score Calculation

- **Start:** 100 points
- **Deductions:** Based on severity of findings
  - CRITICAL: -25 points (eval, data exfiltration)
  - HIGH: -15 points (dynamic require, dangerous imports)
  - MEDIUM: -8 points (obfuscation, suspicious patterns)
  - LOW: -3 points (info leaks, minor issues)
  - INFO: 0 points (informational findings)
- **Capping:** Max 3 deductions per unique pattern (prevents score inflation)
- **Floor:** Score cannot go below 0

### Status Thresholds

| Score Range | Status  | Recommendation |
|-------------|---------|----------------|
| 80-100      | PASS    | Safe to install with review of findings |
| 50-79       | WARN    | Review recommended, some concerns |
| 20-49       | FAIL    | Not recommended, significant issues |
| 0-19        | DANGER  | Do not install, critical vulnerabilities |

### Scoring Limitations

- **Subjective Weights:** Severity levels are based on common threat models, not scientific measurement
- **Context-Free:** Same pattern penalized equally regardless of context
- **Binary Detection:** No severity gradation within a category
- **No Risk Aggregation:** Multiple LOW findings don't escalate to HIGH

## Recommendations for Users

### Before Installing a Skill

1. **Run AcidTest:** `npx acidtest scan ./skill-directory`
2. **Review Findings:** Read each security warning, don't just check the score
3. **Check Permissions:** Ensure declared permissions match your expectations
4. **Inspect Code:** For WARN/FAIL/DANGER, manually review the code
5. **Test in Sandbox:** Run untrusted skills in isolated environments

### For Skill Developers

1. **Declare Permissions:** Be explicit about env vars, file paths, network access
2. **Avoid Dynamic Imports:** Use static `require()` and `import` statements
3. **Document Intent:** Add code comments explaining any low-level API usage
4. **Test with AcidTest:** Ensure `npx acidtest scan .` returns PASS before publishing
5. **CI/CD Integration:** Add AcidTest to GitHub Actions to prevent regressions

### For Organizations

1. **Threshold Policy:** Reject skills below a certain score (e.g., FAIL or worse)
2. **Manual Review:** Require human approval for WARN status
3. **Allowlist:** Maintain approved skills that passed security review
4. **Private Registry:** Host audited skills internally
5. **Least Privilege:** Run agent skills with minimal system permissions

## Continuous Improvement

AcidTest's detection patterns are continuously updated based on:

- Observed attack techniques in the wild
- Community contributions via GitHub issues/PRs
- Security research publications
- Feedback from production deployments

**Current pattern count:** 79 detection patterns
- 48 TypeScript/JavaScript patterns across 6 categories
- 31 Python patterns (17 imports, 14 dangerous calls)

**See:** [CONTRIBUTING.md](CONTRIBUTING.md) for how to submit new patterns.

## Python Support

AcidTest analyzes Python code using tree-sitter-python v0.21.0:

**Detection Capabilities:**
- **Code Execution:** eval(), exec(), compile(), __import__()
- **Command Injection:** subprocess with shell=True, os.system(), os.popen()
- **Unsafe Deserialization:** pickle.loads(), marshal.load(), yaml.load() without SafeLoader
- **File Operations:** shutil.rmtree(), os.remove(), tempfile.mktemp()
- **Native Code:** ctypes, cffi
- **Network Operations:** requests, urllib, httpx, socket (context-aware)

**Python-Specific Features:**
- AST-based function call analysis with context (shell=True detection)
- Import statement analysis for dangerous modules
- Distinction between `subprocess.run()` with and without shell=True
- Lower severity for legitimate API client patterns (requests, os.environ)

**Test Coverage:**
- 16 Python-specific unit tests
- 5 vulnerable Python examples (test corpus)
- 2 legitimate Python examples (API client, file processor)
- 100% detection rate on vulnerable Python code

**Validation:**
- Tested against 55 real-world AgentSkills with Python code
- 71% PASS rate on legitimate skills
- No regressions in TypeScript detection

Python support is production-ready as of v1.0.0 Phase 2.

## Comparison to Other Tools

| Tool Type | AcidTest | npm audit | Sandbox/VM | Manual Review |
|-----------|----------|-----------|------------|---------------|
| Speed | Fast (seconds) | Fast | Slow | Very Slow |
| Coverage | Code + Config | Dependencies | Runtime | Comprehensive |
| False Positives | Some | Few | Rare | None |
| Setup | Zero config | Built-in | Complex | N/A |
| Bypass Resistance | Medium | High | High | Very High |

**Recommendation:** Use AcidTest as **first-line defense**, not replacement for defense-in-depth.

## Limitations

- **Not foolproof:** Determined attackers can bypass static analysis
- **Not comprehensive:** Does not replace professional security audits
- **Not certified:** Not suitable for compliance requirements
- **Not runtime protection:** Does not prevent execution of malicious code

Use AcidTest as a fast, automated screening tool within a layered security strategy.

## References & Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Prompt Injection Primer](https://simonwillison.net/2023/Apr/14/worst-that-can-happen/)
- [Static Analysis Limitations](https://en.wikipedia.org/wiki/Static_program_analysis#Limitations)

---

**Last Updated:** 2026-02-08
**Version:** v1.0.0-dev (Phase 2 Complete)
**Maintainers:** AcidTest Team

For questions or feedback, visit: https://github.com/chuckyatsuk/acidtest/issues
