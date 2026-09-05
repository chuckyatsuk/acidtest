# Security Policy

AcidTest is a security tool for the AI agent ecosystem. We welcome responsible disclosure of vulnerabilities in AcidTest itself.

## Scope

### In Scope

Security issues with AcidTest that we want to know about:

**Detection Bypasses:**
- Malicious code that AcidTest fails to detect (false negatives)
- Obfuscation techniques that evade pattern matching
- Permission mismatches that slip through cross-reference analysis

**Tool Vulnerabilities:**
- Path traversal when scanning user-provided directories
- Regex denial-of-service (ReDoS) in pattern matching
- Code injection via malicious skill manifests
- Arbitrary file read outside scan target

**Scoring Manipulation:**
- Ways to artificially inflate trust scores
- Techniques to hide findings from reports
- Bypasses of severity classification

**Supply Chain:**
- Compromised dependencies
- Malicious patterns in the pattern database

### Out of Scope

Issues we won't treat as security vulnerabilities:

- **False positives** - Safe code flagged as risky (report as a bug, not security issue)
- **Performance issues** - Slow scans or high memory usage (report as a bug)
- **Feature requests** - Missing detection categories (report as enhancement)
- **Documentation errors** - Typos or unclear instructions (report as bug)

## Reporting a Vulnerability

### For Detection Bypasses

If you've found malicious code that AcidTest doesn't catch:

1. **DO NOT** publish the bypass publicly
2. Open a GitHub Issue with title: `[BYPASS] Brief description`
3. Provide:
   - Minimal reproduction code
   - Expected behavior (what should be detected)
   - Actual behavior (what AcidTest reports)
   - Suggested pattern to catch it (if you have one)

**Example:**

```markdown
Title: [BYPASS] String concatenation evades child_process detection

**Malicious code:**
const exec = require('child_' + 'process').exec;
exec(userInput);

**Expected:** Should trigger dangerous-imports pattern
**Actual:** Pattern not detected

**Suggested fix:** Enhance AST analysis to track string concatenation
```

### For Tool Vulnerabilities

If you've found a security flaw in AcidTest itself:

1. **DO NOT** exploit it or publish details publicly
2. Report via **GitHub Security Advisories**:
   - Go to: https://github.com/currentlycurrently/acidtest/security/advisories
   - Click "Report a vulnerability"
   - Provide details (see template below)

3. Or email: [security contact - to be added]

**Report Template:**

```markdown
**Vulnerability Type:** [Path traversal / ReDoS / Code injection / etc.]

**Affected Version:** [e.g., v0.2.2]

**Impact:** [What an attacker could do]

**Steps to Reproduce:**
1. Step one
2. Step two
3. etc.

**Proof of Concept:** [Code or commands]

**Suggested Fix:** [If you have one]
```

## Response Timeline

We aim to respond to security reports within:

- **24 hours** - Initial acknowledgment
- **7 days** - Preliminary assessment and severity classification
- **30 days** - Fix developed and tested
- **60 days** - Patch released and advisory published

**Note:** For detection bypasses (false negatives), we may fast-track patches within 7 days since they're pattern-only changes.

## Severity Classification

We use this rubric to classify security issues:

### Critical
- Remote code execution when scanning malicious skills
- Arbitrary file system access outside scan target
- Credential theft via AcidTest exploitation

**Example:** Path traversal allowing `/etc/passwd` read

### High
- Denial of service via ReDoS patterns
- Score manipulation allowing malware to pass as safe
- Bypass of all five scanning layers

**Example:** Obfuscation technique that evades all pattern detection

### Medium
- Partial bypass of one scanning layer
- Minor information disclosure
- Logic errors in scoring algorithm

**Example:** String concatenation bypassing `child_process` detection

### Low
- Non-exploitable edge cases
- False negatives for rare attack patterns

**Example:** Missing detection for obscure Unicode normalization attack

## Disclosure Policy

### What We Commit To

When you report a vulnerability:

- We will **acknowledge your report** within 24 hours
- We will **not take legal action** against researchers acting in good faith
- We will **credit you** in release notes (unless you prefer anonymity)
- We will **coordinate disclosure** timing with you

### Public Disclosure

After a fix is released:

1. We publish a security advisory with:
   - Description of the issue
   - Affected versions
   - Mitigation steps
   - Credit to reporter (if allowed)

2. We update CHANGELOG.md with security-specific release notes

3. We tag the release with security-specific version (e.g., v0.2.3 → v0.2.4)

### Coordinated Disclosure

We prefer **coordinated disclosure**:

- We fix the issue
- We release a patch
- **Then** we publish details publicly

If you plan to publish research about AcidTest bypasses, please give us 30 days notice.

## Security Best Practices for Users

### When Using AcidTest

**Do:**
- Always scan skills from untrusted sources before installation
- Review findings manually—don't blindly trust scores
- Keep AcidTest updated to get latest pattern definitions
- Run AcidTest in sandboxed environments when scanning unknown code

**Don't:**
- Scan system directories or sensitive file locations
- Run AcidTest with elevated privileges (root/admin)
- Disable pattern validation during development
- Trust skills that pass AcidTest without reviewing the code

### Known Limitations

AcidTest is **static analysis only**. It cannot detect:

- Runtime behavior changes
- Time-delayed attacks (logic bombs)
- Polymorphic malware that changes on each execution
- Attacks that only trigger under specific conditions

**Always review skills manually, even if they pass scanning.**

## Security Updates

We announce security updates via:

- GitHub Security Advisories
- Release notes in CHANGELOG.md
- [Optional: Mailing list, Twitter, etc.]

Subscribe to releases on GitHub to get notified.

## Examples of Good Reports

### Example 1: Detection Bypass

> **Title:** [BYPASS] Base64 + hex encoding evades obfuscation detection
>
> **Description:** The obfuscation patterns detect base64 but not base64 + hex double encoding.
>
> **Malicious code:**
> ```javascript
> eval(Buffer.from('ZXZhbChhdG9iKCdtYWxpY2lvdXMnKSk=', 'base64').toString('hex'))
> ```
>
> **Severity:** High (allows malicious code to evade detection)
>
> **Suggested pattern:**
> ```json
> {
>   "id": "ob-007",
>   "name": "double-encoding",
>   "severity": "HIGH",
>   "match": {
>     "type": "regex",
>     "value": "Buffer\\.from.*base64.*\\.toString.*hex",
>     "flags": "g"
>   },
>   "layer": "code"
> }
> ```

### Example 2: Tool Vulnerability

> **Title:** Path traversal in skill directory scanning
>
> **Description:** AcidTest doesn't validate scan paths, allowing read of any file.
>
> **Steps to reproduce:**
> ```bash
> acidtest scan ../../../etc/passwd
> ```
>
> **Impact:** Can read sensitive files outside intended scan target.
>
> **Suggested fix:** Add path validation in scanner.ts:
> ```typescript
> const resolvedPath = path.resolve(scanPath);
> if (!resolvedPath.startsWith(process.cwd())) {
>   throw new Error('Path traversal detected');
> }
> ```

## Recognition

Security researchers who responsibly disclose issues will be credited in:

- Security advisories
- CHANGELOG.md release notes
- [Optional: Hall of Fame page]

## Contact

- **GitHub Issues** (for detection bypasses): https://github.com/currentlycurrently/acidtest/issues
- **Security Advisories** (for tool vulnerabilities): https://github.com/currentlycurrently/acidtest/security/advisories
- **Email** (for private reports): [To be added]

---

**Last updated:** February 6, 2026
**Version:** 1.0
