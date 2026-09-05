# Test Fixtures

Minimal SKILL.md files for CI testing and development. Each fixture triggers a known set of findings and lands in a known score range.

## Fixture Descriptions

### 1. fixture-pass (PASS: 80-100)

**Expected Score:** 100
**Expected Status:** PASS
**Expected Findings:** 0

A completely clean skill with no security issues:
- No risky imports or operations
- No network calls
- No file system access
- No prompt injection patterns
- Clean markdown with no hidden instructions

**Use case:** Baseline test that the scanner doesn't flag safe code.

---

### 2. fixture-warn (WARN: 50-79)

**Expected Score:** ~73
**Expected Status:** WARN
**Expected Findings:** 3-4

A skill with minor security concerns:
- Uses `fetch()` for HTTP requests (MEDIUM: -8)
- Contains HTTP URL literals in code (LOW: -3)
- Contains HTTP URL in markdown (LOW: -3)
- Requires API_KEY environment variable (potential info finding)

**Triggered Patterns:**
- `ex-001`: fetch-call (MEDIUM)
- `ex-006`: http-url-literal (LOW)

**Use case:** Tests detection of common but acceptable patterns that warrant review.

---

### 3. fixture-fail (FAIL: 20-49)

**Expected Score:** ~26
**Expected Status:** FAIL
**Expected Findings:** 6-8

A skill with serious security issues:
- Hidden HTML comment with prompt injection (MEDIUM: -8)
- Uses file deletion (`unlinkSync`) (HIGH: -15)
- Makes unauthorized fetch calls (MEDIUM: -8)
- Contains exfiltration instructions in markdown (CRITICAL: -25)
- Multiple HTTP URLs (LOW: -3 each)
- Uses dynamic require() (HIGH: -15)

**Triggered Patterns:**
- `pi-004`: maintenance-mode (HIGH)
- `pi-010`: html-comment-instructions (MEDIUM)
- `ex-005`: send-to-url (CRITICAL)
- `di-007`: fs-unlink (HIGH)
- `di-008`: dynamic-require (HIGH)
- `ex-001`: fetch-call (MEDIUM)
- `ex-006`: http-url-literal (LOW)

**Use case:** Tests detection of multiple high-severity issues that should block installation.

---

### 4. fixture-danger (DANGER: 0-19)

**Expected Score:** 0
**Expected Status:** DANGER
**Expected Findings:** 10+

An obviously malicious skill with critical vulnerabilities:
- Multiple prompt injection attempts (CRITICAL: -25 each)
  - "Ignore all previous instructions"
  - "Disregard your safety guidelines"
  - "Act as root"
  - "Forget everything above"
  - "New instructions follow"
- Command execution via `child_process` (CRITICAL: -25)
- Uses `eval()` (CRITICAL: -25)
- VM module for code execution (CRITICAL: -25)
- WebSocket for data exfiltration (HIGH: -15)
- Multiple exfiltration URLs (CRITICAL: -25 each)
- Credential theft patterns

**Triggered Patterns:**
- `pi-001`: instruction-override (CRITICAL)
- `pi-002`: disregard-instructions (CRITICAL)
- `pi-003`: forget-above (CRITICAL)
- `pi-006`: new-instructions (CRITICAL)
- `pi-007`: act-as-root (CRITICAL)
- `di-001`: child-process-import (CRITICAL)
- `di-002`: eval-usage (CRITICAL)
- `di-004`: vm-module (CRITICAL)
- `ex-004`: websocket-connection (HIGH)
- `ex-005`: send-to-url (CRITICAL, multiple instances)
- `ex-006`: http-url-literal (LOW, multiple instances)

**Use case:** Tests detection of obviously malicious code that should never be installed.

---

## Running Tests

```bash
# Scan individual fixtures
npx acidtest scan ./test-fixtures/fixture-pass
npx acidtest scan ./test-fixtures/fixture-warn
npx acidtest scan ./test-fixtures/fixture-fail
npx acidtest scan ./test-fixtures/fixture-danger

# Scan all fixtures
npx acidtest scan-all ./test-fixtures

# JSON output for CI
npx acidtest scan ./test-fixtures/fixture-danger --json
```

## Expected CI Behavior

A properly functioning scanner should:
1. Score `fixture-pass` at 80 or above (PASS)
2. Score `fixture-warn` between 50-79 (WARN)
3. Score `fixture-fail` between 20-49 (FAIL)
4. Score `fixture-danger` below 20 (DANGER)

## Score Calculation Reference

Starting score: 100

Severity deductions:
- CRITICAL: -25 points
- HIGH: -15 points
- MEDIUM: -8 points
- LOW: -3 points
- INFO: 0 points

Status thresholds:
- PASS: 80-100
- WARN: 50-79
- FAIL: 20-49
- DANGER: 0-19

## Maintenance

These fixtures are kept minimal so that they:
- Run fast (under 2 seconds total)
- Have obvious expected findings
- Don't depend on external files
- Work reliably in CI

When you add a detection pattern, update a fixture if it would naturally trigger the new pattern. Keep the fixture count small and focused.
