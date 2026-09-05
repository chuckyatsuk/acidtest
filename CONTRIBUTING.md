# Contributing to AcidTest

Contributions are welcome.

## Quick Start

The easiest way to contribute is to add a detection pattern. No coding required.

## Adding Detection Patterns

Detection patterns are JSON files in `src/patterns/`. Each one defines a security issue to scan for.

### Pattern Structure

```json
{
  "id": "ex-999",
  "name": "my-pattern-name",
  "description": "What this pattern detects",
  "severity": "HIGH",
  "match": {
    "type": "regex",
    "value": "dangerous_function\\(",
    "flags": "g"
  },
  "layer": "code"
}
```

### Fields Explained

- **id**: Unique identifier (format: `category-###`)
  - `pi-###` for prompt injection
  - `ex-###` for exfiltration
  - `di-###` for dangerous imports
  - `ob-###` for obfuscation
  - `cp-###` for credential patterns
  - `sp-###` for sensitive paths

- **name**: Short kebab-case name (e.g., `eval-usage`, `reverse-shell`)

- **description**: Clear explanation of what this detects and why it's dangerous

- **severity**: Risk level
  - `CRITICAL`: Definite malicious behavior (eval, child_process, prompt injection)
  - `HIGH`: Suspicious and potentially dangerous (undeclared network, credential access)
  - `MEDIUM`: Concerning but may be legitimate (fetch calls, base64 encoding)
  - `LOW`: Minor issues or missing declarations
  - `INFO`: Informational findings

- **match.type**: Always `"regex"` for now

- **match.value**: JavaScript regex pattern (remember to escape backslashes)

- **match.flags**: Regex flags (`"i"` for case-insensitive, `"g"` for global, `"is"` for multiline)

- **layer**: Which scanning layer uses this pattern
  - `markdown` - Scans SKILL.md content and MCP manifests
  - `code` - Scans JavaScript/TypeScript files
  - `permissions` - Not used in patterns (handled by code)
  - `crossref` - Not used in patterns (compares layers)

### Pattern Files

Add patterns to the appropriate category file:

- `src/patterns/prompt-injection.json` - Instruction overrides, jailbreaks
- `src/patterns/dangerous-imports.json` - Risky Node.js modules
- `src/patterns/exfiltration-sinks.json` - Data leakage patterns
- `src/patterns/obfuscation.json` - Code hiding techniques
- `src/patterns/credential-patterns.json` - API keys, tokens, secrets
- `src/patterns/sensitive-paths.json` - System file access

### Example: Adding a New Pattern

Add detection for `npm install` in code (a supply chain risk):

1. Open `src/patterns/dangerous-imports.json`

2. Find the next available ID (e.g., `di-010`)

3. Add your pattern:

```json
{
  "id": "di-010",
  "name": "npm-install-in-code",
  "description": "Attempts to install packages at runtime",
  "severity": "HIGH",
  "match": {
    "type": "regex",
    "value": "npm\\s+install|yarn\\s+add|pnpm\\s+add",
    "flags": "g"
  },
  "layer": "code"
}
```

4. Validate your pattern:

```bash
npm run validate
```

5. Build and test:

```bash
npm run build
npm run dev  # Run demo to verify
```

### Pattern Guidelines

**Good patterns:**
- Specific enough to avoid false positives
- Clear description of the threat
- Appropriate severity level
- Well-escaped regex (test with regex101.com)

**Avoid:**
- Overly broad patterns (e.g., matching the word "password" everywhere)
- Complex nested regex that causes performance issues
- Patterns that duplicate existing detections

### Testing Your Pattern

Create a test fixture to verify your pattern works:

```bash
# Create a test skill
mkdir -p test-fixtures/my-test
echo "---
name: test-skill
---
# Test Skill" > test-fixtures/my-test/SKILL.md

# Add code that should trigger your pattern
echo "exec('npm install malicious-package');" > test-fixtures/my-test/index.js

# Scan it
npm run build
npx acidtest scan test-fixtures/my-test
```

Your pattern should appear in the findings.

## Submitting Your Contribution

1. Fork the repository
2. Create a feature branch: `git checkout -b add-npm-install-pattern`
3. Add your pattern to the appropriate JSON file
4. Run validation: `npm run validate`
5. Run build: `npm run build`
6. Test with demo: `npm run dev`
7. Commit with clear message: `git commit -m "Add npm-install-in-code pattern (di-010)"`
8. Push and create a pull request

### Pull Request Checklist

- [ ] Pattern has a unique ID
- [ ] Pattern is added to the correct category file
- [ ] `npm run validate` passes
- [ ] `npm run build` succeeds
- [ ] Tested with at least one fixture
- [ ] Description clearly explains the threat

## Code Contributions

For changes beyond patterns, such as new features or bug fixes:

### Setup

```bash
git clone https://github.com/currentlycurrently/acidtest
cd acidtest
npm install
npm run build
```

### Development Workflow

```bash
npm run watch  # Auto-rebuild on file changes
npm run dev    # Run demo with current code
```

### Project Structure

- `src/index.ts` - CLI entry point
- `src/scanner.ts` - Main orchestration logic
- `src/layers/` - Five scanning layers (permissions, injection, code, crossref, dataflow)
- `src/patterns/` - Detection pattern JSON files
- `src/loaders/` - Skill/MCP manifest parsing
- `src/mcp-server.ts` - MCP protocol server
- `src/reporter.ts` - Terminal output formatting
- `src/scoring.ts` - Trust score calculation

### Coding Standards

- TypeScript strict mode
- ESM modules
- Descriptive variable names
- Comments for complex logic
- Error handling for all file I/O

### Testing

Before submitting:

```bash
npm run validate  # Check patterns
npm run build     # Compile TypeScript
npm run dev       # Test with demo fixtures
```

Test your changes against all fixtures:

```bash
npx acidtest scan-all test-fixtures
```

## Areas We Need Help With

**High Priority:**
- New detection patterns (see issues labeled `pattern-request`)
- Test coverage for edge cases
- Documentation improvements

**Medium Priority:**
- False positive reduction
- Performance optimization for large skills
- Better error messages

**Future:**
- VS Code extension
- GitHub Action
- Web-based scanner UI

## Questions?

- Open an issue for questions or suggestions
- Check existing issues before creating new ones
- Tag issues with appropriate labels

## License

By contributing, you agree your contributions will be licensed under the same MIT License that covers the project.
