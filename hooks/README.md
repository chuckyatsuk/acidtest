# AcidTest Hooks

Hooks to automatically scan your skills/MCP servers for security issues —
at commit time (git pre-commit) and at install time (Claude Code PreToolUse).

## Claude Code PreToolUse Hook

`claude-code-preinstall.sh` blocks a Claude Code tool call when AcidTest
flags the project directory. Claude Code passes the tool call as JSON on
stdin and treats **exit code 2** as "block this action."

### Installation

```bash
mkdir -p ~/.claude/hooks
curl -o ~/.claude/hooks/acidtest-preinstall.sh \
  https://raw.githubusercontent.com/currentlycurrently/acidtest/main/hooks/claude-code-preinstall.sh
chmod +x ~/.claude/hooks/acidtest-preinstall.sh
```

Then register it in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [
          { "type": "command",
            "command": "~/.claude/hooks/acidtest-preinstall.sh" }
        ] }
    ]
  }
}
```

### Behavior

- Reads the tool call from stdin; only acts on install-shaped `Bash`
  commands (`install`, `plugin add`, `clone`) and ignores its own scans.
- Scans `$CLAUDE_PROJECT_DIR` and **exits 2 to block** when the result is
  `FAIL`/`DANGER`; otherwise exits 0 and the action proceeds.
- Requires `acidtest` and `jq` on `PATH`.

## Pre-Commit Hook

Runs AcidTest before each commit to catch security issues early.

### Installation

**Option 1: Copy directly**
```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**Option 2: Download from GitHub**
```bash
curl -o .git/hooks/pre-commit https://raw.githubusercontent.com/currentlycurrently/acidtest/main/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**Option 3: Symlink (for development)**
```bash
ln -s ../../hooks/pre-commit .git/hooks/pre-commit
```

### Behavior

The pre-commit hook:
- Runs an AcidTest scan on your code
- Displays the score and status
- Shows CRITICAL and HIGH severity findings
- Blocks commits on DANGER status
- Warns on FAIL status (does not block by default)
- Passes on WARN and PASS status

### Configuration

To make the hook **block on FAIL status**, edit `.git/hooks/pre-commit` and uncomment this line:

```bash
# exit 1  # <- Remove the # to block on FAIL
```

### Bypassing the Hook

If you need to bypass the pre-commit check (not recommended):

```bash
git commit --no-verify
```

### Uninstalling

```bash
rm .git/hooks/pre-commit
```

## Example Output

### Clean commit (PASS)
```
🛡️  Running AcidTest security scan...

Score:  100/100
Status: PASS

✅ Security scan passed
```

### Blocked commit (DANGER)
```
🛡️  Running AcidTest security scan...

Score:  0/100
Status: DANGER

Findings:
  [CRITICAL] eval() usage detected: Found 2 eval() call(s)
  [CRITICAL] instruction-override: Attempts to override agent instructions

❌ Commit blocked: DANGER status detected
   Fix critical security issues before committing

   To bypass this check (NOT recommended):
   git commit --no-verify
```

## Troubleshooting

**Hook doesn't run:**
- Ensure it's executable: `chmod +x .git/hooks/pre-commit`
- Verify it's in the right location: `.git/hooks/pre-commit`

**"acidtest not found" error:**
- The hook will automatically use `npx` if acidtest isn't globally installed
- Or install globally: `npm install -g acidtest`

**"jq: command not found" error:**
- Install jq:
  - macOS: `brew install jq`
  - Ubuntu: `sudo apt install jq`
  - Or the hook will skip JSON parsing (still runs scan)
