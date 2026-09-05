#!/usr/bin/env bash
#
# AcidTest — Claude Code PreToolUse hook
#
# Blocks a Claude Code tool call when AcidTest flags the project directory.
# Claude Code passes the tool call as JSON on stdin and treats exit code 2
# as "block this action"; any other exit lets it proceed.
#
# Installation:
#   1. Copy this file to ~/.claude/hooks/acidtest-preinstall.sh
#   2. chmod +x ~/.claude/hooks/acidtest-preinstall.sh
#   3. Register it in ~/.claude/settings.json:
#        {
#          "hooks": {
#            "PreToolUse": [
#              { "matcher": "Bash",
#                "hooks": [
#                  { "type": "command",
#                    "command": "~/.claude/hooks/acidtest-preinstall.sh" }
#                ] }
#            ]
#          }
#        }
#
# Requires `acidtest` and `jq` on PATH.

set -euo pipefail

# PreToolUse delivers the tool call as JSON on stdin.
payload="$(cat)"
cmd="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty')"

# Only act on install-shaped commands; let everything else through.
case "$cmd" in
  *"acidtest"*) exit 0 ;;                # never scan our own scans (no recursion)
  *install*|*"plugin add"*|*clone*) ;;   # these are worth scanning
  *) exit 0 ;;
esac

# Scan the directory the session is running in.
target="${CLAUDE_PROJECT_DIR:-.}"
result="$(mktemp)"
trap 'rm -f "$result"' EXIT

if ! acidtest scan "$target" --json > "$result" 2>/dev/null; then
  status="$(jq -r '.status' "$result")"
  {
    echo "🛑 AcidTest blocked this action: $target is $status"
    jq -r '.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH")
           | "  [\(.severity)] \(.title): \(.detail)"' "$result"
  } >&2
  exit 2   # exit 2 tells Claude Code to block the tool call
fi

exit 0
