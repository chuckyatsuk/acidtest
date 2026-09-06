---
name: my-skill
description: A secure AI agent skill template
version: 1.0.0
env: []
bins: []
allowed-tools: []
---

# My Skill

A brief description of what this skill does.

## Features

- Feature 1
- Feature 2
- Feature 3

## Usage

Explain how the agent should use this skill.

Example:
```
User: "Format this text: hello world"
Agent: Uses my-skill to format the text
Result: "HELLO WORLD"
```

## Permissions

This skill requests the following permissions:

- **env**: None (or list required environment variables)
- **bins**: None (or list required system binaries)
- **allowed-tools**: None (or list tools like browser, filesystem)

## Implementation Notes

- Uses only built-in Node.js APIs
- No external network calls
- No file system access
- Safe for general use

## Security

This skill has been scanned with [AcidTest](https://github.com/chuckyatsuk/acidtest) and achieved a score of **100/100** (PASS).

To verify security yourself:
```bash
npx acidtest scan .
```
