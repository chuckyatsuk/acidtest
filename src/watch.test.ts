/**
 * Tests for watch mode
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { watchMode } from './watch.js';

describe('Watch Mode', () => {
  const testDir = join(process.cwd(), 'test-watch-temp');

  beforeEach(() => {
    // Create a temporary test directory
    mkdirSync(testDir, { recursive: true });

    // Create a minimal SKILL.md file
    writeFileSync(
      join(testDir, 'SKILL.md'),
      `---
name: test-skill
---

# Test Skill

This is a test skill.
`
    );

    // Create a handler file
    writeFileSync(
      join(testDir, 'handler.ts'),
      `export function handler() {
  console.log('Hello');
}
`
    );
  });

  afterEach(() => {
    // Clean up
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch (error) {
      // Ignore errors during cleanup
    }
  });

  it('should export watchMode function', () => {
    expect(watchMode).toBeDefined();
    expect(typeof watchMode).toBe('function');
  });

  it('should accept path and options', async () => {
    // This test just verifies the function signature
    // We can't fully test watch mode in a unit test without mocking chokidar
    // Note: watchMode has 1 required param (skillPath) and 1 optional param (options)
    expect(watchMode.length).toBe(1); // Required parameters only
  });
});

// Note: Full integration tests for watch mode would require:
// 1. Mocking file system events
// 2. Mocking stdin for keyboard input
// 3. Testing debouncing behavior
// These are better suited for manual testing or E2E tests
