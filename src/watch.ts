/**
 * Watch mode implementation
 * Re-scans skills on file changes
 */

import chokidar from 'chokidar';
import { scanSkill } from './scanner.js';
import { reportToTerminal, reportAsJSON } from './reporter.js';
import type { ScanResult } from './types.js';

export interface WatchOptions {
  noClear?: boolean;
  jsonOutput?: boolean;
  showRemediation?: boolean;
}

/**
 * Start watch mode for a skill directory
 */
export async function watchMode(skillPath: string, options: WatchOptions = {}): Promise<void> {
  let scanning = false;
  let debounceTimer: NodeJS.Timeout | null = null;

  /**
   * Perform a scan
   */
  async function scan(reason?: string): Promise<void> {
    if (scanning) return;
    scanning = true;

    try {
      // Clear terminal unless disabled
      if (!options.noClear && !options.jsonOutput) {
        console.clear();
      }

      const timestamp = new Date().toLocaleTimeString();

      if (!options.jsonOutput) {
        if (reason) {
          console.log(`[${timestamp}] ${reason}`);
        }
        console.log(`[${timestamp}] Scanning...`);
      }

      // Show progress spinner (not in JSON mode)
      const result: ScanResult = await scanSkill(skillPath, !options.jsonOutput);

      if (options.jsonOutput) {
        reportAsJSON(result);
      } else {
        reportToTerminal(result, { showRemediation: options.showRemediation });
        console.log('\n─'.repeat(30));
        console.log('Watching for changes... (press q to quit, r to re-scan, c to clear)');
      }
    } catch (error) {
      const msg = (error as Error).message ?? String(error);
      console.error(`\n[ERROR] Scan failed: ${msg}`);
      console.error('─'.repeat(30));
      console.error('Watching for changes... (press r to retry, q to quit)');
    } finally {
      scanning = false;
    }
  }

  // Set up file watcher
  const watcher = chokidar.watch(skillPath, {
    ignored: /(node_modules|dist|\.git|\.DS_Store)/,
    persistent: true,
    ignoreInitial: true, // Don't trigger on initial scan
    awaitWriteFinish: {
      stabilityThreshold: 100,
      pollInterval: 50
    }
  });

  // Handle file changes with debouncing
  watcher.on('change', (path) => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }

    debounceTimer = setTimeout(() => {
      scan(`File changed: ${path}`);
    }, 300);
  });

  watcher.on('add', (path) => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }

    debounceTimer = setTimeout(() => {
      scan(`File added: ${path}`);
    }, 300);
  });

  watcher.on('unlink', (path) => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }

    debounceTimer = setTimeout(() => {
      scan(`File removed: ${path}`);
    }, 300);
  });

  watcher.on('error', (error) => {
    console.error('Watcher error:', error);
  });

  // Set up keyboard shortcuts (only in non-JSON mode)
  if (!options.jsonOutput && process.stdin.isTTY) {
    try {
      process.stdin.setRawMode(true);
    } catch {
      // setRawMode may fail in some environments (CI, non-interactive shells)
      // Fall back gracefully without keyboard shortcuts
    }
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    process.stdin.on('data', (key: string) => {
      const char = key.toString();

      // Quit on 'q' or Ctrl+C
      if (char === 'q' || char === '\u0003') {
        console.log('\nExiting watch mode...');
        watcher.close();
        try { process.stdin.setRawMode(false); } catch { /* ignore */ }
        process.exit(0);
      }

      // Force re-scan on 'r'
      if (char === 'r') {
        scan('Manual re-scan triggered');
      }

      // Clear terminal on 'c'
      if (char === 'c') {
        console.clear();
      }
    });
  }

  // Handle process termination
  process.on('SIGINT', () => {
    console.log('\nExiting watch mode...');
    watcher.close();
    if (process.stdin.isTTY) {
      try { process.stdin.setRawMode(false); } catch { /* ignore */ }
    }
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    watcher.close();
    if (process.stdin.isTTY) {
      try { process.stdin.setRawMode(false); } catch { /* ignore */ }
    }
    process.exit(0);
  });

  // Initial message and scan
  if (!options.jsonOutput) {
    console.log('✓ Starting watch mode...\n');
  }

  await scan('Initial scan');
}
