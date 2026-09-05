#!/usr/bin/env node

/**
 * AcidTest CLI entry point
 * Parses arguments and routes to appropriate commands
 */

import { scanSkill, scanAllSkills } from "./scanner.js";
import { reportToTerminal, reportAsJSON } from "./reporter.js";
import type { ErrorResult } from "./types.js";
import { loadConfig, mergeConfig } from "./config.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { spawn } from "child_process";

const VERSION = "1.0.2";

/**
 * Main CLI function
 */
async function main() {
  const args = process.argv.slice(2);

  // Handle --version flag
  if (args.includes("--version") || args.includes("-v")) {
    console.log(`acidtest v${VERSION}`);
    process.exit(0);
  }

  // Handle --help flag
  if (args.includes("--help") || args.includes("-h") || args.length === 0) {
    printHelp();
    process.exit(0);
  }

  // Parse command
  const command = args[0];

  if (command === "scan") {
    await handleScan(args.slice(1));
  } else if (command === "scan-all") {
    await handleScanAll(args.slice(1));
  } else if (command === "demo") {
    await handleDemo(args.slice(1));
  } else if (command === "serve") {
    await handleServe(args.slice(1));
  } else {
    console.error(`Unknown command: ${command}`);
    console.error('Run "acidtest --help" for usage information.');
    process.exit(1);
  }
}

/**
 * Handle 'scan' command
 */
async function handleScan(args: string[]) {
  // Parse flags
  const jsonOutput = args.includes("--json");
  const watchMode = args.includes("--watch") || args.includes("-w");
  const noClear = args.includes("--no-clear");
  const showFix = args.includes("--fix");
  const paths = args.filter((arg) => !arg.startsWith("--") && arg !== "-w");

  if (paths.length === 0) {
    console.error("Error: No skill path provided");
    console.error("Usage: acidtest scan <path-to-skill> [--json] [--watch]");
    process.exit(1);
  }

  const skillPath = paths[0];

  // Handle watch mode
  if (watchMode) {
    const { watchMode: startWatchMode } = await import('./watch.js');
    await startWatchMode(skillPath, { noClear, jsonOutput, showRemediation: showFix });
    return; // Watch mode handles its own exit
  }

  try {
    // Load config from skill directory
    const userConfig = loadConfig(skillPath);
    const config = mergeConfig(userConfig);

    // Show progress spinner for CLI scans (not for JSON output)
    const result = await scanSkill(skillPath, !jsonOutput);

    if (jsonOutput) {
      reportAsJSON(result);
    } else {
      // CLI flags override config
      const showRemediation = showFix || (config.output?.showRemediation ?? false);
      reportToTerminal(result, { showRemediation });
    }

    // Apply threshold checks from config
    let shouldFail = result.status === "FAIL" || result.status === "DANGER";

    // Check minScore threshold
    if (config.thresholds?.minScore && result.score < config.thresholds.minScore) {
      shouldFail = true;
    }

    // Check failOn severity threshold
    if (config.thresholds?.failOn && config.thresholds.failOn.length > 0) {
      const hasFailSeverity = result.findings.some(f =>
        config.thresholds!.failOn!.includes(f.severity)
      );
      if (hasFailSeverity) {
        shouldFail = true;
      }
    }

    if (shouldFail) {
      process.exit(1);
    }
  } catch (error) {
    if (jsonOutput) {
      // Output error as JSON for programmatic use
      const errorResult: ErrorResult = {
        schemaVersion: "1.0.0",
        tool: "acidtest",
        version: VERSION,
        status: "ERROR",
        error: (error as Error).message,
      };
      console.log(JSON.stringify(errorResult, null, 2));
    } else {
      console.error("Error scanning skill:", (error as Error).message);
    }
    process.exit(1);
  }
}

/**
 * Handle 'scan-all' command
 */
async function handleScanAll(args: string[]) {
  // Parse flags
  const jsonOutput = args.includes("--json");
  const paths = args.filter((arg) => !arg.startsWith("--"));

  if (paths.length === 0) {
    console.error("Error: No directory path provided");
    console.error("Usage: acidtest scan-all <directory> [--json]");
    process.exit(1);
  }

  const directory = paths[0];

  try {
    const results = await scanAllSkills(directory);

    if (results.length === 0) {
      console.log("No skills found in directory");
      process.exit(0);
    }

    if (jsonOutput) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      // Print summary for each skill
      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        reportToTerminal(result);

        // Add separator between skills (except for last one)
        if (i < results.length - 1) {
          console.log("\n" + "=".repeat(60) + "\n");
        }
      }

      // Print summary statistics
      console.log("\n" + "=".repeat(60));
      console.log(`\nScanned ${results.length} skill(s):\n`);

      const pass = results.filter((r) => r.status === "PASS").length;
      const warn = results.filter((r) => r.status === "WARN").length;
      const fail = results.filter((r) => r.status === "FAIL").length;
      const danger = results.filter((r) => r.status === "DANGER").length;

      if (pass > 0) console.log(`  PASS:   ${pass}`);
      if (warn > 0) console.log(`  WARN:   ${warn}`);
      if (fail > 0) console.log(`  FAIL:   ${fail}`);
      if (danger > 0) console.log(`  DANGER: ${danger}`);

      console.log();
    }

    // Exit with non-zero if any skill failed
    const hasFailures = results.some(
      (r) => r.status === "FAIL" || r.status === "DANGER",
    );

    if (hasFailures) {
      process.exit(1);
    }
  } catch (error) {
    if (jsonOutput) {
      // Output error as JSON for programmatic use
      const errorResult: ErrorResult = {
        schemaVersion: "1.0.0",
        tool: "acidtest",
        version: VERSION,
        status: "ERROR",
        error: (error as Error).message,
      };
      console.log(JSON.stringify(errorResult, null, 2));
    } else {
      console.error("Error scanning directory:", (error as Error).message);
    }
    process.exit(1);
  }
}

/**
 * Handle 'demo' command
 * Runs built-in test fixtures to show the full output spectrum
 */
async function handleDemo(_args: string[]) {
  console.log("AcidTest Demo - Running built-in test fixtures...\n");

  // Find fixtures directory relative to this file
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const fixturesDir = join(__dirname, "..", "test-fixtures");

  const fixtures = [
    { name: "PASS", path: join(fixturesDir, "fixture-pass") },
    { name: "WARN", path: join(fixturesDir, "fixture-warn") },
    { name: "FAIL", path: join(fixturesDir, "fixture-fail") },
    { name: "DANGER", path: join(fixturesDir, "fixture-danger") },
  ];

  const results = [];

  for (let i = 0; i < fixtures.length; i++) {
    const fixture = fixtures[i];

    try {
      const result = await scanSkill(fixture.path);
      results.push({ fixture: fixture.name, result });

      console.log(`[${ fixture.name } Example]`);
      reportToTerminal(result);

      if (i < fixtures.length - 1) {
        console.log("\n" + "─".repeat(60) + "\n");
      }
    } catch (error) {
      console.warn(
        `Warning: Could not scan ${fixture.name} fixture:`,
        (error as Error).message,
      );
    }
  }

  // Print summary
  console.log("\n" + "=".repeat(60));
  console.log("\nDemo Summary:");
  console.log(
    "AcidTest provides four security levels based on trust score (0-100):\n",
  );

  for (const { result } of results) {
    console.log(
      `  ${result.status.padEnd(6)} (${result.score}/100) - ${getStatusDescription(result.status)}`,
    );
  }

  console.log(
    "\nRun 'acidtest scan <path>' to scan your own skills and tools.",
  );
  console.log("For more information, visit: https://acidtest.dev\n");
}

/**
 * Get status description for demo summary
 */
function getStatusDescription(status: string): string {
  switch (status) {
    case "PASS":
      return "Safe to use, no significant security concerns";
    case "WARN":
      return "Review findings before use, minor concerns";
    case "FAIL":
      return "Not recommended, significant security issues";
    case "DANGER":
      return "Do not use, critical security vulnerabilities";
    default:
      return "Unknown status";
  }
}

/**
 * Handle 'serve' command
 * Starts AcidTest as an MCP server
 */
async function handleServe(_args: string[]) {
  // Find the mcp-server.js file relative to this file
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const mcpServerPath = join(__dirname, "mcp-server.js");

  // Start the MCP server as a child process
  const mcpServer = spawn("node", [mcpServerPath], {
    stdio: "inherit", // Inherit stdin/stdout/stderr for MCP protocol
  });

  // Handle process termination
  mcpServer.on("exit", (code) => {
    process.exit(code || 0);
  });

  // Handle errors
  mcpServer.on("error", (error) => {
    console.error("Failed to start MCP server:", error.message);
    process.exit(1);
  });
}

/**
 * Print help text
 */
function printHelp() {
  console.log(`
AcidTest v${VERSION}
Security scanner for AI agent skills and MCP servers

USAGE:
  acidtest scan <path> [--json] [--watch] [--fix] [--no-clear]
  acidtest scan-all <directory> [--json]
  acidtest demo
  acidtest serve
  acidtest --version
  acidtest --help

COMMANDS:
  scan          Scan a single skill/MCP server (SKILL.md, mcp.json, etc.)
  scan-all      Recursively scan all skills/servers in a directory
  demo          Run demo with built-in test fixtures
  serve         Start AcidTest as an MCP server for AI agents

OPTIONS:
  --json        Output results as JSON
  --watch, -w   Watch for file changes and re-scan automatically
  --fix         Show actionable remediation suggestions for findings
  --no-clear    Don't clear terminal between scans (watch mode only)
  --version     Print version number
  --help        Show this help message

EXAMPLES:
  # See AcidTest in action with demo fixtures
  acidtest demo

  # Scan an AgentSkills skill
  acidtest scan ./my-skill

  # Scan an MCP server
  acidtest scan ./my-mcp-server

  # Scan with JSON output
  acidtest scan ./my-skill --json

  # Show remediation suggestions for findings
  acidtest scan ./my-skill --fix

  # Watch for changes and re-scan automatically
  acidtest scan ./my-skill --watch

  # Scan all skills/servers in a directory
  acidtest scan-all ./directory

  # Start as MCP server (for use with Claude Desktop, etc.)
  acidtest serve

For more information, visit: https://acidtest.dev
`);
}

// Run CLI
main().catch((error) => {
  console.error("Unexpected error:", error);
  process.exit(1);
});
