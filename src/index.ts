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

const VERSION = "2.0.1";

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
  } else if (command === "diff") {
    await handleDiff(args.slice(1));
  } else if (command === "lint") {
    await handleLint(args.slice(1));
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
  const showFix = args.includes("--fix");
  const paths = args.filter((arg) => !arg.startsWith("--"));

  if (paths.length === 0) {
    console.error("Error: No path provided");
    console.error("Usage: acidtest scan <path> [--json] [--fix]");
    process.exit(1);
  }

  const skillPath = paths[0];

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
 * Handle 'diff' command
 * Compares two versions of a skill/MCP server for rug-pull updates
 */
async function handleDiff(args: string[]) {
  const jsonOutput = args.includes("--json");
  const paths = args.filter((arg) => !arg.startsWith("--"));

  if (paths.length < 2) {
    console.error("Error: diff needs two paths (old version, new version)");
    console.error("Usage: acidtest diff <old-version-path> <new-version-path> [--json]");
    process.exit(1);
  }

  const { diffVersions } = await import("./diff.js");

  try {
    const diff = await diffVersions(paths[0], paths[1]);

    if (jsonOutput) {
      console.log(JSON.stringify(diff, null, 2));
    } else {
      console.log(`\nAcidTest v${VERSION} — version diff`);
      console.log(`\nSkill:      ${diff.skill.name}`);
      console.log(`Old:        ${diff.oldPath} (score ${diff.oldScore}/100)`);
      console.log(`New:        ${diff.newPath} (score ${diff.newScore}/100)`);
      console.log(`\nVERDICT: ${diff.verdict}\n`);

      if (diff.findings.length === 0) {
        console.log("No new capabilities or permissions in the update.\n");
      } else {
        for (const finding of diff.findings) {
          console.log(`  [${finding.severity}] ${finding.title}`);
          console.log(`    ${finding.detail}`);
          if (finding.evidence) console.log(`    ${finding.evidence}`);
          console.log();
        }
      }
    }

    // Exit non-zero on a rug-pull so CI can gate on it
    if (diff.verdict === "RUG_PULL") {
      process.exit(1);
    }
  } catch (error) {
    console.error("Error diffing versions:", (error as Error).message);
    process.exit(1);
  }
}

/**
 * Handle 'lint' command
 * Author-side linter: checks the author's OWN manifest/skill for injected-
 * looking text, covert parameters, and shadowing claims before publishing.
 */
async function handleLint(args: string[]) {
  const jsonOutput = args.includes("--json");
  const quiet = args.includes("--quiet"); // errors only, suppress warnings
  const paths = args.filter((a) => !a.startsWith("--"));

  if (paths.length === 0) {
    console.error("Error: no path provided");
    console.error("Usage: acidtest lint <mcp.json|SKILL.md|dir> [--json] [--quiet]");
    process.exit(2);
  }

  const { lint } = await import("./lint.js");

  try {
    const result = await lint(paths[0]);

    if (jsonOutput) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      const chalk = (await import("chalk")).default;
      const shown = quiet
        ? result.findings.filter(
            (f) => f.severity === "CRITICAL" || f.severity === "HIGH",
          )
        : result.findings;

      if (shown.length === 0) {
        console.log(chalk.green("✓ clean — no injected-looking text in your descriptions"));
      } else {
        let currentFile = "";
        for (const f of shown) {
          if (f.file !== currentFile) {
            currentFile = f.file;
            console.log("\n" + chalk.underline(f.file));
          }
          const sev =
            f.severity === "CRITICAL" || f.severity === "HIGH"
              ? chalk.red(f.severity.toLowerCase())
              : chalk.yellow(f.severity.toLowerCase());
          const loc = chalk.dim(`${f.line}:${f.column}`);
          console.log(`  ${loc}  ${sev}  ${f.message}  ${chalk.dim(f.ruleId)}`);
          console.log(`         ${chalk.dim(f.excerpt)}`);
        }
        console.log(
          "\n" +
            chalk.bold(
              `${result.errorCount} error(s), ${result.warningCount} warning(s)`,
            ),
        );
        console.log(
          chalk.dim(
            "If a flag is a false alarm on legitimate wording, rephrase it or\n" +
              "confirm it's intentional — this is what a consumer's scanner will see.",
          ),
        );
      }
    }

    // Exit non-zero if any error-level finding, so CI / pre-commit gates.
    if (result.errorCount > 0) process.exit(1);
  } catch (error) {
    console.error("Error:", (error as Error).message);
    process.exit(2);
  }
}

/**
 * Handle 'demo' command
 * Generates the Q4-2026 attack-class demo pack on demand and walks it
 * with the real scanner. Fixtures are never shipped in the tarball.
 */
async function handleDemo(args: string[]) {
  const { demoCases, materializeDemoPack } = await import("./demo-pack.js");
  const { diffVersions } = await import("./diff.js");

  console.log("AcidTest Demo — Q4 2026 attack classes\n");
  console.log(
    "Fixtures are generated on demand into a temp directory and scanned\n" +
      "with the real scanner, then removed. Nothing is left on disk.\n",
  );

  const { paths, cleanup } = materializeDemoPack();
  const summary: Array<{ title: string; verdict: string }> = [];

  try {
    const cases = demoCases();
    for (let i = 0; i < cases.length; i++) {
      const demoCase = cases[i];
      console.log("\n" + "─".repeat(60) + "\n");
      console.log(`[${demoCase.title}]`);
      console.log(demoCase.about + "\n");

      if (demoCase.id === "rug-pull") {
        // Two-version case: diff v1 against v2.
        const diff = await diffVersions(
          join(paths[demoCase.id], "v1"),
          join(paths[demoCase.id], "v2"),
        );
        console.log(
          `  v1 score ${diff.oldScore}/100  →  v2 score ${diff.newScore}/100`,
        );
        console.log(`  VERDICT: ${diff.verdict}\n`);
        for (const finding of diff.findings) {
          console.log(`    [${finding.severity}] ${finding.title}`);
        }
        summary.push({ title: demoCase.title, verdict: diff.verdict });
      } else {
        const result = await scanSkill(paths[demoCase.id]);
        reportToTerminal(result);
        summary.push({
          title: demoCase.title,
          verdict: `${result.status} (${result.score}/100)`,
        });
      }
    }
  } finally {
    cleanup();
  }

  console.log("\n" + "=".repeat(60));
  console.log("\nDemo Summary:\n");
  for (const { title, verdict } of summary) {
    console.log(`  ${verdict.padEnd(16)} ${title}`);
  }
  console.log(
    "\nRun 'acidtest scan <path>' to scan your own skills and tools,",
  );
  console.log("or 'acidtest diff <old> <new>' to check an update for rug-pulls.");
  console.log("Docs and source: https://github.com/chuckyatsuk/acidtest\n");
}

/**
 * Handle 'serve' command
 * Starts AcidTest as an MCP server
 */
async function handleServe(args: string[]) {
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
  acidtest lint <path> [--json] [--quiet]
  acidtest scan <path> [--json] [--fix]
  acidtest scan-all <directory> [--json]
  acidtest diff <old-version> <new-version> [--json]
  acidtest demo
  acidtest serve
  acidtest --version
  acidtest --help

COMMANDS:
  lint          Lint your own MCP server's tool descriptions before publishing
  scan          Scan a single skill/MCP server (SKILL.md, mcp.json, etc.)
  scan-all      Recursively scan all skills/servers in a directory
  diff          Compare two versions of a skill for rug-pull updates
  demo          Run demo with built-in test fixtures
  serve         Start AcidTest as an MCP server for AI agents

OPTIONS:
  --json        Output results as JSON
  --fix         Show actionable remediation suggestions for findings
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

  # Scan all skills/servers in a directory
  acidtest scan-all ./directory

  # Start as MCP server (for use with Claude Desktop, etc.)
  acidtest serve

Docs and source: https://github.com/chuckyatsuk/acidtest
`);
}

// Run CLI
main().catch((error) => {
  console.error("Unexpected error:", error);
  process.exit(1);
});
