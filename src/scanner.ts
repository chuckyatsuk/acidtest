/**
 * Main scanner orchestrator
 * Coordinates all five scanning layers
 */

import { readFileSync, existsSync, statSync } from "fs";
import { join, basename, extname, dirname } from "path";
import { glob } from "glob";
import matter from "gray-matter";
import type { Skill, CodeFile, ScanResult, Finding, SkillMetadata } from "./types.js";
import { scanPermissions } from "./layers/permissions.js";
import { scanInjection } from "./layers/injection.js";
import { scanCode } from "./layers/code.js";
import { scanCrossReference } from "./layers/crossref.js";
import { scanDataflow } from "./layers/dataflow.js";
import {
  calculateScore,
  determineStatus,
  generateRecommendation,
} from "./scoring.js";
import { detectMCPManifest, parseMCPManifest } from "./loaders/mcp-loader.js";
import { loadConfig, mergeConfig } from "./config.js";

const VERSION = "1.0.2";

/**
 * Main scan function
 * Scans a skill directory or SKILL.md file
 */
export async function scanSkill(skillPath: string, showProgress: boolean = false): Promise<ScanResult> {
  let spinner: any = null;

  // Show spinner only if requested (typically for CLI, not for tests)
  if (showProgress) {
    const ora = (await import('ora')).default;
    spinner = ora('Loading skill...').start();
  }

  // Load configuration
  const scanDirectory = resolveScanDirectory(skillPath);
  const userConfig = loadConfig(scanDirectory);
  const config = mergeConfig(userConfig);

  // Load the skill
  const skill = await loadSkill(skillPath, config.ignore?.files ?? []);

  // Run all five scanning layers
  if (spinner) spinner.text = 'Layer 1: Checking permissions...';
  const layer1 = await scanPermissions(skill);

  if (spinner) spinner.text = 'Layer 2: Detecting injection patterns...';
  const layer2 = await scanInjection(skill);

  if (spinner) spinner.text = 'Layer 3: Analyzing code...';
  const layer3 = await scanCode(skill);

  // Combine findings from layers 1-3 for cross-reference
  const previousFindings = [
    ...layer1.findings,
    ...layer2.findings,
    ...layer3.findings,
  ];

  if (spinner) spinner.text = 'Layer 4: Cross-referencing behaviors...';
  const layer4 = await scanCrossReference(skill, previousFindings);

  if (spinner) spinner.text = 'Layer 5: Analyzing dataflow...';
  const layer5 = await scanDataflow(skill);

  // Combine all findings
  let allFindings: Finding[] = [
    ...layer1.findings,
    ...layer2.findings,
    ...layer3.findings,
    ...layer4.findings,
    ...layer5.findings,
  ];

  // Apply ignore filters from config
  if (config.ignore?.patterns && config.ignore.patterns.length > 0) {
    allFindings = allFindings.filter(f =>
      !f.patternId || !config.ignore!.patterns!.includes(f.patternId)
    );
  }

  if (config.ignore?.categories && config.ignore.categories.length > 0) {
    allFindings = allFindings.filter(f =>
      !config.ignore!.categories!.includes(f.category)
    );
  }

  // Apply MCP-specific severity adjustments
  if (skill.isMCP) {
    allFindings = adjustFindingsForMCP(allFindings);
  }

  // Calculate score and status
  const score = calculateScore(allFindings);
  const status = determineStatus(score);
  const recommendation = generateRecommendation(status, allFindings);

  // Build result with normalized permissions
  const result: ScanResult = {
    schemaVersion: "1.0.0",
    tool: "acidtest",
    version: VERSION,
    skill: {
      name: skill.name,
      path: skill.path,
      hasManifest: skill.hasManifest,
    },
    score,
    status,
    permissions: normalizePermissions(skill.metadata),
    findings: allFindings,
    recommendation,
  };

  if (spinner) {
    spinner.succeed('Scan complete');
  }

  return result;
}

/**
 * Load a skill from a directory or SKILL.md file
 * Also supports MCP server manifests (mcp.json, server.json, package.json)
 * If no manifest found, creates minimal Skill object for code-only scanning
 */
async function loadSkill(skillPath: string, ignoreFileGlobs: string[] = []): Promise<Skill> {
  let skillDir: string;

  // Determine if path is a directory or file
  if (existsSync(skillPath) && statSync(skillPath).isDirectory()) {
    skillDir = skillPath;
  } else if (
    basename(skillPath) === "SKILL.md" ||
    basename(skillPath).endsWith(".json")
  ) {
    skillDir = dirname(skillPath);
  } else {
    throw new Error(
      "Path must be a skill/MCP directory or SKILL.md/manifest file",
    );
  }

  // Try to load as SKILL.md first (AgentSkills format)
  const skillMdPath = join(skillDir, "SKILL.md");
  if (existsSync(skillMdPath)) {
    return await loadAgentSkill(skillDir, skillMdPath, ignoreFileGlobs);
  }

  // Try to detect MCP manifest
  const mcpManifestPath = detectMCPManifest(skillDir);
  if (mcpManifestPath) {
    return await loadMCPServer(skillDir, mcpManifestPath, ignoreFileGlobs);
  }

  // No manifest found - create minimal Skill object for code-only scanning
  return await loadGenericCode(skillDir, ignoreFileGlobs);
}

/**
 * Load an AgentSkills format skill (SKILL.md)
 */
async function loadAgentSkill(
  skillDir: string,
  skillMdPath: string,
  ignoreFileGlobs: string[],
): Promise<Skill> {
  // Read and parse SKILL.md
  const skillContent = readFileSync(skillMdPath, "utf-8");
  const parsed = matter(skillContent);

  // Extract metadata and markdown
  const metadata = parsed.data;
  const markdownContent = parsed.content;

  // Determine skill name
  const skillName = metadata.name || basename(skillDir) || "unknown-skill";

  // Find all code files (.ts, .js, .mjs, .cjs)
  const codeFiles = await findCodeFiles(skillDir, ignoreFileGlobs);

  return {
    name: skillName,
    path: skillDir,
    metadata,
    markdownContent,
    codeFiles,
    hasManifest: true,
  };
}

/**
 * Load an MCP server manifest
 */
async function loadMCPServer(
  skillDir: string,
  manifestPath: string,
  ignoreFileGlobs: string[],
): Promise<Skill> {
  const manifest = parseMCPManifest(manifestPath);

  // Use the manifest content as markdown for scanning
  const markdownContent = JSON.stringify(manifest.rawConfig, null, 2);

  // Determine server name
  const serverName =
    manifest.metadata.name || basename(skillDir) || "unknown-mcp-server";

  // Find all code files
  const codeFiles = await findCodeFiles(skillDir, ignoreFileGlobs);

  return {
    name: serverName,
    path: skillDir,
    metadata: manifest.metadata,
    markdownContent,
    codeFiles,
    isMCP: true, // Flag this as an MCP server
    hasManifest: true,
  };
}

/**
 * Load generic code directory without manifest
 * Creates minimal Skill object to enable code-only scanning
 */
async function loadGenericCode(skillDir: string, ignoreFileGlobs: string[]): Promise<Skill> {
  // Use directory name as skill name
  const skillName = basename(skillDir) || "unknown-code";

  // Find all code files
  const codeFiles = await findCodeFiles(skillDir, ignoreFileGlobs);

  // Check for README.md to use as markdown content (optional)
  let markdownContent = "";
  const readmePath = join(skillDir, "README.md");
  if (existsSync(readmePath)) {
    try {
      markdownContent = readFileSync(readmePath, "utf-8");
    } catch (error) {
      // Ignore read errors
    }
  }

  return {
    name: skillName,
    path: skillDir,
    metadata: {}, // Empty metadata signals no manifest
    markdownContent,
    codeFiles,
    isMCP: false,
    hasManifest: false, // No manifest found
  };
}

/**
 * Normalize permissions to always have consistent structure
 */
function normalizePermissions(metadata: SkillMetadata): {
  bins: string[];
  env: string[];
  tools: string[];
} {
  // Handle bins
  let bins: string[] = [];
  if (metadata.bins) {
    bins = Array.isArray(metadata.bins) ? metadata.bins : [metadata.bins];
  }

  // Handle env
  let env: string[] = [];
  if (metadata.env) {
    env = Array.isArray(metadata.env) ? metadata.env : [metadata.env];
  }

  // Handle allowed-tools
  let tools: string[] = [];
  if (metadata["allowed-tools"]) {
    tools = Array.isArray(metadata["allowed-tools"])
      ? metadata["allowed-tools"]
      : [metadata["allowed-tools"]];
  }

  return { bins, env, tools };
}

/**
 * Find all code files in skill directory
 */
async function findCodeFiles(skillDir: string, ignoreFileGlobs: string[] = []): Promise<CodeFile[]> {
  const codeFiles: CodeFile[] = [];

  // Search for .ts, .js, .mjs, .cjs, .py files
  const patterns = [
    join(skillDir, "**/*.ts"),
    join(skillDir, "**/*.js"),
    join(skillDir, "**/*.mjs"),
    join(skillDir, "**/*.cjs"),
    join(skillDir, "**/*.py"),
  ];

  for (const pattern of patterns) {
    try {
      const files = await glob(pattern, {
        follow: false, // Don't follow symlinks outside the skill directory
        ignore: [
          "**/node_modules/**",
          "**/dist/**",
          "**/build/**",
          "**/__tests__/**",
          "**/tests/**",
          "**/test/**",
          "**/*.test.{js,ts,mjs,cjs}",
          "**/*.spec.{js,ts,mjs,cjs}",
          "**/*.d.ts", // Exclude TypeScript declaration files
          "**/fixtures/**",
          "**/examples/**",
          "**/.git/**",
          "**/.cache/**",
          "**/.next/**",
          "**/.nuxt/**",
          "**/.vite*/**",
          "**/coverage/**",
          "**/*.min.js",
          "**/*.min.mjs",
          "**/vendor/**",
          ...ignoreFileGlobs,
        ],
      });

      for (const filePath of files) {
        try {
          // Skip TypeScript declaration files (.d.ts)
          if (filePath.endsWith('.d.ts')) {
            continue;
          }

          // Skip test files
          if (filePath.includes('.spec.') || filePath.includes('.test.')) {
            continue;
          }

          const content = readFileSync(filePath, "utf-8");
          const ext = extname(filePath).slice(1); // Remove leading dot

          // Determine extension type
          let extension: "ts" | "js" | "mjs" | "cjs" | "py";
          if (ext === "ts") extension = "ts";
          else if (ext === "mjs") extension = "mjs";
          else if (ext === "cjs") extension = "cjs";
          else if (ext === "py") extension = "py";
          else extension = "js";

          codeFiles.push({
            path: filePath,
            content,
            extension,
          });
        } catch (error) {
          // Skip files that can't be read
          console.warn(`Warning: Could not read file: ${filePath}`);
        }
      }
    } catch (error) {
      // Log glob failures in debug mode but don't abort the scan
      if (process.env.ACIDTEST_DEBUG) {
        console.warn(`Warning: glob pattern failed: ${pattern}: ${(error as Error).message}`);
      }
    }
  }

  return codeFiles;
}

/**
 * Resolve skill directory from either directory or file path
 */
function resolveScanDirectory(skillPath: string): string {
  if (existsSync(skillPath) && statSync(skillPath).isDirectory()) {
    return skillPath;
  }
  return dirname(skillPath);
}

/**
 * Adjust finding severities for MCP servers
 * MCP servers are API clients and have different threat models than AgentSkills
 */
function adjustFindingsForMCP(findings: Finding[]): Finding[] {
  return findings.map(finding => {
    // Lower severity for legitimate API client patterns (by patternId)
    const mcpLegitimatePatternIds = [
      'ex-001',  // fetch-call - API clients make HTTP requests
      'cp-006',  // process-env-access - Need env vars for API keys
      'ob-001',  // base64-decode - Common for encoding
      'ex-006',  // http-url-literal - API endpoints are hardcoded
    ];

    if (mcpLegitimatePatternIds.includes(finding.patternId || '')) {
      // Reduce severity by one level for MCP servers
      if (finding.severity === 'MEDIUM') {
        return { ...finding, severity: 'LOW' as const };
      }
      if (finding.severity === 'LOW') {
        return { ...finding, severity: 'INFO' as const };
      }
    }

    return finding;
  });
}

/**
 * Scan multiple skills/MCP servers in a directory
 */
export async function scanAllSkills(directory: string): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  const scanned = new Set<string>(); // Track scanned directories to avoid duplicates

  // Find all SKILL.md files
  const skillPattern = join(directory, "**/SKILL.md");
  const skillFiles = await glob(skillPattern, {
    ignore: ["**/node_modules/**"],
  });

  for (const skillFile of skillFiles) {
    const skillDir = dirname(skillFile);
    if (scanned.has(skillDir)) continue;
    scanned.add(skillDir);

    try {
      const result = await scanSkill(skillFile);
      results.push(result);
    } catch (error) {
      console.warn(
        `Warning: Could not scan skill at ${skillFile}:`,
        (error as Error).message,
      );
    }
  }

  // Find all MCP manifest files
  const mcpPatterns = [
    join(directory, "**/mcp.json"),
    join(directory, "**/server.json"),
  ];

  for (const pattern of mcpPatterns) {
    const manifestFiles = await glob(pattern, {
      ignore: ["**/node_modules/**"],
    });

    for (const manifestFile of manifestFiles) {
      const manifestDir = dirname(manifestFile);
      if (scanned.has(manifestDir)) continue;
      scanned.add(manifestDir);

      try {
        const result = await scanSkill(manifestFile);
        results.push(result);
      } catch (error) {
        console.warn(
          `Warning: Could not scan MCP server at ${manifestFile}:`,
          (error as Error).message,
        );
      }
    }
  }

  return results;
}
