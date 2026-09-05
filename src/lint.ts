/**
 * Lint mode — the author-side inversion of the scanner.
 *
 * Instead of a consumer scanning a server to decide whether to trust it,
 * this is an MCP server (or skill) AUTHOR running a linter on their own
 * tool descriptions before they publish — so they catch injected-looking
 * text, covert parameters, and shadowing claims in their own manifest and
 * fix them (or confirm they're intentional) before a consumer's scanner
 * flags them.
 *
 * Output is eslint-shaped: file:line, rule id, severity, message, the
 * offending text. Designed for a pre-commit hook / CI.
 */

import { readFileSync, existsSync, statSync, readdirSync } from "fs";
import { join, basename, relative } from "path";
import type { Pattern, Severity } from "./types.js";
import { loadPatterns } from "./pattern-loader.js";

export interface LintFinding {
  file: string;
  line: number;
  column: number;
  ruleId: string;
  severity: Severity;
  message: string;
  excerpt: string;
}

export interface LintResult {
  schemaVersion: string;
  tool: string;
  target: string;
  findings: LintFinding[];
  errorCount: number; // CRITICAL + HIGH
  warningCount: number; // MEDIUM + LOW + INFO
}

// The pattern packs that describe attack *grammar in text an agent reads* —
// exactly what an author controls in their own manifest. Deliberately NOT
// the code/dataflow packs: this lints authored descriptions, not runtime code.
const LINT_PATTERN_CATEGORIES = [
  "mcp-tool-poisoning",
  "mcp-shadowing",
  "prompt-injection",
  "frontmatter-injection",
  "unicode-obfuscation",
];

// Files whose authored text an author is responsible for.
const LINTABLE_MANIFESTS = ["mcp.json", "server.json"];
const LINTABLE_SKILL = "SKILL.md";

// Real MCP servers declare tool/parameter descriptions as string literals in
// source (`description: "..."` in TS/JS, `description="..."` in Python), not
// in a static manifest. To lint the surface an agent actually sees, we extract
// those description strings from source and lint each one at its real line.
const SOURCE_EXTS = [".ts", ".js", ".mjs", ".cjs", ".py"];
const DESCRIPTION_LITERAL =
  /\bdescription\s*[:=]\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`)/g;

interface DescriptionString {
  text: string; // the description content (unescaped enough for pattern matching)
  line: number; // line in the source file where it starts
  column: number;
}

function extractDescriptions(source: string): DescriptionString[] {
  const out: DescriptionString[] = [];
  let m: RegExpExecArray | null;
  DESCRIPTION_LITERAL.lastIndex = 0;
  while ((m = DESCRIPTION_LITERAL.exec(source)) !== null) {
    const raw = m[1] ?? m[2] ?? m[3] ?? "";
    const text = raw.replace(/\\(["'`\\])/g, "$1");
    const { line, column } = locate(source, m.index);
    out.push({ text, line, column });
  }
  return out;
}

async function lintPatterns(): Promise<Pattern[]> {
  const packs = await Promise.all(
    LINT_PATTERN_CATEGORIES.map((c) => loadPatterns(c)),
  );
  return packs.flat();
}

/**
 * Locate a byte offset as 1-based line/column.
 */
function locate(text: string, index: number): { line: number; column: number } {
  const before = text.slice(0, index);
  const line = before.split("\n").length;
  const column = index - before.lastIndexOf("\n");
  return { line, column };
}

function excerpt(text: string, index: number, matchLen: number): string {
  const lineStart = text.lastIndexOf("\n", index) + 1;
  let lineEnd = text.indexOf("\n", index);
  if (lineEnd === -1) lineEnd = text.length;
  const raw = text.slice(lineStart, lineEnd).trim();
  return raw.length > 120 ? raw.slice(0, 117) + "..." : raw;
}

/**
 * Run the lint patterns against one file's raw text.
 */
function lintText(text: string, fileLabel: string, patterns: Pattern[]): LintFinding[] {
  const findings: LintFinding[] = [];

  for (const pattern of patterns) {
    // Global match so we report every occurrence with its own location,
    // which is what an author needs to fix each one.
    const flags = pattern.match.flags?.includes("g")
      ? pattern.match.flags
      : (pattern.match.flags || "") + "g";
    let re: RegExp;
    try {
      re = new RegExp(pattern.match.value, flags);
    } catch {
      continue; // skip a malformed pattern rather than crash the lint
    }

    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const { line, column } = locate(text, m.index);
      findings.push({
        file: fileLabel,
        line,
        column,
        ruleId: pattern.id,
        severity: pattern.severity,
        message: `${pattern.name}: ${pattern.description || pattern.name}`,
        excerpt: excerpt(text, m.index, m[0].length),
      });
      if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loop
    }
  }

  // Stable order: by line, then severity weight.
  const weight: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  findings.sort((a, b) => a.line - b.line || weight[a.severity] - weight[b.severity]);
  return findings;
}

/**
 * Lint the description string literals extracted from a source file.
 */
function lintSource(source: string, fileLabel: string, patterns: Pattern[]): LintFinding[] {
  const findings: LintFinding[] = [];
  for (const desc of extractDescriptions(source)) {
    // Run each pattern against the description text; report at the source line.
    for (const finding of lintText(desc.text, fileLabel, patterns)) {
      findings.push({
        ...finding,
        line: desc.line,
        column: desc.column,
        excerpt: desc.text.length > 120 ? desc.text.slice(0, 117) + "..." : desc.text,
      });
    }
  }
  return findings;
}

type Target = { path: string; kind: "text" | "source" };

/**
 * Resolve which files to lint from a path. A manifest/SKILL.md is linted as
 * raw text; a source file has its description literals extracted and linted.
 * A directory is walked for both.
 */
function resolveTargets(inputPath: string): Target[] {
  if (!existsSync(inputPath)) {
    throw new Error(`Path not found: ${inputPath}`);
  }

  if (statSync(inputPath).isDirectory()) {
    const found: Target[] = [];
    for (const name of [...LINTABLE_MANIFESTS, LINTABLE_SKILL]) {
      const p = join(inputPath, name);
      if (existsSync(p)) found.push({ path: p, kind: "text" });
    }
    for (const p of walkSource(inputPath)) {
      found.push({ path: p, kind: "source" });
    }
    if (found.length === 0) {
      throw new Error(
        `Nothing to lint in ${inputPath} (looked for mcp.json, server.json, SKILL.md, or source files with tool descriptions)`,
      );
    }
    return found;
  }

  const base = basename(inputPath);
  if ([...LINTABLE_MANIFESTS, LINTABLE_SKILL].includes(base)) {
    return [{ path: inputPath, kind: "text" }];
  }
  if (SOURCE_EXTS.some((e) => base.endsWith(e))) {
    return [{ path: inputPath, kind: "source" }];
  }
  throw new Error(
    `Not a lintable file: ${base} (expected mcp.json, server.json, SKILL.md, or a .ts/.js/.py source file)`,
  );
}

/**
 * Recursively find source files under a directory, skipping noise dirs.
 */
function walkSource(dir: string): string[] {
  const out: string[] = [];
  const skip = new Set([
    "node_modules",
    "dist",
    "build",
    ".git",
    "coverage",
    "__pycache__",
    ".venv",
    "venv",
  ]);
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop()!;
    let entries: import("fs").Dirent[];
    try {
      entries = readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!skip.has(e.name)) stack.push(join(cur, e.name));
      } else if (
        SOURCE_EXTS.some((ext) => e.name.endsWith(ext)) &&
        !e.name.endsWith(".d.ts") &&
        !/\.(test|spec)\./.test(e.name)
      ) {
        out.push(join(cur, e.name));
      }
    }
  }
  return out;
}

/**
 * Lint a manifest/skill path (file or directory).
 */
export async function lint(inputPath: string): Promise<LintResult> {
  const patterns = await lintPatterns();
  const targets = resolveTargets(inputPath);

  const findings: LintFinding[] = [];
  for (const target of targets) {
    const text = readFileSync(target.path, "utf-8");
    const label = relative(process.cwd(), target.path) || basename(target.path);
    if (target.kind === "source") {
      findings.push(...lintSource(text, label, patterns));
    } else {
      findings.push(...lintText(text, label, patterns));
    }
  }

  const errorCount = findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH",
  ).length;
  const warningCount = findings.length - errorCount;

  return {
    schemaVersion: "1.0.0",
    tool: "acidtest-lint",
    target: inputPath,
    findings,
    errorCount,
    warningCount,
  };
}
