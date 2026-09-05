/**
 * Version-diff analysis ("rug-pull" detection)
 *
 * Compares two versions of the same skill or MCP server and flags
 * capability classes (network, exec, credential access, obfuscation)
 * that appear in the new version but were absent from the old one —
 * the signature of a benign-v1 / malicious-v2 rug-pull update.
 */

import { scanSkill } from "./scanner.js";
import type { Finding, ScanResult } from "./types.js";

export type CapabilityClass =
  | "network"
  | "exec"
  | "credential-access"
  | "obfuscation"
  | "injection";

export interface VersionDiff {
  schemaVersion: string;
  tool: string;
  skill: { name: string };
  oldPath: string;
  newPath: string;
  oldScore: number;
  newScore: number;
  addedPermissions: { bins: string[]; env: string[]; tools: string[] };
  addedCapabilities: CapabilityClass[];
  findings: Finding[];
  verdict: "CLEAN" | "SUSPICIOUS" | "RUG_PULL";
}

/**
 * Classify a finding into a coarse capability class.
 * Pattern-id prefixes are stable across the pattern set; AST findings
 * use their synthetic patternIds and categories.
 */
export function classifyFinding(finding: Finding): CapabilityClass | null {
  const id = finding.patternId || "";
  const category = finding.category || "";

  // Exec: code execution / dynamic loading
  if (
    /^(di|pyimp|pycall)-/.test(id) ||
    ["ast-eval", "ast-function-constructor", "ast-dynamic-require", "ast-string-concat"].includes(id) ||
    ["eval-usage", "function-constructor", "dynamic-require", "dangerous-calls", "string-concatenation"].includes(category)
  ) {
    return "exec";
  }

  // Network: outbound reach
  if (/^ex-/.test(id) || ["exfiltration-sinks", "network-urls"].includes(category)) {
    return "network";
  }

  // Credential access: secrets, sensitive paths, env harvesting
  if (
    /^(cp|sp|me)-/.test(id) ||
    ["credential-patterns", "sensitive-paths", "mcp-exfil"].includes(category)
  ) {
    return "credential-access";
  }

  // Obfuscation: hidden or encoded content
  if (/^(ob|uo)-/.test(id) || ["obfuscation", "unicode-obfuscation"].includes(category)) {
    return "obfuscation";
  }

  // Injection: instructions aimed at the agent
  if (
    /^(pi|tp|fm|cs)-/.test(id) ||
    ["prompt-injection", "tool-poisoning", "frontmatter-injection", "mcp-shadowing"].includes(category)
  ) {
    return "injection";
  }

  return null;
}

function capabilityClasses(result: ScanResult): Set<CapabilityClass> {
  const classes = new Set<CapabilityClass>();
  for (const finding of result.findings) {
    const cls = classifyFinding(finding);
    if (cls) classes.add(cls);
  }
  return classes;
}

/**
 * Is a capability class plausibly covered by the declared permissions?
 */
function isDeclared(cls: CapabilityClass, permissions: ScanResult["permissions"]): boolean {
  const tools = permissions.tools.map((t) => t.toLowerCase());
  const bins = permissions.bins.map((b) => b.toLowerCase());

  switch (cls) {
    case "network":
      return (
        tools.some((t) => ["network", "browser", "http", "fetch"].includes(t)) ||
        bins.some((b) => ["curl", "wget"].includes(b))
      );
    case "exec":
      return (
        tools.some((t) => ["shell", "exec", "bash"].includes(t)) ||
        bins.some((b) => ["sh", "bash", "zsh"].includes(b))
      );
    case "credential-access":
      return permissions.env.length > 0;
    default:
      // Obfuscation and injection are never legitimately "declared"
      return false;
  }
}

function added(oldList: string[], newList: string[]): string[] {
  const oldSet = new Set(oldList);
  return newList.filter((item) => !oldSet.has(item));
}

/**
 * Compare two versions of a skill/MCP server.
 */
export async function diffVersions(oldPath: string, newPath: string): Promise<VersionDiff> {
  const oldResult = await scanSkill(oldPath, false);
  const newResult = await scanSkill(newPath, false);

  const findings: Finding[] = [];

  // Newly declared permissions: transparent, but worth surfacing
  const addedPermissions = {
    bins: added(oldResult.permissions.bins, newResult.permissions.bins),
    env: added(oldResult.permissions.env, newResult.permissions.env),
    tools: added(oldResult.permissions.tools, newResult.permissions.tools),
  };

  for (const [kind, items] of Object.entries(addedPermissions)) {
    if (items.length > 0) {
      findings.push({
        severity: "LOW",
        category: "version-diff",
        title: `New declared ${kind} in update`,
        detail: `The new version declares ${kind} not present in the old version: ${items.join(", ")}`,
        evidence: "Review whether the new access is expected for this update",
      });
    }
  }

  // Capability classes present in the new version but absent from the old
  const oldClasses = capabilityClasses(oldResult);
  const newClasses = capabilityClasses(newResult);
  const addedCapabilities = [...newClasses].filter((cls) => !oldClasses.has(cls));

  for (const cls of addedCapabilities) {
    const declared = isDeclared(cls, newResult.permissions);
    const examples = newResult.findings
      .filter((f) => classifyFinding(f) === cls)
      .slice(0, 3)
      .map((f) => f.title);

    findings.push({
      severity: declared ? "HIGH" : "CRITICAL",
      category: "version-diff",
      title: `Update adds ${cls} capability`,
      detail: declared
        ? `The new version adds ${cls} behavior that the old version did not have (declared in permissions)`
        : `The new version adds ${cls} behavior that the old version did not have, and it is not covered by declared permissions`,
      evidence: `New findings: ${examples.join("; ")}`,
    });
  }

  // Verdict
  let verdict: VersionDiff["verdict"] = "CLEAN";
  if (findings.some((f) => f.severity === "CRITICAL")) {
    verdict = "RUG_PULL";
  } else if (findings.length > 0) {
    verdict = "SUSPICIOUS";
  }

  return {
    schemaVersion: "1.0.0",
    tool: "acidtest",
    skill: { name: newResult.skill.name },
    oldPath,
    newPath,
    oldScore: oldResult.score,
    newScore: newResult.score,
    addedPermissions,
    addedCapabilities,
    findings,
    verdict,
  };
}
