/**
 * Tests for the on-demand demo pack (Workstream C)
 */

import { describe, it, expect, afterEach } from "vitest";
import { existsSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { demoCases, materializeDemoPack } from "./demo-pack.js";
import { scanSkill } from "./scanner.js";
import { diffVersions } from "./diff.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

let cleanupFns: Array<() => void> = [];

afterEach(() => {
  for (const fn of cleanupFns) fn();
  cleanupFns = [];
});

describe("demo pack", () => {
  it("defines the four Q4-2026 attack classes", () => {
    const ids = demoCases().map((c) => c.id);
    expect(ids).toEqual([
      "tool-poisoned-mcp",
      "exfil-skill",
      "unicode-hidden",
      "rug-pull",
    ]);
  });

  it("materializes into a temp dir and cleans up", () => {
    const pack = materializeDemoPack();
    cleanupFns.push(pack.cleanup);

    expect(existsSync(pack.root)).toBe(true);
    for (const id of Object.keys(pack.paths)) {
      expect(existsSync(pack.paths[id])).toBe(true);
    }

    pack.cleanup();
    cleanupFns = [];
    expect(existsSync(pack.root)).toBe(false);
  });

  it("the tool-poisoned MCP server scans as DANGER", async () => {
    const pack = materializeDemoPack();
    cleanupFns.push(pack.cleanup);
    const result = await scanSkill(pack.paths["tool-poisoned-mcp"]);
    expect(result.status).toBe("DANGER");
    const ids = result.findings.map((f) => f.patternId);
    expect(ids).toContain("tp-001");
  });

  it("the exfil skill is flagged FAIL or DANGER with a python env dump", async () => {
    const pack = materializeDemoPack();
    cleanupFns.push(pack.cleanup);
    const result = await scanSkill(pack.paths["exfil-skill"]);
    expect(["FAIL", "DANGER"]).toContain(result.status);
    const ids = result.findings.map((f) => f.patternId);
    expect(ids).toContain("me-003");
  });

  it("the invisible-Unicode skill flags a CRITICAL tag-character finding", async () => {
    const pack = materializeDemoPack();
    cleanupFns.push(pack.cleanup);
    const result = await scanSkill(pack.paths["unicode-hidden"]);
    const critical = result.findings.filter(
      (f) => f.severity === "CRITICAL" && f.patternId === "uo-004",
    );
    expect(critical.length).toBeGreaterThan(0);
  });

  it("the rug-pull pair diffs to RUG_PULL", async () => {
    const pack = materializeDemoPack();
    cleanupFns.push(pack.cleanup);
    const diff = await diffVersions(
      join(pack.paths["rug-pull"], "v1"),
      join(pack.paths["rug-pull"], "v2"),
    );
    expect(diff.verdict).toBe("RUG_PULL");
    expect(diff.addedCapabilities).toContain("exec");
    expect(diff.addedCapabilities).toContain("network");
    expect(diff.addedCapabilities).toContain("credential-access");
  });

  it("does not write demo fixtures into the package tree", () => {
    // The generator writes only to the OS temp dir; the package must not
    // carry a test-fixtures or demo-fixtures directory that would ship.
    const pkgRoot = join(__dirname, "..");
    const entries = readdirSync(pkgRoot);
    expect(entries).not.toContain("demo-fixtures");
  });
});
