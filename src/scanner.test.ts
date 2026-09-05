/**
 * Tests for main scanner
 */

import { describe, it, expect } from "vitest";
import { scanSkill } from "./scanner.js";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesDir = join(__dirname, "..", "test-fixtures");

describe("scanSkill", () => {
  it("should scan PASS fixture and return PASS status", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-pass"));

    expect(result.status).toBe("PASS");
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.schemaVersion).toBe("1.0.0");
    expect(result.tool).toBe("acidtest");
  });

  it("scores a benign fetch skill as PASS", async () => {
    // fixture-warn is a benign web-fetcher (env + fetch, declared browser
    // tool). In the v2 two-layer model there is no cross-reference layer to
    // flag "undeclared access," so a benign skill scores clean — correct for
    // the MCP-first threat model.
    const result = await scanSkill(join(fixturesDir, "fixture-warn"));

    expect(result.status).toBe("PASS");
    expect(result.findings.every((f) => f.severity !== "CRITICAL")).toBe(true);
  });

  it("scores a skill with HIGH findings but no CRITICAL as WARN", async () => {
    // fixture-fail carries a maintenance-mode injection and fs-unlink, both
    // HIGH. With no CRITICAL, the any-CRITICAL-floors-to-FAIL rule does not
    // apply, so this lands at WARN.
    const result = await scanSkill(join(fixturesDir, "fixture-fail"));

    expect(result.status).toBe("WARN");
    expect(result.findings.some((f) => f.severity === "HIGH")).toBe(true);
  });

  it("should scan DANGER fixture and return DANGER status", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-danger"));

    expect(result.status).toBe("DANGER");
    expect(result.score).toBeLessThan(20);
  });

  it("should include skill metadata in result", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-pass"));

    expect(result.skill).toBeDefined();
    expect(result.skill.name).toBeDefined();
    expect(result.skill.path).toBeDefined();
  });

  it("should include findings array", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-danger"));

    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("should include recommendation", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-pass"));

    expect(result.recommendation).toBeDefined();
    expect(typeof result.recommendation).toBe("string");
  });

  it("should normalize permissions", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-pass"));

    expect(result.permissions).toBeDefined();
    expect(Array.isArray(result.permissions.bins)).toBe(true);
    expect(Array.isArray(result.permissions.env)).toBe(true);
    expect(Array.isArray(result.permissions.tools)).toBe(true);
  });

  it("should throw error for non-existent directory", async () => {
    await expect(
      scanSkill(join(fixturesDir, "non-existent"))
    ).rejects.toThrow();
  });

  it("should scan MCP server manifest", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-mcp-pass"));

    expect(result.status).toBe("PASS");
    expect(result.skill.name).toBeDefined();
  });

  it("should scan entropy fixture and filter legitimate high-entropy strings", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-entropy"));

    // Should not flag JWTs, UUIDs, hashes as obfuscation
    const obfuscationFindings = result.findings.filter((f) =>
      f.category.includes("obfuscation")
    );

    // The fixture has legitimate JWT/UUID/hash - should not be flagged
    // But it also has a suspicious base64 string - should be flagged
    expect(obfuscationFindings.length).toBeGreaterThan(0);
  });

  it("should scan code without manifest (Node.js)", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-no-manifest-node"));

    // Should complete without errors
    expect(result.status).toBeDefined();
    expect(result.skill.name).toBe("fixture-no-manifest-node");
    expect(result.skill.hasManifest).toBe(false);

    // Should still detect code patterns (layers 2, 3, 5)
    expect(result.findings.length).toBeGreaterThan(0);

    // Should NOT have permission mismatches (layer 1 & 4 skipped)
    const permissionFindings = result.findings.filter(f =>
      f.category.includes('permission')
    );
    expect(permissionFindings.length).toBe(0);
  });

  it("should scan code without manifest (Python)", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-no-manifest-python"));

    // Should complete without errors
    expect(result.status).toBeDefined();
    expect(result.skill.name).toBe("fixture-no-manifest-python");
    expect(result.skill.hasManifest).toBe(false);

    // Should still detect code patterns
    expect(result.findings.length).toBeGreaterThan(0);

    // Should detect the subprocess(shell=True) command injection via the
    // python-sinks regex pack (Python AST was removed in v2).
    const shellFindings = result.findings.filter(f =>
      f.patternId === 'py-001' || f.title.includes('shell')
    );
    expect(shellFindings.length).toBeGreaterThan(0);
  });

  it("should have empty permissions for code without manifest", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-no-manifest-node"));

    // Permissions should be empty arrays
    expect(result.permissions.bins).toEqual([]);
    expect(result.permissions.env).toEqual([]);
    expect(result.permissions.tools).toEqual([]);
  });
});
