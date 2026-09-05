/**
 * Tests for version-diff / rug-pull detection
 */

import { describe, it, expect } from "vitest";
import { diffVersions, classifyFinding } from "./diff.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesDir = join(__dirname, "..", "test-fixtures");

const v1 = join(fixturesDir, "fixture-rugpull-v1");
const v2 = join(fixturesDir, "fixture-rugpull-v2");

describe("classifyFinding", () => {
  it("classifies by patternId prefix", () => {
    expect(classifyFinding({ patternId: "ex-001", severity: "MEDIUM", category: "x", title: "", detail: "" })).toBe("network");
    expect(classifyFinding({ patternId: "di-002", severity: "HIGH", category: "x", title: "", detail: "" })).toBe("exec");
    expect(classifyFinding({ patternId: "cp-003", severity: "HIGH", category: "x", title: "", detail: "" })).toBe("credential-access");
    expect(classifyFinding({ patternId: "uo-004", severity: "HIGH", category: "x", title: "", detail: "" })).toBe("obfuscation");
    expect(classifyFinding({ patternId: "tp-002", severity: "HIGH", category: "x", title: "", detail: "" })).toBe("injection");
  });

  it("returns null for unclassifiable findings", () => {
    expect(classifyFinding({ severity: "INFO", category: "parse-error", title: "", detail: "" })).toBeNull();
  });
});

describe("diffVersions (rug-pull detection)", () => {
  it("flags the benign→malicious fixture pair as RUG_PULL", async () => {
    const diff = await diffVersions(v1, v2);

    expect(diff.verdict).toBe("RUG_PULL");
    expect(diff.addedCapabilities).toContain("network");
    expect(diff.addedCapabilities).toContain("exec");
    expect(diff.addedCapabilities).toContain("credential-access");

    const critical = diff.findings.filter((f) => f.severity === "CRITICAL");
    expect(critical.length).toBeGreaterThan(0);
  });

  it("reports the score change between versions", async () => {
    const diff = await diffVersions(v1, v2);
    expect(diff.oldScore).toBeGreaterThan(diff.newScore);
  });

  it("reports CLEAN when a version is compared with itself", async () => {
    const diff = await diffVersions(v1, v1);
    expect(diff.verdict).toBe("CLEAN");
    expect(diff.addedCapabilities).toEqual([]);
    expect(diff.findings).toEqual([]);
  });

  it("keeps v1 scoring as a passing skill", async () => {
    const diff = await diffVersions(v1, v2);
    expect(diff.oldScore).toBeGreaterThanOrEqual(80);
  });
});
