/**
 * Tests for scoring engine
 */

import { describe, it, expect } from "vitest";
import {
  calculateScore,
  determineStatus,
  generateRecommendation,
  getSeverityCounts,
} from "./scoring.js";
import type { Finding } from "./types.js";

describe("calculateScore", () => {
  it("should start at 100 with no findings", () => {
    expect(calculateScore([])).toBe(100);
  });

  it("should deduct 25 points for CRITICAL", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "CRITICAL",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];
    expect(calculateScore(findings)).toBe(75); // 100 - 25
  });

  it("should deduct 15 points for HIGH", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "HIGH",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];
    expect(calculateScore(findings)).toBe(85); // 100 - 15
  });

  it("should deduct 8 points for MEDIUM", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "MEDIUM",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];
    expect(calculateScore(findings)).toBe(92); // 100 - 8
  });

  it("should deduct 3 points for LOW", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "LOW",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];
    expect(calculateScore(findings)).toBe(97); // 100 - 3
  });

  it("should deduct 0 points for INFO", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "INFO",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];
    expect(calculateScore(findings)).toBe(100); // 100 - 0
  });

  it("should cap deductions at 3 per unique pattern", () => {
    const findings: Finding[] = Array(10).fill({
      title: "Same Pattern",
      severity: "CRITICAL",
      category: "test",
      detail: "Test",
      patternId: "same-pattern",
      file: "test.ts",
        line: 1,
    });

    // Should only deduct 3 times: 3 * 25 = 75 points
    expect(calculateScore(findings)).toBe(25); // 100 - 75
  });

  it("should track different patterns separately", () => {
    const findings: Finding[] = [
      {
        title: "Pattern A",
        severity: "CRITICAL",
        category: "test",
        detail: "Test",
        patternId: "pattern-a",
        file: "test.ts",
        line: 1,
      },
      {
        title: "Pattern A",
        severity: "CRITICAL",
        category: "test",
        detail: "Test",
        patternId: "pattern-a",
        file: "test.ts",
        line: 2,
      },
      {
        title: "Pattern B",
        severity: "HIGH",
        category: "test",
        detail: "Test",
        patternId: "pattern-b",
        file: "test.ts",
        line: 3,
      },
    ];

    // Pattern A: 2 * 25 = 50
    // Pattern B: 1 * 15 = 15
    // Total: 65 deducted
    expect(calculateScore(findings)).toBe(35); // 100 - 65
  });

  it("should floor score at 0", () => {
    const findings: Finding[] = Array(10)
      .fill(null)
      .map((_, i) => ({
        title: `Pattern ${i}`,
        severity: "CRITICAL" as const,
        category: "test",
        detail: "Test",
        patternId: `pattern-${i}`,
        location: { file: "test.ts", line: i },
      }));

    // 10 different patterns * 25 = 250 deducted
    // Should floor at 0, not go negative
    expect(calculateScore(findings)).toBe(0);
  });

  it("should use title as fallback if patternId is missing", () => {
    const findings: Finding[] = [
      {
        title: "Same Title",
        severity: "CRITICAL",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
      {
        title: "Same Title",
        severity: "CRITICAL",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 2,
      },
    ];

    // Should treat both as same pattern: 2 * 25 = 50
    expect(calculateScore(findings)).toBe(50); // 100 - 50
  });
});

describe("determineStatus", () => {
  it("should return PASS for scores >= 80", () => {
    expect(determineStatus(100)).toBe("PASS");
    expect(determineStatus(80)).toBe("PASS");
  });

  it("should return WARN for scores 50-79", () => {
    expect(determineStatus(79)).toBe("WARN");
    expect(determineStatus(50)).toBe("WARN");
  });

  it("should return FAIL for scores 20-49", () => {
    expect(determineStatus(49)).toBe("FAIL");
    expect(determineStatus(20)).toBe("FAIL");
  });

  it("should return DANGER for scores < 20", () => {
    expect(determineStatus(19)).toBe("DANGER");
    expect(determineStatus(0)).toBe("DANGER");
  });

  it("floors a single CRITICAL finding to at least FAIL", () => {
    const oneCritical = [
      { severity: "CRITICAL", category: "mcp-exfil", title: "x", detail: "" },
    ] as any;
    // A high score that would otherwise be PASS/WARN is floored to FAIL
    expect(determineStatus(90, oneCritical)).toBe("FAIL");
    expect(determineStatus(72, oneCritical)).toBe("FAIL");
    // An already-low score stays where it is
    expect(determineStatus(30, oneCritical)).toBe("FAIL");
    expect(determineStatus(10, oneCritical)).toBe("DANGER");
  });

  it("escalates two or more CRITICAL findings to DANGER", () => {
    const twoCritical = [
      { severity: "CRITICAL", category: "mcp-exfil", title: "x", detail: "" },
      { severity: "CRITICAL", category: "tool-poisoning", title: "y", detail: "" },
    ] as any;
    expect(determineStatus(90, twoCritical)).toBe("DANGER");
  });

  it("does not floor when there is no CRITICAL", () => {
    const highsOnly = [
      { severity: "HIGH", category: "x", title: "x", detail: "" },
      { severity: "HIGH", category: "y", title: "y", detail: "" },
    ] as any;
    expect(determineStatus(60, highsOnly)).toBe("WARN");
    expect(determineStatus(85, highsOnly)).toBe("PASS");
  });
});

describe("generateRecommendation", () => {
  it("should warn about undeclared exfiltration", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "CRITICAL",
        category: "permission-mismatch",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];

    expect(generateRecommendation("DANGER", findings)).toBe(
      "Do not install. Undeclared data exfiltration detected."
    );
  });

  it("should warn about exfiltration in category", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "HIGH",
        category: "exfiltration-sinks",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];

    expect(generateRecommendation("FAIL", findings)).toBe(
      "Do not install. Undeclared data exfiltration detected."
    );
  });

  it("should warn about prompt injection", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "CRITICAL",
        category: "prompt-injection",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];

    expect(generateRecommendation("FAIL", findings)).toBe(
      "Do not install. Prompt injection attempt detected."
    );
  });

  it("should return DANGER message for DANGER status", () => {
    expect(generateRecommendation("DANGER", [])).toBe(
      "Do not install. Skill presents severe security risks."
    );
  });

  it("should return FAIL message for FAIL status", () => {
    expect(generateRecommendation("FAIL", [])).toBe(
      "Do not install without thorough review. Multiple security issues detected."
    );
  });

  it("should return WARN message for WARN status", () => {
    expect(generateRecommendation("WARN", [])).toBe(
      "Review recommended. Some security concerns detected."
    );
  });

  it("should return PASS message with no findings", () => {
    expect(generateRecommendation("PASS", [])).toBe(
      "Skill appears safe to install."
    );
  });

  it("should return PASS message with findings", () => {
    const findings: Finding[] = [
      {
        title: "Test",
        severity: "LOW",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
    ];

    expect(generateRecommendation("PASS", findings)).toBe(
      "Skill appears relatively safe, but review findings."
    );
  });
});

describe("getSeverityCounts", () => {
  it("should return zero counts for no findings", () => {
    const counts = getSeverityCounts([]);
    expect(counts).toEqual({
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    });
  });

  it("should count findings by severity", () => {
    const findings: Finding[] = [
      {
        title: "Test 1",
        severity: "CRITICAL",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 1,
      },
      {
        title: "Test 2",
        severity: "CRITICAL",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 2,
      },
      {
        title: "Test 3",
        severity: "HIGH",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 3,
      },
      {
        title: "Test 4",
        severity: "MEDIUM",
        category: "test",
        detail: "Test",
        file: "test.ts",
        line: 4,
      },
    ];

    const counts = getSeverityCounts(findings);
    expect(counts).toEqual({
      CRITICAL: 2,
      HIGH: 1,
      MEDIUM: 1,
      LOW: 0,
      INFO: 0,
    });
  });
});
