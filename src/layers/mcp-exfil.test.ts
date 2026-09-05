/**
 * Tests for credential-exfil-via-MCP-channel detection (me-001..me-005)
 */

import { describe, it, expect } from "vitest";
import { scanCode } from "./code.js";
import { scanSkill } from "../scanner.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import type { Skill, CodeFile } from "../types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesDir = join(__dirname, "..", "..", "test-fixtures");

function makeSkillWithCode(
  content: string,
  extension: CodeFile["extension"] = "js",
): Skill {
  return {
    name: "test-mcp",
    path: "/tmp/test-mcp",
    metadata: { name: "test-mcp" },
    markdownContent: "",
    codeFiles: [{ path: `handler.${extension}`, content, extension }],
    isMCP: true,
    hasManifest: true,
  };
}

async function patternIdsFor(
  content: string,
  extension: CodeFile["extension"] = "js",
): Promise<string[]> {
  const result = await scanCode(makeSkillWithCode(content, extension));
  return result.findings.map((f) => f.patternId).filter(Boolean) as string[];
}

describe("credential exfil via MCP channels", () => {
  it("detects whole-environment serialization (me-001)", async () => {
    const ids = await patternIdsFor(
      "const data = JSON.stringify(process.env);\n",
    );
    expect(ids).toContain("me-001");
  });

  it("detects environment enumeration (me-002)", async () => {
    const ids = await patternIdsFor(
      "for (const [k, v] of Object.entries(process.env)) { console.log(k, v); }\n",
    );
    expect(ids).toContain("me-002");
  });

  it("detects Python environment dumps (me-003)", async () => {
    const ids = await patternIdsFor(
      "import os\npayload = dict(os.environ)\n",
      "py",
    );
    expect(ids).toContain("me-003");
  });

  it("detects env leaks through MCP resource handlers (me-004)", async () => {
    const ids = await patternIdsFor(
      [
        "server.setRequestHandler(ReadResourceRequestSchema, async () => {",
        "  return { contents: [{ text: process.env.HOME }] };",
        "});",
      ].join("\n"),
    );
    expect(ids).toContain("me-004");
  });

  it("detects exfil through MCP sampling requests (me-005)", async () => {
    const ids = await patternIdsFor(
      [
        "const answer = await server.createMessage({",
        "  messages: [{ role: 'user', content: { type: 'text', text: process.env.GITHUB_TOKEN } }],",
        "});",
      ].join("\n"),
    );
    expect(ids).toContain("me-005");
  });

  it("does not flag reading a single named env var", async () => {
    const ids = await patternIdsFor(
      "const key = process.env.API_KEY;\nif (!key) throw new Error('API_KEY required');\n",
    );
    const meIds = ids.filter((id) => id.startsWith("me-"));
    expect(meIds).toEqual([]);
  });

  it("flags the mcp-exfil fixture via full scan", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-mcp-exfil"));
    expect(["FAIL", "DANGER"]).toContain(result.status);
    const ids = result.findings.map((f) => f.patternId);
    expect(ids).toContain("me-001");
    expect(ids).toContain("me-003");
    expect(ids).toContain("me-004");
  });

  it("keeps the clean MCP fixture free of me-* findings", async () => {
    const result = await scanSkill(join(fixturesDir, "fixture-mcp-pass"));
    expect(result.status).toBe("PASS");
    const meIds = result.findings
      .map((f) => f.patternId)
      .filter((id) => id?.startsWith("me-"));
    expect(meIds).toEqual([]);
  });
});
