#!/usr/bin/env node

/**
 * AcidTest MCP Server
 * Exposes AcidTest scanning as an MCP tool for AI agents
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { scanSkill, scanAllSkills } from "./scanner.js";

const VERSION = "2.0.0";

/**
 * Create and configure the MCP server
 */
function createServer() {
  const server = new Server(
    {
      name: "acidtest",
      version: VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  /**
   * List available tools
   */
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "scan_skill",
          description:
            "Scan an AI agent skill or MCP server for security vulnerabilities. Returns a trust score (0-100) and detailed findings across four security layers: permissions audit, prompt injection detection, code analysis, and cross-reference validation.",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description:
                  "Path to the skill directory, SKILL.md file, or MCP server manifest (mcp.json, server.json, package.json)",
              },
            },
            required: ["path"],
          },
        },
        {
          name: "scan_all",
          description:
            "Recursively scan all skills and MCP servers in a directory. Returns an array of scan results with trust scores and findings for each skill/server found.",
          inputSchema: {
            type: "object",
            properties: {
              directory: {
                type: "string",
                description: "Path to the directory containing skills/servers",
              },
            },
            required: ["directory"],
          },
        },
      ],
    };
  });

  /**
   * Handle tool calls
   */
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      if (name === "scan_skill") {
        // Validate arguments
        if (!args || typeof args !== "object" || !("path" in args)) {
          return {
            content: [
              {
                type: "text",
                text: "Error: Missing required argument 'path'",
              },
            ],
            isError: true,
          };
        }

        const path = args.path as string;

        // Run scan
        const result = await scanSkill(path);

        // Return result as JSON
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } else if (name === "scan_all") {
        // Validate arguments
        if (!args || typeof args !== "object" || !("directory" in args)) {
          return {
            content: [
              {
                type: "text",
                text: "Error: Missing required argument 'directory'",
              },
            ],
            isError: true,
          };
        }

        const directory = args.directory as string;

        // Run scan
        const results = await scanAllSkills(directory);

        // Return results as JSON
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(results, null, 2),
            },
          ],
        };
      } else {
        return {
          content: [
            {
              type: "text",
              text: `Error: Unknown tool '${name}'`,
            },
          ],
          isError: true,
        };
      }
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${(error as Error).message}`,
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * Start the MCP server
 */
async function main() {
  const server = createServer();
  const transport = new StdioServerTransport();

  await server.connect(transport);

  // Log to stderr (stdout is reserved for MCP protocol)
  console.error(`AcidTest MCP Server v${VERSION} running on stdio`);
}

// Start server
main().catch((error) => {
  console.error("Fatal error in MCP server:", error);
  process.exit(1);
});
