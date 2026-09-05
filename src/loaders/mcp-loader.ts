/**
 * MCP server manifest loader
 * Detects and parses MCP server configuration files
 */

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import type { SkillMetadata } from "../types.js";

/**
 * MCP manifest format types
 */
export type MCPManifestFormat =
  | "mcp.json"
  | "server.json"
  | "package.json"
  | "claude_desktop_config.json";

/**
 * Detected MCP manifest
 */
export interface MCPManifest {
  format: MCPManifestFormat;
  path: string;
  metadata: SkillMetadata;
  rawConfig: any;
}

/**
 * Detect if a directory contains an MCP server manifest
 * Returns the path to the manifest if found, otherwise null
 */
export function detectMCPManifest(directory: string): string | null {
  // Check for various MCP manifest files in order of preference
  const manifestFiles: MCPManifestFormat[] = [
    "mcp.json",
    "server.json",
    "package.json",
    "claude_desktop_config.json",
  ];

  for (const filename of manifestFiles) {
    const manifestPath = join(directory, filename);
    if (existsSync(manifestPath)) {
      // For package.json, verify it has MCP-related config
      if (filename === "package.json") {
        try {
          const content = JSON.parse(readFileSync(manifestPath, "utf-8"));
          if (content.mcp || content.mcpServers) {
            return manifestPath;
          }
        } catch {
          continue;
        }
      } else {
        return manifestPath;
      }
    }
  }

  return null;
}

/**
 * Parse an MCP manifest file
 */
export function parseMCPManifest(manifestPath: string): MCPManifest {
  const content = readFileSync(manifestPath, "utf-8");
  const rawConfig = JSON.parse(content);
  const filename = manifestPath.split("/").pop() as MCPManifestFormat;

  // Extract metadata based on format
  let metadata: SkillMetadata;

  if (filename === "mcp.json" || filename === "server.json") {
    metadata = extractFromMCPJson(rawConfig);
  } else if (filename === "package.json") {
    metadata = extractFromPackageJson(rawConfig);
  } else if (filename === "claude_desktop_config.json") {
    metadata = extractFromClaudeConfig(rawConfig);
  } else {
    throw new Error(`Unsupported MCP manifest format: ${filename}`);
  }

  return {
    format: filename,
    path: manifestPath,
    metadata,
    rawConfig,
  };
}

/**
 * Extract metadata from mcp.json or server.json
 */
function extractFromMCPJson(config: any): SkillMetadata {
  const metadata: SkillMetadata = {
    name: config.name || "unknown-mcp-server",
    description: config.description,
    version: config.version,
  };

  // Extract tools
  if (config.tools && Array.isArray(config.tools)) {
    metadata["allowed-tools"] = config.tools.map((tool: any) => {
      if (typeof tool === "string") return tool;
      return tool.name || "unknown-tool";
    });
  }

  // Extract environment variables
  if (config.env) {
    if (typeof config.env === "object") {
      metadata.env = Object.keys(config.env);
    } else if (Array.isArray(config.env)) {
      metadata.env = config.env;
    }
  }

  // Extract command/binary
  if (config.command) {
    metadata.bins = [config.command];

    // Add args that look like binaries
    if (config.args && Array.isArray(config.args)) {
      const binaryArgs = config.args.filter((arg: string) =>
        typeof arg === "string" && !arg.includes("/") && !arg.startsWith("-")
      );
      if (binaryArgs.length > 0) {
        metadata.bins = [...(metadata.bins || []), ...binaryArgs];
      }
    }
  }

  // Check transport for network implications
  if (config.transport === "sse") {
    // SSE implies network access
    metadata["allowed-tools"] = [
      ...(metadata["allowed-tools"] || []),
      "network",
    ];
  }

  return metadata;
}

/**
 * Extract metadata from package.json with MCP config
 */
function extractFromPackageJson(config: any): SkillMetadata {
  const metadata: SkillMetadata = {
    name: config.name || "unknown-mcp-server",
    description: config.description,
    version: config.version,
  };

  // Check for mcp config
  const mcpConfig = config.mcp || config.mcpServers;
  if (!mcpConfig) {
    return metadata;
  }

  // If mcpConfig is an object with server definitions
  if (typeof mcpConfig === "object" && !Array.isArray(mcpConfig)) {
    // Could be a direct config or a servers map
    if (mcpConfig.tools) {
      // Direct config
      return {
        ...metadata,
        ...extractFromMCPJson(mcpConfig),
      };
    } else {
      // Servers map - take the first server
      const firstServer = Object.values(mcpConfig)[0] as any;
      if (firstServer) {
        return {
          ...metadata,
          ...extractFromMCPJson(firstServer),
        };
      }
    }
  }

  return metadata;
}

/**
 * Extract metadata from claude_desktop_config.json
 */
function extractFromClaudeConfig(config: any): SkillMetadata {
  const metadata: SkillMetadata = {
    name: "claude-desktop-mcp-servers",
    description: "MCP servers from Claude Desktop config",
  };

  // Extract from mcpServers
  if (config.mcpServers && typeof config.mcpServers === "object") {
    const allTools: string[] = [];
    const allEnv: string[] = [];
    const allBins: string[] = [];

    // Combine all servers
    for (const [_serverName, serverConfig] of Object.entries(
      config.mcpServers,
    )) {
      const server = serverConfig as any;

      // Extract command
      if (server.command) {
        allBins.push(server.command);
      }

      // Extract env
      if (server.env && typeof server.env === "object") {
        allEnv.push(...Object.keys(server.env));
      }

      // Extract tools if present
      if (server.tools && Array.isArray(server.tools)) {
        allTools.push(
          ...server.tools.map((t: any) =>
            typeof t === "string" ? t : t.name || "unknown-tool",
          ),
        );
      }
    }

    if (allTools.length > 0) metadata["allowed-tools"] = [...new Set(allTools)];
    if (allEnv.length > 0) metadata.env = [...new Set(allEnv)];
    if (allBins.length > 0) metadata.bins = [...new Set(allBins)];
  }

  return metadata;
}
