/**
 * Layer 1: Permission Audit
 * Analyzes YAML frontmatter to identify requested permissions and assess risk
 */

import type { Skill, Finding, LayerResult } from '../types.js';
import { loadPatterns } from '../pattern-loader.js';

/**
 * Scan skill permissions from YAML frontmatter
 */
export async function scanPermissions(skill: Skill): Promise<LayerResult> {
  const findings: Finding[] = [];
  const metadata = skill.metadata;

  // Skip permission audit if no manifest found (empty metadata)
  if (!skill.hasManifest || Object.keys(metadata).length === 0) {
    return {
      layer: 'permissions',
      findings: [] // Empty findings array, no error
    };
  }

  // Load credential patterns for environment variable scanning
  const credentialPatterns = await loadPatterns('credential-patterns');

  // Check for no declared permissions (suspicious)
  // Skip this check for MCP servers as they don't use the same permission model
  if (!skill.isMCP && !metadata.bins && !metadata.env && !metadata['allowed-tools']) {
    findings.push({
      severity: 'LOW',
      category: 'permissions',
      title: 'No declared permissions',
      file: 'SKILL.md',
      detail: 'Skill declares no permissions (bins, env, or allowed-tools)',
      evidence: 'Legitimate skills typically declare at least one permission'
    });
  }

  // Scan environment variables for credential patterns
  if (metadata.env && Array.isArray(metadata.env)) {
    for (const envVar of metadata.env) {
      for (const pattern of credentialPatterns) {
        if (pattern.layer !== 'permissions') continue;

        const regex = new RegExp(pattern.match.value, pattern.match.flags);
        if (regex.test(envVar)) {
          findings.push({
            severity: pattern.severity,
            category: 'credential-request',
            title: pattern.name,
            file: 'SKILL.md',
            detail: `Requests credential environment variable: ${envVar}`,
            evidence: pattern.description,
            patternId: pattern.id,
            ...(pattern.remediation && { remediation: pattern.remediation })
          });
        }
      }
    }
  }

  // Check allowed-tools for dangerous permissions
  if (metadata['allowed-tools'] && Array.isArray(metadata['allowed-tools'])) {
    const tools = metadata['allowed-tools'];

    // Check for shell/command execution
    const shellTools = ['shell', 'bash', 'exec', 'command'];
    const hasShell = tools.some(tool =>
      shellTools.some(shellTool => tool.toLowerCase().includes(shellTool))
    );

    if (hasShell) {
      findings.push({
        severity: 'CRITICAL',
        category: 'dangerous-permission',
        title: 'Shell execution permission',
        file: 'SKILL.md',
        detail: 'Skill requests shell/command execution capability',
        evidence: `Allowed tools: ${tools.filter(t => shellTools.some(st => t.toLowerCase().includes(st))).join(', ')}`
      });
    }

    // Check for network access
    const networkTools = ['browser', 'http', 'fetch', 'network', 'web', 'curl', 'wget'];
    const hasNetwork = tools.some(tool =>
      networkTools.some(netTool => tool.toLowerCase().includes(netTool))
    );

    if (hasNetwork) {
      findings.push({
        severity: 'HIGH',
        category: 'network-permission',
        title: 'Network access permission',
        file: 'SKILL.md',
        detail: 'Skill requests network/HTTP access capability',
        evidence: `Allowed tools: ${tools.filter(t => networkTools.some(nt => t.toLowerCase().includes(nt))).join(', ')}`
      });
    }

    // Check for file system access
    const fsTools = ['file', 'filesystem', 'fs', 'read', 'write'];
    const hasFileSystem = tools.some(tool =>
      fsTools.some(fsTool => tool.toLowerCase().includes(fsTool))
    );

    if (hasFileSystem) {
      findings.push({
        severity: 'MEDIUM',
        category: 'filesystem-permission',
        title: 'File system access permission',
        file: 'SKILL.md',
        detail: 'Skill requests file system access capability',
        evidence: `Allowed tools: ${tools.filter(t => fsTools.some(ft => t.toLowerCase().includes(ft))).join(', ')}`
      });
    }
  }

  // Check for dangerous system binaries
  if (metadata.bins && Array.isArray(metadata.bins)) {
    const dangerousBins = [
      { pattern: /^(bash|sh|zsh|fish|cmd|powershell)$/i, severity: 'CRITICAL' as const, reason: 'Shell interpreter' },
      { pattern: /^(curl|wget|fetch)$/i, severity: 'HIGH' as const, reason: 'Network download tool' },
      { pattern: /^(nc|netcat|ncat)$/i, severity: 'CRITICAL' as const, reason: 'Network connection tool' },
      { pattern: /^(python|node|ruby|perl|php)$/i, severity: 'HIGH' as const, reason: 'Script interpreter' },
      { pattern: /^(docker|kubectl|podman)$/i, severity: 'HIGH' as const, reason: 'Container management' },
      { pattern: /^(ssh|scp|sftp)$/i, severity: 'HIGH' as const, reason: 'Remote access tool' },
      { pattern: /^(git)$/i, severity: 'MEDIUM' as const, reason: 'Version control (can clone arbitrary repos)' }
    ];

    for (const bin of metadata.bins) {
      for (const dangerous of dangerousBins) {
        if (dangerous.pattern.test(bin)) {
          findings.push({
            severity: dangerous.severity,
            category: 'dangerous-binary',
            title: `Dangerous binary: ${bin}`,
            file: 'SKILL.md',
            detail: `Requests access to system binary: ${bin}`,
            evidence: dangerous.reason
          });
        }
      }
    }
  }

  return {
    layer: 'permissions',
    findings
  };
}
