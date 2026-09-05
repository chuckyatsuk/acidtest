/**
 * Layer 4: Cross-Reference Analysis
 * Compares findings across layers to detect permission mismatches and deception
 */

import type { Skill, Finding, LayerResult, CodeFile } from '../types.js';

/**
 * Cross-reference findings from previous layers
 */
export async function scanCrossReference(
  skill: Skill,
  previousFindings: Finding[]
): Promise<LayerResult> {
  const findings: Finding[] = [];
  const metadata = skill.metadata;

  // Skip cross-reference if no manifest found (empty metadata)
  if (!skill.hasManifest || Object.keys(metadata).length === 0) {
    return {
      layer: 'crossref',
      findings: [] // Empty findings array, no error
    };
  }

  // Extract findings by category
  const networkFindings = previousFindings.filter(f =>
    f.category.includes('network') ||
    f.category === 'exfiltration-sinks' ||
    f.patternId?.startsWith('ex-')
  );

  const shellFindings = previousFindings.filter(f =>
    f.category.includes('child_process') ||
    f.category.includes('shell') ||
    f.patternId === 'di-001'
  );

  const fileSystemFindings = previousFindings.filter(f =>
    f.category.includes('filesystem') ||
    f.category.includes('sensitive-paths') ||
    f.patternId?.startsWith('sp-')
  );

  const envAccessFindings = previousFindings.filter(f =>
    f.patternId === 'cp-006' // process.env access
  );

  // Get declared permissions
  const allowedTools = metadata['allowed-tools'] || [];
  const allowedBins = metadata.bins || [];
  const allowedEnv = metadata.env || [];

  // Check for network capability mismatches
  // Skip for MCP servers - they are API clients by design and expected to make network calls
  if (networkFindings.length > 0 && !skill.isMCP) {
    const declaredNetwork = allowedTools.some(tool =>
      ['browser', 'http', 'fetch', 'network', 'web', 'curl', 'wget'].some(net =>
        tool.toLowerCase().includes(net)
      )
    ) || allowedBins.some(bin =>
      ['curl', 'wget'].some(net => bin.toLowerCase().includes(net))
    );

    if (!declaredNetwork) {
      findings.push({
        severity: 'CRITICAL',
        category: 'permission-mismatch',
        title: 'Undeclared network access',
        detail: 'Code makes network calls but skill does not declare network permissions',
        evidence: `Found ${networkFindings.length} network-related finding(s) in code`
      });
    }
  }

  // Check for shell execution mismatches
  if (shellFindings.length > 0) {
    const declaredShell = allowedTools.some(tool =>
      ['shell', 'bash', 'exec', 'command'].some(sh =>
        tool.toLowerCase().includes(sh)
      )
    ) || allowedBins.some(bin =>
      ['bash', 'sh', 'zsh', 'fish', 'cmd', 'powershell'].some(sh =>
        bin.toLowerCase() === sh
      )
    );

    if (!declaredShell) {
      findings.push({
        severity: 'CRITICAL',
        category: 'permission-mismatch',
        title: 'Undeclared shell execution',
        detail: 'Code executes shell commands but skill does not declare shell permissions',
        evidence: `Found ${shellFindings.length} shell-related finding(s) in code`
      });
    }
  }

  // Check for file system access mismatches
  // Skip for MCP servers - they may need limited filesystem access for caching
  if (fileSystemFindings.length > 0 && !skill.isMCP) {
    const declaredFS = allowedTools.some(tool =>
      ['file', 'filesystem', 'fs', 'read', 'write'].some(fs =>
        tool.toLowerCase().includes(fs)
      )
    );

    if (!declaredFS) {
      findings.push({
        severity: 'HIGH',
        category: 'permission-mismatch',
        title: 'Undeclared file system access',
        detail: 'Code accesses sensitive file paths but skill does not declare filesystem permissions',
        evidence: `Found ${fileSystemFindings.length} filesystem-related finding(s) in code`
      });
    }
  }

  // Check for environment variable mismatches
  // Skip for MCP servers - they commonly use env vars for API keys
  if (envAccessFindings.length > 0 && skill.codeFiles.length > 0 && !skill.isMCP) {
    // Extract environment variables accessed in code
    const codeEnvVars = extractEnvVarsFromCode(skill.codeFiles);

    // Find undeclared env vars
    const undeclaredEnvVars = codeEnvVars.filter(
      envVar => !allowedEnv.includes(envVar)
    );

    if (undeclaredEnvVars.length > 0) {
      findings.push({
        severity: 'HIGH',
        category: 'permission-mismatch',
        title: 'Undeclared environment variable access',
        detail: 'Code accesses environment variables not declared in skill metadata',
        evidence: `Undeclared variables: ${undeclaredEnvVars.slice(0, 5).join(', ')}${undeclaredEnvVars.length > 5 ? '...' : ''}`
      });
    }
  }

  // Check for deception indicators
  const description = (metadata.description || '').toLowerCase();
  const benignKeywords = ['calculator', 'timer', 'note', 'reminder', 'formatter', 'converter'];
  const seemsBenign = benignKeywords.some(kw => description.includes(kw));

  if (seemsBenign && networkFindings.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'deception-indicator',
      title: 'Benign description with network access',
      detail: `Skill claims to be a "${metadata.description}" but makes network calls`,
      evidence: 'Simple utility skills typically do not require network access'
    });
  }

  // Check for supply chain indicators
  if (skill.codeFiles.length > 0) {
    // Check for suspiciously large code files for simple functionality
    const totalCodeSize = skill.codeFiles.reduce((sum, f) => sum + f.content.length, 0);

    if (totalCodeSize > 100000 && seemsBenign) {
      findings.push({
        severity: 'MEDIUM',
        category: 'supply-chain-risk',
        title: 'Unusually large code for stated purpose',
        detail: `Code is ${totalCodeSize} characters but skill description suggests simple functionality`,
        evidence: 'Large code size may indicate hidden functionality'
      });
    }

    // Check for minified code
    const hasMinified = skill.codeFiles.some(f => {
      const lines = f.content.split('\n');
      const avgLineLength = f.content.length / lines.length;
      return avgLineLength > 200; // Average line > 200 chars suggests minification
    });

    if (hasMinified) {
      findings.push({
        severity: 'MEDIUM',
        category: 'supply-chain-risk',
        title: 'Minified or obfuscated code detected',
        detail: 'Code appears to be minified or obfuscated',
        evidence: 'Minified code is harder to audit and may hide malicious behavior'
      });
    }
  }

  return {
    layer: 'crossref',
    findings
  };
}

/**
 * Extract environment variable names accessed in code
 */
function extractEnvVarsFromCode(codeFiles: CodeFile[]): string[] {
  const envVars = new Set<string>();
  const envPattern = /process\.env\.([A-Z_][A-Z0-9_]*)/g;

  for (const file of codeFiles) {
    let match;
    while ((match = envPattern.exec(file.content)) !== null) {
      envVars.add(match[1]);
    }
  }

  return Array.from(envVars);
}
