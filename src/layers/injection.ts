/**
 * Layer 2: Prompt Injection Scan
 * Scans markdown content for prompt injection patterns
 */

import type { Skill, Finding, LayerResult } from '../types.js';
import { loadPatterns } from '../pattern-loader.js';

/**
 * Scan markdown content for prompt injection patterns
 */
export async function scanInjection(skill: Skill): Promise<LayerResult> {
  const findings: Finding[] = [];
  const markdown = skill.markdownContent || '';
  const sourceLabel = skill.isMCP ? 'MCP manifest' : 'SKILL.md';

  // Skip markdown scanning if no markdown content
  if (!markdown || markdown.length === 0) {
    return {
      layer: 'markdown',
      findings: []
    };
  }

  // Load prompt injection, sensitive path, and tool-poisoning patterns
  const promptPatterns = await loadPatterns('prompt-injection');
  const pathPatterns = await loadPatterns('sensitive-paths');
  const poisoningPatterns = await loadPatterns('mcp-tool-poisoning');
  const unicodePatterns = await loadPatterns('unicode-obfuscation');

  // Combine patterns that apply to markdown layer
  const allPatterns = [...promptPatterns, ...pathPatterns, ...poisoningPatterns, ...unicodePatterns].filter(
    p => p.layer === 'markdown'
  );

  // Scan against each pattern
  for (const pattern of allPatterns) {
    const regex = new RegExp(pattern.match.value, pattern.match.flags || '');
    const matches = markdown.match(regex);

    if (matches && matches.length > 0) {
      // Try to find line number for the match
      const lineNumber = findLineNumber(markdown, matches[0]);

      findings.push({
        severity: pattern.severity,
        category: pattern.category || 'prompt-injection',
        title: pattern.name,
        file: sourceLabel,
        line: lineNumber,
        detail: pattern.description || `Pattern match: ${pattern.name}`,
        evidence: matches.length > 1 ? `${matches.length} matches found` : `Match: "${truncate(matches[0], 100)}"`,
        patternId: pattern.id,
        ...(pattern.remediation && { remediation: pattern.remediation })
      });
    }
  }

  // Additional heuristic checks

  // Check for excessively long markdown (could hide malicious content)
  if (markdown.length > 50000) {
    findings.push({
      severity: 'LOW',
      category: 'suspicious-size',
      title: 'Unusually large skill documentation',
      file: sourceLabel,
      detail: `Skill documentation is ${markdown.length} characters`,
      evidence: 'Large files can hide malicious content'
    });
  }

  // Scan raw SKILL.md frontmatter for injection attempts.
  // Frontmatter fields (description, triggers, ...) reach the agent as
  // metadata and are an instruction-override channel of their own.
  const fmText = skill.rawFrontmatter || '';
  if (fmText.trim().length > 0) {
    const fmPatterns = await loadPatterns('frontmatter-injection');
    const frontmatterPatterns = [...allPatterns, ...fmPatterns].filter(
      p => p.layer === 'markdown'
    );

    for (const pattern of frontmatterPatterns) {
      const regex = new RegExp(pattern.match.value, pattern.match.flags || '');
      const matches = fmText.match(regex);

      if (matches && matches.length > 0) {
        const lineInFrontmatter = findLineNumber(fmText, matches[0]);

        findings.push({
          severity: pattern.severity,
          category: pattern.category || 'frontmatter-injection',
          title: pattern.name,
          file: 'SKILL.md (frontmatter)',
          // Raw frontmatter starts on line 2, after the opening --- delimiter
          line: lineInFrontmatter !== undefined ? lineInFrontmatter + 1 : undefined,
          detail: pattern.description || `Pattern match: ${pattern.name}`,
          evidence: matches.length > 1 ? `${matches.length} matches found` : `Match: "${truncate(matches[0], 100)}"`,
          patternId: pattern.id,
          ...(pattern.remediation && { remediation: pattern.remediation })
        });
      }
    }
  }

  // Check for base64-looking strings in markdown (potential obfuscation)
  const base64Pattern = /[A-Za-z0-9+\/]{50,}={0,2}/g;
  const base64Matches = markdown.match(base64Pattern);
  if (base64Matches && base64Matches.length > 0) {
    findings.push({
      severity: 'MEDIUM',
      category: 'obfuscation',
      title: 'Possible base64-encoded content in markdown',
      file: sourceLabel,
      detail: `Found ${base64Matches.length} base64-looking string(s)`,
      evidence: 'Base64 encoding can hide malicious instructions'
    });
  }

  return {
    layer: 'markdown',
    findings
  };
}

/**
 * Find line number for a match in text
 */
function findLineNumber(text: string, match: string): number | undefined {
  const index = text.indexOf(match);
  if (index === -1) return undefined;

  const beforeMatch = text.substring(0, index);
  const lineNumber = beforeMatch.split('\n').length;

  return lineNumber;
}

/**
 * Truncate string for display
 */
function truncate(str: string, maxLength: number): string {
  // Remove newlines and excessive whitespace
  const cleaned = str.replace(/\s+/g, ' ').trim();

  if (cleaned.length <= maxLength) {
    return cleaned;
  }

  return cleaned.substring(0, maxLength) + '...';
}
