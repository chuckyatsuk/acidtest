/**
 * Layer 3: Code Analysis
 * Performs AST analysis on JavaScript/TypeScript/Python handler files
 */

import ts from 'typescript';
import type { Skill, Finding, LayerResult, CodeFile } from '../types.js';
import { loadPatterns } from '../pattern-loader.js';

/**
 * Scan code files for security issues
 */
export async function scanCode(skill: Skill): Promise<LayerResult> {
  const findings: Finding[] = [];

  // If no code files, nothing to scan
  if (skill.codeFiles.length === 0) {
    return {
      layer: 'code',
      findings
    };
  }

  // Load code-related patterns
  const dangerousImports = await loadPatterns('dangerous-imports');
  const pathPatterns = await loadPatterns('sensitive-paths');
  const exfiltrationPatterns = await loadPatterns('exfiltration-sinks');
  const obfuscationPatterns = await loadPatterns('obfuscation');
  const credentialPatterns = await loadPatterns('credential-patterns');

  // Unicode/invisible-character obfuscation patterns
  const unicodePatterns = await loadPatterns('unicode-obfuscation');

  // Credential-exfiltration-via-MCP-channel patterns
  const mcpExfilPatterns = await loadPatterns('mcp-exfil');

  // Python dangerous-sink patterns (regex; replaces the removed Python AST)
  const pythonSinkPatterns = await loadPatterns('python-sinks');

  // Combine all code-layer patterns. Python-specific AST scanning was
  // removed in v2 (MCP-first); Python sinks are now covered by the
  // regex python-sinks pack, and the rest are language-agnostic.
  const allPatterns = [
    ...dangerousImports,
    ...pathPatterns,
    ...exfiltrationPatterns,
    ...obfuscationPatterns,
    ...credentialPatterns,
    ...unicodePatterns,
    ...mcpExfilPatterns,
    ...pythonSinkPatterns
  ].filter(p => p.layer === 'code');

  // Scan each code file
  for (const codeFile of skill.codeFiles) {
    // Regex-based pattern scanning
    const regexFindings = scanCodeWithRegex(codeFile, allPatterns);
    findings.push(...regexFindings);

    // AST-based analysis
    const astFindings = scanCodeWithAST(codeFile);
    findings.push(...astFindings);
  }

  return {
    layer: 'code',
    findings
  };
}

/**
 * Scan code file using regex patterns
 */
function scanCodeWithRegex(codeFile: CodeFile, patterns: any[]): Finding[] {
  const findings: Finding[] = [];
  const content = codeFile.content;
  const relativePath = codeFile.path;

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.match.value, pattern.match.flags || '');
    const matches = content.match(regex);

    if (matches && matches.length > 0) {
      // Special handling for path-traversal pattern (sp-006)
      // Exclude legitimate import/require statements
      if (pattern.id === 'sp-006') {
        const legitimateMatches = filterPathTraversalMatches(content, matches);
        if (legitimateMatches.length === 0) {
          continue; // All matches were legitimate imports
        }
      }

      // Find line number for first match
      const lineNumber = findLineNumber(content, matches[0]);

      findings.push({
        severity: pattern.severity,
        category: pattern.category || 'code-issue',
        title: pattern.name,
        file: relativePath,
        line: lineNumber,
        detail: pattern.description || `Pattern match: ${pattern.name}`,
        evidence: `Found ${matches.length} occurrence(s)`,
        patternId: pattern.id,
        ...(pattern.remediation && { remediation: pattern.remediation })
      });
    }
  }

  return findings;
}

/**
 * Scan code file using AST analysis
 * Dispatches to appropriate parser based on file extension
 */
function scanCodeWithAST(codeFile: CodeFile): Finding[] {
  const findings: Finding[] = [];
  const relativePath = codeFile.path;

  try {
    // Python files: no AST analysis in v2 (tree-sitter removed for MCP-first).
    // They are still covered by the language-agnostic regex patterns.
    if (codeFile.extension === 'py') {
      return findings;
    }

    // Parse TypeScript/JavaScript
    const sourceFile = ts.createSourceFile(
      codeFile.path,
      codeFile.content,
      ts.ScriptTarget.Latest,
      true
    );

    // Extract all URLs from string literals
    const urls = extractURLs(sourceFile);
    if (urls.length > 0) {
      findings.push({
        severity: 'INFO',
        category: 'network-urls',
        title: 'URL literals found in code',
        file: relativePath,
        detail: `Found ${urls.length} URL(s) in code`,
        evidence: urls.slice(0, 5).join(', ') + (urls.length > 5 ? '...' : '')
      });
    }

    // Check for suspicious patterns
    const suspiciousFindings = detectSuspiciousPatterns(sourceFile, relativePath);
    findings.push(...suspiciousFindings);

    // Entropy-based obfuscation detection
    const entropyFindings = detectHighEntropyStrings(sourceFile, relativePath);
    findings.push(...entropyFindings);

  } catch (error) {
    // If parsing fails, the code might be malformed or obfuscated
    findings.push({
      severity: 'MEDIUM',
      category: 'parse-error',
      title: 'Failed to parse code file',
      file: relativePath,
      detail: 'Could not parse file as valid JavaScript/TypeScript',
      evidence: 'May indicate obfuscated or malformed code'
    });
  }

  return findings;
}

/**
 * Extract URL strings from source file
 */
function extractURLs(sourceFile: ts.SourceFile): string[] {
  const urls: string[] = [];
  const urlPattern = /^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;

  function visit(node: ts.Node) {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const text = node.text;
      if (urlPattern.test(text)) {
        urls.push(text);
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return urls;
}

/**
 * Detect suspicious patterns via AST traversal
 */
function detectSuspiciousPatterns(sourceFile: ts.SourceFile, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const dynamicRequires: number[] = [];
  const evals: number[] = [];
  const functionConstructors: number[] = [];
  const propertyAccessBypasses: number[] = [];
  const stringConcatenations: number[] = [];

  function visit(node: ts.Node) {
    // Check for eval() calls
    if (ts.isCallExpression(node)) {
      const expression = node.expression;
      if (ts.isIdentifier(expression) && expression.text === 'eval') {
        const lineNumber = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        evals.push(lineNumber);
      }

      // Check for require() with non-literal arguments (catches dynamic require, template literals, variables)
      if (ts.isIdentifier(expression) && expression.text === 'require') {
        if (node.arguments.length > 0) {
          const arg = node.arguments[0];
          // Catches: require(variable), require(obj.prop), require(`template${expr}`)
          if (!ts.isStringLiteral(arg) && !ts.isNoSubstitutionTemplateLiteral(arg)) {
            const lineNumber = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
            dynamicRequires.push(lineNumber);
          }
          // Check for string concatenation: require('child_' + 'process')
          if (ts.isBinaryExpression(arg) && arg.operatorToken.kind === ts.SyntaxKind.PlusToken) {
            const lineNumber = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
            stringConcatenations.push(lineNumber);
          }
        }
      }
    }

    // Check for Function constructor: new Function(...)
    if (ts.isNewExpression(node)) {
      const expression = node.expression;
      if (ts.isIdentifier(expression) && expression.text === 'Function') {
        const lineNumber = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        functionConstructors.push(lineNumber);
      }
    }

    // Check for bracket notation property access on sensitive objects
    // Catches: global['child_process'], process['env'], require['cache']
    if (ts.isElementAccessExpression(node)) {
      const expression = node.expression;
      if (ts.isIdentifier(expression)) {
        const objName = expression.text;
        // Check if accessing sensitive global objects
        const sensitiveObjects = ['global', 'process', 'require', 'module', 'exports'];
        if (sensitiveObjects.includes(objName)) {
          const lineNumber = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
          propertyAccessBypasses.push(lineNumber);
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);

  // Add findings for dynamic requires
  if (dynamicRequires.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'dynamic-require',
      title: 'Dynamic require() detected',
      file: filePath,
      line: dynamicRequires[0],
      detail: `Found ${dynamicRequires.length} dynamic require() call(s)`,
      evidence: 'Dynamic imports can load arbitrary modules',
      patternId: 'ast-dynamic-require'
    });
  }

  // Add findings for eval usage
  if (evals.length > 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'eval-usage',
      title: 'eval() usage detected',
      file: filePath,
      line: evals[0],
      detail: `Found ${evals.length} eval() call(s)`,
      evidence: 'eval() can execute arbitrary code',
      patternId: 'ast-eval'
    });
  }

  // Add findings for Function constructor
  if (functionConstructors.length > 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'function-constructor',
      title: 'Function constructor detected',
      file: filePath,
      line: functionConstructors[0],
      detail: `Found ${functionConstructors.length} Function constructor call(s)`,
      evidence: 'Function constructor can execute arbitrary code like eval()',
      patternId: 'ast-function-constructor'
    });
  }

  // Add findings for property access bypasses
  if (propertyAccessBypasses.length > 0) {
    findings.push({
      severity: 'MEDIUM',
      category: 'property-access-bypass',
      title: 'Bracket notation on sensitive objects',
      file: filePath,
      line: propertyAccessBypasses[0],
      detail: `Found ${propertyAccessBypasses.length} bracket notation access(es) on sensitive objects`,
      evidence: 'Bracket notation can bypass static analysis: global["child_process"]',
      patternId: 'ast-bracket-access'
    });
  }

  // Add findings for string concatenation in require
  if (stringConcatenations.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'string-concatenation',
      title: 'String concatenation in require()',
      file: filePath,
      line: stringConcatenations[0],
      detail: `Found ${stringConcatenations.length} concatenated string(s) in require()`,
      evidence: 'String concatenation can hide malicious imports: require("child_" + "process")',
      patternId: 'ast-string-concat'
    });
  }

  return findings;
}

/**
 * Calculate Shannon entropy of a string
 * Returns a value between 0 (no randomness) and ~8 (maximum randomness for byte strings)
 */
function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;

  // Count character frequencies
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }

  // Calculate entropy using Shannon formula: -Σ(p * log2(p))
  let entropy = 0;
  const length = str.length;

  for (const count of freq.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Check if string matches common legitimate high-entropy patterns
 */
function isLegitimateHighEntropyString(text: string): boolean {
  // JWT tokens (header.payload.signature format, starts with eyJ)
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)) {
    return true;
  }

  // UUID/GUID (8-4-4-4-12 format)
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)) {
    return true;
  }

  // Hex hashes (SHA256: 64 chars, SHA1: 40 chars, MD5: 32 chars)
  if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(text)) {
    return true;
  }

  // Base64 strings (common in configs, keys)
  // Must have padding OR be very long (>100 chars suggests real encoded data)
  // Short base64-looking strings without padding are suspicious
  if (/^[A-Za-z0-9+/]+=+$/.test(text) && text.length % 4 === 0) {
    return true; // Has proper padding
  }
  if (/^[A-Za-z0-9+/]+$/.test(text) && text.length > 100) {
    return true; // Very long, likely real encoded data
  }

  // API keys with common prefixes (Stripe, GitHub, etc.)
  if (/^(sk_|pk_|gh[ps]_|AKIA|ya29\.|glpat-|xox[abp]-)[A-Za-z0-9_-]+$/i.test(text)) {
    // These ARE suspicious, so return false to flag them
    return false;
  }

  return false;
}

/**
 * Detect high-entropy strings that may indicate obfuscation
 */
function detectHighEntropyStrings(sourceFile: ts.SourceFile, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const ENTROPY_THRESHOLD = 4.5; // Strings above this are suspicious
  const MIN_LENGTH = 20; // Only check strings longer than this
  const highEntropyStrings: Array<{ text: string; entropy: number; line: number }> = [];

  function visit(node: ts.Node) {
    // Check string literals and template literals
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const text = node.text;

      // Skip short strings
      if (text.length < MIN_LENGTH) {
        ts.forEachChild(node, visit);
        return;
      }

      // Skip URLs (already detected elsewhere)
      if (/^https?:\/\//.test(text)) {
        ts.forEachChild(node, visit);
        return;
      }

      // Skip legitimate high-entropy strings (JWTs, UUIDs, hashes)
      if (isLegitimateHighEntropyString(text)) {
        ts.forEachChild(node, visit);
        return;
      }

      const entropy = calculateEntropy(text);

      if (entropy > ENTROPY_THRESHOLD) {
        const lineNumber = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        highEntropyStrings.push({
          text: text.substring(0, 50) + (text.length > 50 ? '...' : ''),
          entropy: Math.round(entropy * 100) / 100,
          line: lineNumber
        });
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);

  // Only create a finding if we found high-entropy strings
  if (highEntropyStrings.length > 0) {
    const first = highEntropyStrings[0];
    findings.push({
      severity: 'MEDIUM',
      category: 'obfuscation',
      title: 'High-entropy strings detected',
      file: filePath,
      line: first.line,
      detail: `Found ${highEntropyStrings.length} string(s) with high entropy (>${ENTROPY_THRESHOLD})`,
      evidence: `Entropy: ${first.entropy}, Example: "${first.text}"`
    });
  }

  return findings;
}

/**
 * Filter out legitimate path traversal patterns (imports) from suspicious ones
 * Returns only the suspicious matches
 */
function filterPathTraversalMatches(content: string, matches: RegExpMatchArray): string[] {
  const suspicious: string[] = [];

  // Split content into lines for context checking
  const lines = content.split('\n');

  for (const match of matches) {
    // Find which line contains this match
    const matchIndex = content.indexOf(match);
    if (matchIndex === -1) continue;

    const beforeMatch = content.substring(0, matchIndex);
    const lineNumber = beforeMatch.split('\n').length - 1;
    const line = lines[lineNumber]?.trim() || '';

    // Check if this is a legitimate import/require statement
    const isImport = /^import\s+.*from\s+['"]/.test(line) ||
                     /^export\s+.*from\s+['"]/.test(line) ||
                     /require\s*\(\s*['"]/.test(line);

    // If it's not an import, it's suspicious
    if (!isImport) {
      suspicious.push(match);
    }
  }

  return suspicious;
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
