/**
 * Layer 3: Code Analysis
 * Performs AST analysis on JavaScript/TypeScript/Python handler files
 */

import ts from 'typescript';
import type { Skill, Finding, LayerResult, CodeFile } from '../types.js';
import { loadPatterns } from '../pattern-loader.js';
import { PythonParser } from '../parsers/python-parser.js';

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

  // Load Python-specific patterns
  const dangerousImportsPython = await loadPatterns('dangerous-imports-python');
  const dangerousCallsPython = await loadPatterns('dangerous-calls-python');

  // Combine all code-layer patterns
  const allPatterns = [
    ...dangerousImports,
    ...pathPatterns,
    ...exfiltrationPatterns,
    ...obfuscationPatterns,
    ...credentialPatterns,
    ...dangerousImportsPython,
    ...dangerousCallsPython
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
    // Dispatch to appropriate parser based on file extension
    if (codeFile.extension === 'py') {
      // Python files - use tree-sitter for AST analysis
      const pythonParser = new PythonParser();
      if (pythonParser.canParse(codeFile.path)) {
        try {
          const parsed = pythonParser.parse(codeFile.path, codeFile.content);

          // Analyze Python AST for suspicious patterns
          const pythonFindings = analyzePythonAST(parsed.ast, codeFile.content, relativePath);
          findings.push(...pythonFindings);

        } catch (error) {
          // Python parse error
          findings.push({
            severity: 'MEDIUM',
            category: 'parse-error',
            title: 'Failed to parse Python file',
            file: relativePath,
            detail: 'Could not parse file as valid Python',
            evidence: 'May indicate malformed or obfuscated code'
          });
        }
      }
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

/**
 * Analyze Python AST for security issues
 */
function analyzePythonAST(tree: any, _content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const rootNode = tree.rootNode;

  // Traverse the AST and collect dangerous patterns
  const dangerousCalls: Array<{ name: string; line: number; text: string }> = [];
  const dangerousImports: Array<{ module: string; line: number; text: string }> = [];

  function traverse(node: any) {
    if (!node) return;

    // Detect dangerous function calls
    if (node.type === 'call') {
      const funcNode = node.childForFieldName('function');
      if (funcNode) {
        const funcText = funcNode.text;
        const line = node.startPosition.row + 1;
        const callText = node.text;

        // Check for dangerous builtins: eval(), exec(), compile()
        if (['eval', 'exec', 'compile', '__import__'].includes(funcText)) {
          dangerousCalls.push({ name: funcText, line, text: callText });
        }

        // Check for os.system(), os.popen(), etc.
        if (funcText.startsWith('os.')) {
          const methodName = funcText.substring(3);
          if (['system', 'popen', 'popen2', 'popen3', 'popen4'].includes(methodName)) {
            dangerousCalls.push({ name: funcText, line, text: callText });
          }
          if (['execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe'].includes(methodName)) {
            dangerousCalls.push({ name: funcText, line, text: callText });
          }
          if (['spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe'].includes(methodName)) {
            dangerousCalls.push({ name: funcText, line, text: callText });
          }
          if (['remove', 'unlink', 'rmdir', 'removedirs'].includes(methodName)) {
            dangerousCalls.push({ name: funcText, line, text: callText });
          }
        }

        // Check for subprocess calls (especially with shell=True)
        if (funcText.startsWith('subprocess.')) {
          const methodName = funcText.substring(11);
          if (['run', 'call', 'Popen', 'check_output', 'check_call'].includes(methodName)) {
            // Check if shell=True is present in the arguments
            if (callText.includes('shell=True') || callText.includes('shell = True')) {
              dangerousCalls.push({ name: `${funcText} with shell=True`, line, text: callText });
            } else {
              dangerousCalls.push({ name: funcText, line, text: callText });
            }
          }
        }

        // Check for pickle.loads(), pickle.load()
        if (funcText.startsWith('pickle.')) {
          const methodName = funcText.substring(7);
          if (['loads', 'load', 'Unpickler'].includes(methodName)) {
            dangerousCalls.push({ name: funcText, line, text: callText });
          }
        }

        // Check for marshal.loads(), marshal.load()
        if (funcText.startsWith('marshal.')) {
          const methodName = funcText.substring(8);
          if (['loads', 'load'].includes(methodName)) {
            dangerousCalls.push({ name: funcText, line, text: callText });
          }
        }

        // Check for yaml.load() (should use safe_load)
        if (funcText === 'yaml.load' && !callText.includes('SafeLoader')) {
          dangerousCalls.push({ name: 'yaml.load without SafeLoader', line, text: callText });
        }

        // Check for shutil.rmtree()
        if (funcText === 'shutil.rmtree') {
          dangerousCalls.push({ name: funcText, line, text: callText });
        }

        // Check for tempfile.mktemp()
        if (funcText === 'tempfile.mktemp') {
          dangerousCalls.push({ name: funcText, line, text: callText });
        }

        // Check for open() with write mode
        if (funcText === 'open' && /['"]w/.test(callText)) {
          dangerousCalls.push({ name: 'open() with write mode', line, text: callText });
        }

        // Check for importlib.import_module()
        if (funcText === 'importlib.import_module') {
          dangerousCalls.push({ name: funcText, line, text: callText });
        }
      }
    }

    // Detect dangerous imports
    if (node.type === 'import_statement' || node.type === 'import_from_statement') {
      const line = node.startPosition.row + 1;
      const importText = node.text;

      // Check for dangerous modules
      const dangerousModules = [
        'subprocess', 'os', 'pickle', 'shelve', 'marshal', 'ctypes', 'cffi',
        'socket', 'requests', 'urllib', 'httpx', 'importlib'
      ];

      for (const module of dangerousModules) {
        if (importText.includes(module)) {
          dangerousImports.push({ module, line, text: importText });
          break;
        }
      }
    }

    // Recursively traverse children
    for (let i = 0; i < node.childCount; i++) {
      traverse(node.child(i));
    }
  }

  traverse(rootNode);

  // Create findings for dangerous calls
  const callCounts = new Map<string, number>();
  for (const call of dangerousCalls) {
    const count = callCounts.get(call.name) || 0;
    callCounts.set(call.name, count + 1);
  }

  for (const [callName, count] of callCounts.entries()) {
    const firstCall = dangerousCalls.find(c => c.name === callName);
    if (!firstCall) continue;

    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
    let patternId = 'pycall-999';

    // Determine severity and pattern ID based on call type
    if (callName === 'eval' || callName === 'exec') {
      severity = 'CRITICAL';
      patternId = callName === 'eval' ? 'pyimp-003' : 'pyimp-004';
    } else if (callName.includes('shell=True')) {
      severity = 'CRITICAL';
      patternId = 'pycall-001';
    } else if (callName === 'os.system') {
      severity = 'CRITICAL';
      patternId = 'pycall-002';
    } else if (callName.startsWith('pickle.')) {
      severity = 'CRITICAL';
      patternId = 'pycall-006';
    } else if (callName.startsWith('yaml.load')) {
      severity = 'CRITICAL';
      patternId = 'pycall-008';
    } else if (callName === 'shutil.rmtree') {
      severity = 'HIGH';
      patternId = 'pycall-012';
    }

    findings.push({
      severity,
      category: 'dangerous-calls',
      title: `Dangerous Python call: ${callName}()`,
      file: filePath,
      line: firstCall.line,
      detail: `Uses ${callName}() which can be dangerous`,
      evidence: `Found ${count} occurrence(s)`,
      patternId
    });
  }

  // Create findings for dangerous imports (but only INFO level to avoid false positives)
  const importCounts = new Map<string, number>();
  for (const imp of dangerousImports) {
    const count = importCounts.get(imp.module) || 0;
    importCounts.set(imp.module, count + 1);
  }

  for (const [module, count] of importCounts.entries()) {
    const firstImport = dangerousImports.find(i => i.module === module);
    if (!firstImport) continue;

    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
    let patternId = 'pyimp-999';

    // Determine severity based on module
    if (module === 'pickle') {
      severity = 'CRITICAL';
      patternId = 'pyimp-006';
    } else if (module === 'subprocess') {
      severity = 'HIGH';
      patternId = 'pyimp-001';
    } else if (module === 'os') {
      severity = 'MEDIUM';
      patternId = 'pyimp-002';
    } else if (['ctypes', 'cffi', 'marshal', 'shelve'].includes(module)) {
      severity = 'HIGH';
      patternId = module === 'ctypes' ? 'pyimp-011' :
                  module === 'cffi' ? 'pyimp-012' :
                  module === 'marshal' ? 'pyimp-008' : 'pyimp-007';
    } else if (['socket', 'requests', 'urllib', 'httpx'].includes(module)) {
      severity = 'LOW';
      patternId = module === 'socket' ? 'pyimp-013' :
                  module === 'requests' ? 'pyimp-014' :
                  module === 'urllib' ? 'pyimp-015' : 'pyimp-016';
    } else if (module === 'importlib') {
      severity = 'MEDIUM';
      patternId = 'pyimp-010';
    }

    findings.push({
      severity,
      category: 'dangerous-imports',
      title: `Python import: ${module}`,
      file: filePath,
      line: firstImport.line,
      detail: `Imports ${module} module`,
      evidence: `Found ${count} import(s)`,
      patternId
    });
  }

  return findings;
}
