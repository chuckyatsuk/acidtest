/**
 * Core TypeScript interfaces for AcidTest security scanner
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Status = 'PASS' | 'WARN' | 'FAIL' | 'DANGER' | 'ERROR';

export type Layer = 'permissions' | 'markdown' | 'code' | 'crossref' | 'dataflow';

export type PatternMatchType = 'regex' | 'ast' | 'exact';

/**
 * Pattern match configuration
 */
export interface PatternMatch {
  type: PatternMatchType;
  value: string;
  flags?: string;
}

/**
 * Remediation suggestion for a finding
 */
export interface Remediation {
  title: string;
  suggestions: string[];
  autofix?: boolean;
  fixAction?: {
    type: 'replace';
    pattern: string;
    replacement: string;
  };
}

/**
 * Detection pattern definition
 */
export interface Pattern {
  id: string;
  name: string;
  description?: string;
  severity: Severity;
  match: PatternMatch;
  layer: Layer;
  category?: string;
  remediation?: Remediation;
}

/**
 * Pattern category file structure
 */
export interface PatternCategory {
  category: string;
  patterns: Pattern[];
}

/**
 * Skill metadata from YAML frontmatter
 */
export interface SkillMetadata {
  name?: string;
  description?: string;
  version?: string;
  env?: string[];
  bins?: string[];
  'allowed-tools'?: string[];
  [key: string]: unknown;
}

/**
 * Parsed skill structure
 */
export interface Skill {
  name: string;
  path: string;
  metadata: SkillMetadata; // Empty object {} signals no manifest
  markdownContent?: string; // Optional - may be empty for code-only scanning
  codeFiles: CodeFile[];
  isMCP?: boolean; // True if this is an MCP server (not AgentSkills)
  hasManifest?: boolean; // True if SKILL.md or MCP manifest was found
}

/**
 * Code file structure
 */
export interface CodeFile {
  path: string;
  content: string;
  extension: 'ts' | 'js' | 'mjs' | 'cjs' | 'py';
}

/**
 * Individual security finding
 */
export interface Finding {
  severity: Severity;
  category: string;
  title: string;
  file?: string;
  line?: number;
  detail: string;
  evidence?: string;
  patternId?: string;
  remediation?: Remediation;
}

/**
 * Layer scan result
 */
export interface LayerResult {
  layer: Layer;
  findings: Finding[];
}

/**
 * Complete scan result
 */
export interface ScanResult {
  schemaVersion: string;
  tool: string;
  version: string;
  skill: {
    name: string;
    path: string;
    hasManifest?: boolean; // True if SKILL.md or MCP manifest was found
  };
  score: number;
  status: Status;
  permissions: {
    bins: string[];
    env: string[];
    tools: string[];
  };
  findings: Finding[];
  recommendation: string;
}

/**
 * Error result for failed scans
 */
export interface ErrorResult {
  schemaVersion: string;
  tool: string;
  version: string;
  status: 'ERROR';
  error: string;
}

/**
 * CLI options
 */
export interface CliOptions {
  json?: boolean;
  verbose?: boolean;
}

/**
 * AcidTest configuration file schema (.acidtest.json)
 */
export interface AcidTestConfig {
  ignore?: {
    patterns?: string[];      // Pattern IDs to ignore
    categories?: string[];    // Categories to ignore
    files?: string[];         // Glob patterns for files to skip
  };
  thresholds?: {
    minScore?: number;        // Minimum passing score (default: 0)
    failOn?: Severity[];      // Exit 1 if these severities found
  };
  output?: {
    format?: 'detailed' | 'compact' | 'json';
    showRemediation?: boolean;
    colors?: boolean;
  };
}
