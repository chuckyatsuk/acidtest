/**
 * Reporter
 * Formats scan results for terminal output with colors
 */

import chalk from 'chalk';
import Table from 'cli-table3';
import type { ScanResult, Finding, Status, Severity } from './types.js';

export interface ReportOptions {
  showRemediation?: boolean;
}

/**
 * Report scan results to terminal
 */
export function reportToTerminal(result: ScanResult, options: ReportOptions = {}): void {
  console.log();
  console.log(chalk.bold(`AcidTest v${result.version}`));
  console.log();
  console.log(`Scanning: ${chalk.cyan(result.skill.name)}`);
  console.log(`Source:   ${chalk.dim(result.skill.path)}`);
  console.log();

  // Show warning if no manifest found
  if (result.skill.hasManifest === false) {
    console.log(chalk.yellow('⚠  No manifest found. Running security scan without permission audit.'));
    console.log(chalk.dim('   For full analysis, add SKILL.md: https://github.com/currentlycurrently/acidtest#usage'));
    console.log();
  }

  console.log(chalk.dim('━'.repeat(60)));
  console.log();

  // Trust score with colored bar
  const scoreBar = renderScoreBar(result.score);
  const statusColor = getStatusColor(result.status);
  console.log(
    `TRUST SCORE: ${chalk.bold(`${result.score}/100`)} ${scoreBar} ${statusColor(result.status)}`
  );
  console.log();
  console.log(chalk.dim('━'.repeat(60)));
  console.log();

  // Permissions section (now always normalized as arrays)
  const hasBins = result.permissions.bins.length > 0;
  const hasEnv = result.permissions.env.length > 0;
  const hasTools = result.permissions.tools.length > 0;

  if (hasBins || hasEnv || hasTools) {
    console.log(chalk.bold('PERMISSIONS'));

    if (hasBins) {
      console.log(`  bins:  ${result.permissions.bins.join(', ')}`);
    }
    if (hasEnv) {
      console.log(`  env:   ${result.permissions.env.join(', ')}`);
    }
    if (hasTools) {
      console.log(`  tools: ${result.permissions.tools.join(', ')}`);
    }

    console.log();
  }

  // Findings section
  if (result.findings.length > 0) {
    console.log(chalk.bold('FINDINGS'));
    console.log();

    // Group by severity
    const critical = result.findings.filter(f => f.severity === 'CRITICAL');
    const high = result.findings.filter(f => f.severity === 'HIGH');
    const medium = result.findings.filter(f => f.severity === 'MEDIUM');
    const low = result.findings.filter(f => f.severity === 'LOW');
    const info = result.findings.filter(f => f.severity === 'INFO');

    const grouped = [
      ...critical,
      ...high,
      ...medium,
      ...low,
      ...info
    ];

    for (const finding of grouped) {
      renderFinding(finding, options.showRemediation);
    }

    console.log();

    // Show summary table if there are multiple findings
    if (result.findings.length > 1) {
      renderSummaryTable(result.findings);
      console.log();
    }
  } else {
    console.log(chalk.green('No security issues detected.'));
    console.log();
  }

  console.log(chalk.dim('━'.repeat(60)));
  console.log();

  // Recommendation
  const recommendationColor = result.status === 'PASS' ? chalk.green : chalk.yellow;
  console.log(
    chalk.bold('RECOMMENDATION: ') +
    recommendationColor(result.recommendation)
  );

  console.log();
}

/**
 * Report scan results as JSON
 */
export function reportAsJSON(result: ScanResult): void {
  console.log(JSON.stringify(result, null, 2));
}

/**
 * Render a single finding
 */
function renderFinding(finding: Finding, showRemediation: boolean = false): void {
  const severityIcon = getSeverityIcon(finding.severity);
  const severityColor = getSeverityColor(finding.severity);

  // First line: severity and title
  console.log(
    `  ${severityIcon} ${severityColor(finding.severity.padEnd(8))} ${chalk.bold(finding.title)}`
  );

  // Location (file and line)
  if (finding.file) {
    const location = finding.line
      ? `${finding.file}:${finding.line}`
      : finding.file;
    console.log(`    ${chalk.dim(location)}`);
  }

  // Detail
  if (finding.detail) {
    console.log(`    ${finding.detail}`);
  }

  // Evidence
  if (finding.evidence) {
    console.log(`    ${chalk.dim(finding.evidence)}`);
  }

  // Remediation suggestions (only shown when --fix flag is used)
  if (showRemediation && finding.remediation) {
    console.log();
    console.log(`    ${chalk.cyan.bold('💡 Suggested Fix:')}`);
    console.log(`    ${chalk.cyan(finding.remediation.title)}`);
    for (const suggestion of finding.remediation.suggestions) {
      console.log(`      ${chalk.dim('•')} ${suggestion}`);
    }
  }

  console.log();
}

/**
 * Render summary table for findings
 */
function renderSummaryTable(findings: Finding[]): void {
  // Count findings by severity
  const counts = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: findings.filter(f => f.severity === 'INFO').length,
  };

  // Get examples for each severity (up to 3)
  const getExamples = (severity: Severity): string => {
    const severityFindings = findings.filter(f => f.severity === severity);
    const examples = severityFindings.slice(0, 3).map(f => f.title);
    return examples.join(', ') + (severityFindings.length > 3 ? '...' : '');
  };

  const table = new Table({
    head: [chalk.bold('Severity'), chalk.bold('Count'), chalk.bold('Examples')],
    colWidths: [12, 8, 45],
    style: {
      head: [],
      border: ['dim']
    }
  });

  // Only add rows for severities that have findings
  if (counts.CRITICAL > 0) {
    table.push([
      chalk.red.bold('CRITICAL'),
      chalk.red.bold(counts.CRITICAL.toString()),
      getExamples('CRITICAL')
    ]);
  }

  if (counts.HIGH > 0) {
    table.push([
      chalk.red('HIGH'),
      chalk.red(counts.HIGH.toString()),
      getExamples('HIGH')
    ]);
  }

  if (counts.MEDIUM > 0) {
    table.push([
      chalk.yellow('MEDIUM'),
      chalk.yellow(counts.MEDIUM.toString()),
      getExamples('MEDIUM')
    ]);
  }

  if (counts.LOW > 0) {
    table.push([
      chalk.dim('LOW'),
      chalk.dim(counts.LOW.toString()),
      chalk.dim(getExamples('LOW'))
    ]);
  }

  if (counts.INFO > 0) {
    table.push([
      chalk.blue('INFO'),
      chalk.blue(counts.INFO.toString()),
      chalk.dim(getExamples('INFO'))
    ]);
  }

  console.log(chalk.bold('SUMMARY'));
  console.log(table.toString());
}

/**
 * Get icon for severity level
 */
function getSeverityIcon(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return chalk.red('✖');
    case 'HIGH':
      return chalk.red('✖');
    case 'MEDIUM':
      return chalk.yellow('⚠');
    case 'LOW':
      return chalk.dim('○');
    case 'INFO':
      return chalk.blue('ℹ');
  }
}

/**
 * Get color function for severity
 */
function getSeverityColor(severity: Severity): typeof chalk.red {
  switch (severity) {
    case 'CRITICAL':
      return chalk.red.bold;
    case 'HIGH':
      return chalk.red;
    case 'MEDIUM':
      return chalk.yellow;
    case 'LOW':
      return chalk.dim;
    case 'INFO':
      return chalk.blue;
  }
}

/**
 * Get color function for status
 */
function getStatusColor(status: Status): typeof chalk.red {
  switch (status) {
    case 'PASS':
      return chalk.green.bold;
    case 'WARN':
      return chalk.yellow.bold;
    case 'FAIL':
      return chalk.red.bold;
    case 'DANGER':
      return chalk.red.bold.bgRed;
    case 'ERROR':
      return chalk.red.bold;
  }
}

/**
 * Render score bar
 */
function renderScoreBar(score: number): string {
  const barLength = 10;
  const filled = Math.round((score / 100) * barLength);
  const empty = barLength - filled;

  let color: typeof chalk.red;
  if (score >= 80) color = chalk.green;
  else if (score >= 50) color = chalk.yellow;
  else color = chalk.red;

  return color('█'.repeat(filled)) + chalk.dim('░'.repeat(empty));
}
