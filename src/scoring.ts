/**
 * Scoring engine
 * Calculates trust score from security findings
 */

import type { Finding, Status, Severity } from './types.js';

/**
 * Severity point deductions
 */
const SEVERITY_POINTS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0
};

/**
 * Calculate trust score from findings
 * Score starts at 100 and deductions are made for each finding
 * Repeated patterns are capped at 3 deductions to prevent score inflation
 */
export function calculateScore(findings: Finding[]): number {
  let score = 100;

  // Track how many times we've deducted points for each pattern
  const patternDeductionCount = new Map<string, number>();

  for (const finding of findings) {
    // Use patternId as the key, fallback to title if not available
    const key = finding.patternId || finding.title;
    const currentCount = patternDeductionCount.get(key) || 0;

    // Cap deductions at 3 per unique pattern
    if (currentCount < 3) {
      const deduction = SEVERITY_POINTS[finding.severity];
      score -= deduction;
      patternDeductionCount.set(key, currentCount + 1);
    }
  }

  // Floor at 0
  return Math.max(0, score);
}

/**
 * Determine overall status from score and findings.
 *
 * Score sets the baseline band. On top of that, a single CRITICAL finding
 * floors the status at FAIL: a high-confidence attack (env exfil, tool
 * poisoning, a concealment directive) is never merely a "WARN," regardless
 * of how few other findings there are. This matters now that the scanner
 * runs two layers instead of five — one real CRITICAL used to be joined by
 * a stacking cross-reference finding that pushed the score down on its own;
 * flooring makes the intent explicit rather than relying on that accident.
 */
export function determineStatus(score: number, findings: Finding[] = []): Status {
  const scoreBand: Status =
    score >= 80 ? 'PASS' : score >= 50 ? 'WARN' : score >= 20 ? 'FAIL' : 'DANGER';

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;

  // Two or more CRITICALs is DANGER; a single CRITICAL floors at FAIL.
  if (criticalCount >= 2) return 'DANGER';
  if (criticalCount === 1) {
    return scoreBand === 'PASS' || scoreBand === 'WARN' ? 'FAIL' : scoreBand;
  }

  return scoreBand;
}

/**
 * Generate recommendation based on status and findings
 */
export function generateRecommendation(
  status: Status,
  findings: Finding[]
): string {
  // Check for critical permission mismatches or exfiltration
  const hasCriticalMismatch = findings.some(
    f => f.severity === 'CRITICAL' && f.category === 'permission-mismatch'
  );

  const hasExfiltration = findings.some(
    f => f.category.includes('exfiltration') || f.title.toLowerCase().includes('exfiltrate')
  );

  const hasPromptInjection = findings.some(
    f => f.category === 'prompt-injection' && f.severity === 'CRITICAL'
  );

  if (hasCriticalMismatch || hasExfiltration) {
    return 'Do not install. Undeclared data exfiltration detected.';
  }

  if (hasPromptInjection) {
    return 'Do not install. Prompt injection attempt detected.';
  }

  switch (status) {
    case 'DANGER':
      return 'Do not install. Skill presents severe security risks.';

    case 'FAIL':
      return 'Do not install without thorough review. Multiple security issues detected.';

    case 'WARN':
      return 'Review recommended. Some security concerns detected.';

    case 'PASS':
      return findings.length === 0
        ? 'Skill appears safe to install.'
        : 'Skill appears relatively safe, but review findings.';

    default:
      return 'Unable to determine safety.';
  }
}

/**
 * Get severity counts from findings
 */
export function getSeverityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  };

  for (const finding of findings) {
    counts[finding.severity]++;
  }

  return counts;
}
