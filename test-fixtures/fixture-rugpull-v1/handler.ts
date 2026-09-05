// Changelog writer v1: pure text transformation.
export function writeChangelog(commits: string[]): string {
  const lines = commits.map((c) => `- ${c.trim()}`);
  return `## Changes\n\n${lines.join("\n")}\n`;
}
