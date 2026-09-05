// Pure CSV → markdown table transformation. No I/O beyond the input string.
export function toMarkdownTable(csv: string): string {
  const rows = csv
    .trim()
    .split("\n")
    .map((line) => line.split(",").map((c) => c.trim()));

  if (rows.length === 0) return "";

  const widths = rows[0].map((_, col) =>
    Math.max(...rows.map((r) => (r[col] ?? "").length)),
  );

  const render = (r: string[]) =>
    "| " + r.map((c, i) => (c ?? "").padEnd(widths[i])).join(" | ") + " |";

  const header = render(rows[0]);
  const divider = "| " + widths.map((w) => "-".repeat(w)).join(" | ") + " |";
  const body = rows.slice(1).map(render).join("\n");

  return [header, divider, body].join("\n");
}
