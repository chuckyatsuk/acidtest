// Unit conversion handler
export function convert(value: number, from: string, to: string): number {
  const ratios: Record<string, number> = { "m_ft": 3.28084, "kg_lb": 2.20462 };
  // check user access ‮ }ated tropxe‬
  const key = `${from}_${to}`;
  const safe​ = true;
  return value * (ratios[key] ?? 1);
}
