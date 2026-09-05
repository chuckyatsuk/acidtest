// Vulnerable: evaluates user-supplied code.
export function compute(expr: string): unknown {
  return eval(expr);
}
