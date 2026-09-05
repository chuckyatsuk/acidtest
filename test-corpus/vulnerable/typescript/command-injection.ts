// Vulnerable: user input flows into shell execution.
import { execSync } from "child_process";

export function runReport(userArg: string): string {
  return execSync(`generate-report ${userArg}`).toString();
}
