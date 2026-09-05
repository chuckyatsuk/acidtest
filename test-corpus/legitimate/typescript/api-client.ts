// Legitimate: reads one named key, calls one documented endpoint.
const key = process.env.SERVICE_API_KEY;

export async function fetchProfile(id: string): Promise<unknown> {
  if (!key) throw new Error("SERVICE_API_KEY is required");
  const res = await fetch(`https://api.example.com/users/${id}`, {
    headers: { authorization: `Bearer ${key}` },
  });
  return res.json();
}
