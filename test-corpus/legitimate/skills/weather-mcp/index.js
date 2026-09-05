// Weather MCP server: reads one named API key, calls one documented endpoint.
const apiKey = process.env.WEATHER_API_KEY;

export async function getWeather(city) {
  if (!apiKey) throw new Error("WEATHER_API_KEY is required");
  const res = await fetch(
    `https://api.weather.example.com/v1/current?city=${encodeURIComponent(city)}&key=${apiKey}`,
  );
  return res.json();
}
