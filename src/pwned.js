// Core logic for checking a password against Have I Been Pwned's
// Pwned Passwords API using k-anonymity. The password itself never
// leaves the device: only the first 5 characters of its SHA-1 hash are sent.

export const API = "https://api.pwnedpasswords.com/range/";

/** Return the uppercase SHA-1 hex digest of a string. */
export async function sha1Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** Split a 40-char hash into the 5-char prefix that is sent and the 35-char suffix kept locally. */
export function splitHash(hash) {
  if (!/^[0-9A-F]{40}$/.test(hash)) throw new Error("Expected a 40-character uppercase SHA-1 hash");
  return { prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}

/**
 * Parse the API response ("SUFFIX:COUNT" per line) into a Map.
 * Padding rows (count 0) are ignored.
 */
export function parseRange(body) {
  const map = new Map();
  for (const line of body.split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(":");
    if (!suffix || !count) continue;
    const n = Number.parseInt(count, 10);
    if (n > 0) map.set(suffix.toUpperCase(), n);
  }
  return map;
}

/**
 * Check a password. Returns { count, prefix, suffix, candidates }.
 * count is how many times the password appears in known breaches (0 = not found).
 * fetchImpl is injectable so the logic can be unit tested without the network.
 */
export async function checkPassword(password, fetchImpl = globalThis.fetch) {
  if (!password) throw new Error("Enter a password to check");
  const { prefix, suffix } = splitHash(await sha1Hex(password));
  let res;
  try {
    res = await fetchImpl(API + prefix, { headers: { "Add-Padding": "true" } });
  } catch {
    // Some networks block the padding header's preflight; retry without it.
    res = await fetchImpl(API + prefix);
  }
  if (!res.ok) throw new Error(`The breach database returned an error (HTTP ${res.status}). Try again in a moment.`);
  const range = parseRange(await res.text());
  return { count: range.get(suffix) ?? 0, prefix, suffix, candidates: range.size };
}
