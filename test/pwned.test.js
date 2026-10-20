import { test } from "node:test";
import assert from "node:assert/strict";
import { sha1Hex, splitHash, parseRange, checkPassword, API } from "../src/pwned.js";
import { estimateStrength } from "../src/strength.js";

// SHA-1("password") is a well-known test vector.
const PASSWORD_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

const mockFetch = (body, { ok = true, status = 200, calls = [] } = {}) =>
  async (url, opts) => { calls.push({ url, opts }); return { ok, status, text: async () => body }; };

test("sha1Hex matches the known SHA-1 test vector", async () => {
  assert.equal(await sha1Hex("password"), PASSWORD_HASH);
});

test("splitHash returns a 5-char prefix and 35-char suffix", () => {
  const { prefix, suffix } = splitHash(PASSWORD_HASH);
  assert.equal(prefix, "5BAA6");
  assert.equal(suffix.length, 35);
  assert.equal(prefix + suffix, PASSWORD_HASH);
});

test("splitHash rejects anything that is not a SHA-1 hash", () => {
  assert.throws(() => splitHash("not-a-hash"));
});

test("parseRange reads counts and drops padding rows", () => {
  const map = parseRange("AAA:3\r\nBBB:0\r\nccc:12\n\n");
  assert.equal(map.get("AAA"), 3);
  assert.equal(map.has("BBB"), false);
  assert.equal(map.get("CCC"), 12);
});

test("checkPassword only sends the 5-char prefix, never the password or full hash", async () => {
  const calls = [];
  const suffix = PASSWORD_HASH.slice(5);
  const result = await checkPassword("password", mockFetch(`${suffix}:9545824\nABCDEF:2`, { calls }));
  assert.equal(result.count, 9545824);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, API + "5BAA6");
  const sent = calls[0].url.slice(API.length);
  assert.equal(sent, "5BAA6");
  assert.ok(!sent.includes("password"));
  assert.ok(!calls[0].url.includes(suffix));
});

test("checkPassword returns 0 when the suffix is not in the range", async () => {
  const result = await checkPassword("correct horse battery staple x9!", mockFetch("ABCDEF:2"));
  assert.equal(result.count, 0);
});

test("checkPassword throws a readable error on HTTP failure", async () => {
  await assert.rejects(() => checkPassword("abc", mockFetch("", { ok: false, status: 503 })), /HTTP 503/);
});

test("checkPassword retries without padding if the first request fails", async () => {
  let n = 0;
  const flaky = async () => { if (n++ === 0) throw new TypeError("blocked"); return { ok: true, status: 200, text: async () => "" }; };
  const result = await checkPassword("abc", flaky);
  assert.equal(n, 2);
  assert.equal(result.count, 0);
});

test("estimateStrength rates common and long passwords sensibly", () => {
  assert.ok(estimateStrength("password123").score <= 2);
  assert.equal(estimateStrength("orbit-Lantern-77-quiet-Maple").score, 4);
  assert.equal(estimateStrength("").score, 0);
});
