// A simple, explainable strength estimate. It is not a replacement for
// a full estimator like zxcvbn, but it shows the main ideas: length,
// character variety and common patterns.

const COMMON = ["password", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "football", "abc123", "123456"];

export function estimateStrength(pw) {
  const tips = [];
  if (!pw) return { score: 0, label: "Empty", bits: 0, tips: ["Type a password to see its strength."] };

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(pool || 1);

  const lower = pw.toLowerCase();
  if (COMMON.some((w) => lower.includes(w))) { bits *= 0.4; tips.push("Avoid common words like \"password\" or \"qwerty\"."); }
  if (/(.)\1{2,}/.test(pw)) { bits *= 0.8; tips.push("Avoid repeating the same character."); }
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)/i.test(pw)) { bits *= 0.7; tips.push("Avoid sequences like 1234 or abcd."); }
  if (/(19|20)\d{2}$/.test(pw)) { bits *= 0.85; tips.push("A year at the end is easy to guess."); }
  if (pw.length < 12) tips.push("Use at least 12 characters. Three or four random words works well.");

  bits = Math.round(bits);
  const score = bits < 28 ? 1 : bits < 45 ? 2 : bits < 65 ? 3 : 4;
  const label = ["Empty", "Very weak", "Weak", "Good", "Strong"][score];
  return { score, label, bits, tips };
}
