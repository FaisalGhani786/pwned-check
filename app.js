import { sha1Hex, splitHash, checkPassword } from "./src/pwned.js";
import { estimateStrength } from "./src/strength.js";

const $ = (id) => document.getElementById(id);
const pw = $("pw"), form = $("form"), go = $("go"), result = $("result");
const meterBars = [...$("meter").children];
const colours = ["var(--raise)", "var(--bad)", "var(--warn)", "var(--accent)", "var(--good)"];
const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

$("toggle").addEventListener("click", (e) => {
  const show = pw.type === "password";
  pw.type = show ? "text" : "password";
  e.currentTarget.textContent = show ? "Hide" : "Show";
  e.currentTarget.setAttribute("aria-pressed", String(show));
});

async function renderLive() {
  const value = pw.value;
  const s = estimateStrength(value);
  meterBars.forEach((bar, i) => { bar.style.background = i < s.score ? colours[s.score] : colours[0]; });
  $("sLabel").textContent = s.label;
  $("sBits").textContent = `about ${s.bits} bits`;
  $("tips").innerHTML = value ? s.tips.map((t) => `<li>${esc(t)}</li>`).join("") : "";

  if (!value) {
    $("hash").innerHTML = '<span class="ph">' + "0".repeat(40) + "</span>";
    $("prefix").textContent = "-----";
    $("suffix").textContent = "-".repeat(35);
    return;
  }
  const { prefix, suffix } = splitHash(await sha1Hex(value));
  if (pw.value !== value) return; // a newer keystroke has already rendered
  $("hash").innerHTML = `<span class="p">${prefix}</span><span class="s">${suffix}</span>`;
  $("prefix").textContent = prefix;
  $("suffix").textContent = suffix;
}
pw.addEventListener("input", renderLive);

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!pw.value) { pw.focus(); return; }
  go.disabled = true; go.textContent = "Checking…";
  const lane = $("laneSent");
  lane.classList.remove("flash"); void lane.offsetWidth; lane.classList.add("flash");
  try {
    const { count, candidates } = await checkPassword(pw.value);
    if (count > 0) {
      result.className = "result bad";
      result.innerHTML = `<h2>Found in <span class="num">${count.toLocaleString("en-GB")}</span> breach${count === 1 ? "" : "es"}</h2>
        <p>This password has appeared in public data breaches, so attackers already have it in their wordlists. Stop using it everywhere and switch to a unique password from a password manager.</p>`;
    } else {
      result.className = "result good";
      result.innerHTML = `<h2>Not found in any known breach</h2>
        <p>None of the ${candidates.toLocaleString("en-GB")} leaked hashes with the same prefix matched yours. That's good, but it doesn't make a password strong, so check the strength meter too.</p>`;
    }
  } catch (err) {
    result.className = "result";
    result.innerHTML = `<h2>Couldn't reach the breach database</h2><p>${esc(err.message || "Check your connection and try again.")}</p>`;
  } finally {
    go.disabled = false; go.textContent = "Check";
  }
});
