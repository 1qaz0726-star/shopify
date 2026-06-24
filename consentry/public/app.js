// app.js — client logic for the Consentry scan flow.
// All user-derived strings are rendered via textContent (never innerHTML) to
// keep the report XSS-safe.

const form = document.getElementById("scan-form");
const input = document.getElementById("store-url");
const button = document.getElementById("scan-btn");
const errorEl = document.getElementById("scan-error");
const resultEl = document.getElementById("result");

const SCAN_STEPS = [
  "Fetching storefront…",
  "Parsing scripts & pixels…",
  "Checking for a consent layer…",
  "Scoring compliance…",
];

const ICON = { critical: "!", warning: "!", info: "i", good: "✓" };
const GAUGE_COLOR = { critical: "#b23a2e", warning: "#b9802a", good: "#2f6b4f" };
const VERDICT_TITLE = {
  critical: "Action needed",
  warning: "Worth a closer look",
  good: "Looking clean",
};

function showError(message) {
  errorEl.textContent = message;
  errorEl.hidden = false;
}
function clearError() {
  errorEl.hidden = true;
  errorEl.textContent = "";
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

let stepTimer = null;
function renderScanning() {
  resultEl.hidden = false;
  resultEl.replaceChildren();
  const wrap = el("div", "scanning");
  const bar = el("div", "scanning__bar");
  bar.appendChild(el("i"));
  const list = el("ul", "scanning__steps");
  SCAN_STEPS.forEach((s) => list.appendChild(el("li", null, s)));
  wrap.append(bar, list);
  resultEl.appendChild(wrap);

  const items = [...list.children];
  let i = 0;
  items[0].classList.add("active");
  stepTimer = setInterval(() => {
    items[i].classList.remove("active");
    items[i].classList.add("done");
    i += 1;
    if (i < items.length) items[i].classList.add("active");
    else clearInterval(stepTimer);
  }, 650);
}

function stopScanning() {
  if (stepTimer) clearInterval(stepTimer);
  stepTimer = null;
}

function animateGauge(gauge, target) {
  let cur = 0;
  const numEl = gauge.querySelector(".gauge__num");
  const tick = () => {
    cur += Math.max(1, Math.round((target - cur) / 6));
    if (cur >= target) cur = target;
    gauge.style.setProperty("--val", cur);
    numEl.textContent = cur;
    if (cur < target) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function renderResult(data) {
  resultEl.replaceChildren();
  const report = el("div", "report");

  // Head: gauge + verdict
  const head = el("div", "report__head");
  const gauge = el("div", "gauge");
  gauge.style.setProperty("--gauge-color", GAUGE_COLOR[data.level] || GAUGE_COLOR.warning);
  gauge.append(el("span", "gauge__num", "0"), el("span", "gauge__den", "/ 100"));
  head.appendChild(gauge);

  const verdict = el("div", "report__verdict");
  verdict.appendChild(el("span", `badge badge--${data.level}`, (VERDICT_TITLE[data.level] || "Result").toUpperCase()));
  verdict.appendChild(el("h2", null, headline(data)));
  verdict.appendChild(el("p", "report__url", displayUrl(data)));
  head.appendChild(verdict);
  report.appendChild(head);

  // Findings
  const list = el("ul", "findings");
  (data.findings || []).forEach((f) => {
    const li = el("li", `finding finding--${f.severity}`);
    li.appendChild(el("span", "finding__icon", ICON[f.severity] || "i"));
    const body = el("div");
    body.appendChild(el("h4", null, f.title));
    body.appendChild(el("p", null, f.detail));
    li.appendChild(body);
    list.appendChild(li);
  });
  report.appendChild(list);

  // Foot: CTA to the app
  const foot = el("div", "report__foot");
  foot.appendChild(el("p", null, footMessage(data)));
  const cta = el("a", "btn btn--solid", "Fix this automatically");
  cta.href = "#waitlist-form";
  foot.appendChild(cta);
  report.appendChild(foot);

  resultEl.appendChild(report);
  animateGauge(gauge, clampScore(data.score));
  resultEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

function clampScore(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  return Math.min(100, Math.max(0, Math.round(v)));
}

function headline(data) {
  const n = (data.trackers || []).length;
  if (data.level === "critical") return `${n} tracker${n === 1 ? "" : "s"} firing before consent`;
  if (data.level === "warning") return "Consent layer found, but verify it blocks";
  return "No major pixels firing on load";
}

function displayUrl(data) {
  try {
    return new URL(data.finalUrl || data.url).host;
  } catch {
    return data.url || "";
  }
}

function footMessage(data) {
  if (data.level === "good") return "Nice. Keep it that way as you add marketing tools.";
  return "Consentry can block these until each visitor consents — no code.";
}

async function runScan(rawUrl) {
  clearError();
  button.disabled = true;
  button.textContent = "Scanning…";
  renderScanning();

  const startedAt = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
      signal: controller.signal,
    });
    const data = await res.json().catch(() => ({}));
    // Let the scanning animation breathe for a beat so it doesn't flash.
    const elapsed = Date.now() - startedAt;
    if (elapsed < 1600) await new Promise((r) => setTimeout(r, 1600 - elapsed));
    stopScanning();

    if (!res.ok) {
      resultEl.hidden = true;
      resultEl.replaceChildren();
      showError(data.error || "We couldn't scan that store. Please try again.");
      return;
    }
    renderResult(data);
  } catch (err) {
    stopScanning();
    resultEl.hidden = true;
    resultEl.replaceChildren();
    showError(
      err && err.name === "AbortError"
        ? "That took too long — the store may be slow. Try again."
        : "Network hiccup — please try again in a moment.",
    );
  } finally {
    clearTimeout(timeout);
    button.disabled = false;
    button.textContent = "Scan my store";
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const value = input.value.trim();
  if (!value) {
    showError("Enter your store's web address to scan it.");
    input.focus();
    return;
  }
  runScan(value);
});

// --- Waitlist (Phase 0: capture intent locally) ---------------------------
const waitlistForm = document.getElementById("waitlist-form");
const waitlistEmail = document.getElementById("waitlist-email");
const waitlistMsg = document.getElementById("waitlist-msg");

waitlistForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const email = waitlistEmail.value.trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    waitlistMsg.hidden = false;
    waitlistMsg.textContent = "That email doesn't look right — mind checking it?";
    return;
  }
  waitlistMsg.hidden = false;
  waitlistMsg.textContent = "You're on the list. We'll be in touch when your spot opens.";
  waitlistEmail.value = "";
  waitlistEmail.disabled = true;
});
