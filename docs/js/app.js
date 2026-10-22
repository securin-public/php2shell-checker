import { assess, FIXED } from "./php2shell.js";
import { API_BASE } from "./config.js";

const root = document.documentElement;
const toggle = document.getElementById("themeToggle");
const form = document.getElementById("checkForm");
const input = document.getElementById("target");
const button = document.getElementById("checkBtn");
const resultEl = document.getElementById("result");

// Theme: light by default, remembered per browser.
function setTheme(theme) {
  root.dataset.theme = theme;
  toggle.setAttribute("aria-label", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  try { localStorage.setItem("theme", theme); } catch {}
}
toggle.addEventListener("click", () => setTheme(root.dataset.theme === "dark" ? "light" : "dark"));
setTheme(root.dataset.theme === "dark" ? "dark" : "light");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = input.value.trim();
  if (!target) { input.focus(); return; }
  if (!API_BASE) {
    render({ tone: "warn", icon: "!", title: "Checker not configured", body: "<p>The checker service URL hasn't been set for this deployment yet.</p>" });
    return;
  }

  setLoading(true);
  try {
    const res = await fetch(`${API_BASE}/check?target=${encodeURIComponent(target)}`, { headers: { Accept: "application/json" } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      render({ tone: "warn", icon: "!", title: "Couldn't check that site", body: `<p>${esc(data.error || `Checker returned HTTP ${res.status}.`)}</p>` });
      return;
    }
    renderVerdict(data);
  } catch {
    render({ tone: "warn", icon: "!", title: "Checker unavailable", body: "<p>We couldn't reach the checker service. Try again in a moment.</p>" });
  } finally {
    setLoading(false);
  }
});

// Supports shareable links (?target=example.com) and submits made before this module loaded,
// which fall back to a native GET of the form.
const initial = new URLSearchParams(location.search).get("target");
if (initial) {
  input.value = initial;
  form.requestSubmit();
}

function setLoading(on) {
  button.disabled = on;
  button.classList.toggle("is-loading", on);
  button.querySelector(".btn__label").textContent = on ? "Checking…" : "Check";
}

function renderVerdict(data) {
  const a = assess(data.xPoweredBy);
  const facts = [
    ["Checked", data.finalUrl],
    ["HTTP status", data.httpStatus],
    ["X-Powered-By", data.xPoweredBy || "— (not sent)"],
    ["Server", data.server || "— (not sent)"],
  ];
  const distroNote = a.distroBuild
    ? `<p class="note">The version string <code>${esc(a.version.full)}</code> looks like an OS vendor build. Vendors often backport fixes without changing the upstream version, so check your distribution's security advisory before acting.</p>`
    : `<p class="note">This is a passive version check. OS vendor packages may contain backported fixes, so confirm against your vendor's advisory.</p>`;

  const views = {
    vulnerable: {
      tone: "vulnerable", icon: "!",
      title: `Likely vulnerable — PHP ${a.version?.full}`,
      body: `<p>${vulnReason(a)}</p><p><strong>Fix:</strong> ${fixAdvice(a)}</p>`,
    },
    patched: {
      tone: "patched", icon: "✓",
      title: `Not affected by version — PHP ${a.version?.full}`,
      body: "<p>The reported PHP version includes the fixes for CVE-2026-109618 and CVE-2026-109619.</p>",
    },
    "out-of-range": {
      tone: "warn", icon: "?",
      title: `End-of-life — PHP ${a.version?.full}`,
      body: `<p>PHP ${esc(a.branch)} is end-of-life. The PHP project doesn't say whether it is affected by these two vulnerabilities, and it no longer receives any security fixes.</p>
             <p><strong>Recommended:</strong> upgrade to a supported release (${SUPPORTED}).</p>`,
    },
    unrecognised: {
      tone: "unknown", icon: "?",
      title: `Can't tell — PHP ${a.version?.full} isn't a real release`,
      body: "<p>The site advertises a PHP version that was never released, so the header is probably fake or customised.</p><p>Check the real version on the server with <code>php -v</code>.</p>",
    },
    "no-php-header": {
      tone: "unknown", icon: "?",
      title: "Can't tell — no PHP version advertised",
      body: "<p>The site sends <code>X-Powered-By</code>, but it doesn't contain a PHP version.</p><p>It may not run PHP, or PHP may sit behind a different path or host.</p>",
    },
    "no-header": {
      tone: "unknown", icon: "?",
      title: "Can't tell — version is hidden",
      body: "<p>The site doesn't send an <code>X-Powered-By</code> header. That's good hardening, but it isn't proof of safety.</p><p>If the site runs PHP, run <code>php -v</code> on the server.</p>",
    },
  };

  const v = views[a.status];
  const showNote = a.status === "vulnerable" || a.status === "patched";
  render({ ...v, title: esc(v.title), body: v.body + factsHtml(facts) + (showNote ? distroNote : "") });
}

const SUPPORTED = Object.values(FIXED).join(", ") + " or later";

function vulnReason(a) {
  if (!a.version) return ""; // views are built for every status; only used when a version exists
  if (a.version.base === "8.6.0") return "This is a PHP 8.6.0 pre-release build from before RC4, which predates the fixes.";
  if (a.prerelease) return "This is a pre-release build of a fixed version, which predates the fix.";
  if (a.eol) return `PHP ${esc(a.branch)} is end-of-life. The PHP security team published a source backport of the CVE-2026-109618 and CVE-2026-109619 fixes for this branch, so treat it as affected.`;
  return `PHP ${esc(a.version.base)} is earlier than the fixed release for CVE-2026-109618 and CVE-2026-109619.`;
}

function fixAdvice(a) {
  if (!a.version) return "";
  if (a.version.base === "8.6.0") return "update to PHP 8.6.0RC4 or later. Pre-releases are not for production, so a stable release is better.";
  if (a.fixedIn) return `upgrade to PHP ${esc(a.fixedIn)} or later.`;
  return `PHP ${esc(a.branch)} gets no official release from the PHP project. Upgrade to a supported release (${SUPPORTED}), install your OS or LTS vendor's backported package, or apply the PHP security team's source backport if you build PHP from source.`;
}

function factsHtml(rows) {
  return `<dl class="facts">${rows.map(([k, val]) => `<dt>${esc(k)}</dt><dd>${esc(val)}</dd>`).join("")}</dl>`;
}

function render({ tone, icon, title, body }) {
  resultEl.className = `result result--${tone === "warn" ? "warn" : tone}`;
  resultEl.innerHTML = `<div class="result__head"><span class="result__icon">${icon}</span><h2>${title}</h2></div>${body}`;
  resultEl.hidden = false;
  resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
