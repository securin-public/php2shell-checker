import { API_BASE } from "./config.js";

// Stack order matters: grey "unknown" separates red and green for colour-blind readers.
const SERIES = [
  { key: "vulnerable", label: "Vulnerable" },
  { key: "unknown", label: "Can't tell" },
  { key: "patched", label: "Patched" },
  { key: "out-of-range", label: "Outside range (EOL)" },
];
const KEY_STORE = "statsKey";

const root = document.documentElement;
const $ = (id) => document.getElementById(id);
const toggle = $("themeToggle");
let data = null;
let days = 30;

function setTheme(theme) {
  root.dataset.theme = theme;
  toggle.setAttribute("aria-label", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  try { localStorage.setItem("theme", theme); } catch {}
}
toggle.addEventListener("click", () => setTheme(root.dataset.theme === "dark" ? "light" : "dark"));
setTheme(root.dataset.theme === "dark" ? "dark" : "light");

function savedKey() { try { return sessionStorage.getItem(KEY_STORE) || ""; } catch { return ""; } }
function saveKey(k) { try { k ? sessionStorage.setItem(KEY_STORE, k) : sessionStorage.removeItem(KEY_STORE); } catch {} }

async function load(key) {
  const res = await fetch(`${API_BASE}/stats`, { headers: { Authorization: `Bearer ${key}` } });
  if (res.status === 401) throw new Error("That key isn't valid.");
  if (!res.ok) throw new Error(`Stats service returned HTTP ${res.status}.`);
  return res.json();
}

async function start(key) {
  try {
    data = await load(key);
    saveKey(key);
    $("keyForm").hidden = true;
    $("controls").hidden = false;
    $("content").hidden = false;
    render();
  } catch (err) {
    saveKey("");
    $("keyForm").hidden = false;
    $("keyErr").textContent = key ? err.message : "";
  }
}

$("keyForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector(".btn");
  btn.disabled = true; btn.classList.add("is-loading");
  await start($("key").value.trim());
  btn.disabled = false; btn.classList.remove("is-loading");
});
$("signOut").addEventListener("click", () => {
  saveKey(""); data = null;
  $("content").hidden = true; $("controls").hidden = true; $("keyForm").hidden = false; $("key").value = "";
});
document.querySelectorAll(".seg button").forEach((b) =>
  b.addEventListener("click", () => {
    days = Number(b.dataset.days);
    document.querySelectorAll(".seg button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    render();
  })
);

// Build one row per UTC day in the window, zero-filled.
function window_() {
  const rows = [];
  const today = new Date(new Date().toISOString().slice(0, 10) + "T00:00:00Z");
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000).toISOString().slice(0, 10);
    rows.push({ day: d, vulnerable: 0, patched: 0, unknown: 0, "out-of-range": 0, unreachable: 0, rejected: 0 });
  }
  const byDay = new Map(rows.map((r) => [r.day, r]));
  for (const { day, verdict, n } of data.daily) if (byDay.has(day) && verdict in byDay.get(day)) byDay.get(day)[verdict] += n;
  return rows;
}

const sum = (rows, k) => rows.reduce((a, r) => a + r[k], 0);
const fmt = (n) => n.toLocaleString("en-US");
const pct = (n, total) => (total ? `${Math.round((n / total) * 100)}%` : "–");
const dayLabel = (d) => new Date(d + "T00:00:00Z").toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });

function render() {
  const rows = window_();
  const t = Object.fromEntries(["vulnerable", "patched", "unknown", "out-of-range", "unreachable", "rejected"].map((k) => [k, sum(rows, k)]));
  const assessed = t.vulnerable + t.patched + t.unknown + t["out-of-range"];
  const notChecked = t.unreachable + t.rejected;
  const total = assessed + notChecked;
  const allTime = Object.values(data.totals).reduce((a, b) => a + b, 0);

  const tile = (label, value, sub, color, extra = "") =>
    `<div class="tile ${extra}"><div class="tile__k">${color ? `<span class="tile__dot" style="background:${color}"></span>` : ""}${label}</div>
     <div class="tile__v">${fmt(value)}</div><div class="tile__s">${sub}</div></div>`;
  $("tiles").innerHTML =
    tile("Total checks", total, `${fmt(allTime)} all time`, "", "tile--total") +
    SERIES.map((s) => tile(s.label, t[s.key], `${pct(t[s.key], assessed)} of assessed`, `var(--s-${s.key})`)).join("") +
    tile("Not checked", notChecked, `${fmt(t.unreachable)} unreachable · ${fmt(t.rejected)} invalid`, "");

  $("legend").innerHTML = SERIES.map((s) => `<li><i style="background:var(--s-${s.key})"></i>${s.label}</li>`).join("");
  renderChart(rows);
  renderTable(rows);
  $("updated").textContent = `Updated ${new Date().toLocaleString()} · times are UTC days.`;
}

function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function renderChart(rows) {
  const chart = $("chart");
  const stackTotal = (r) => SERIES.reduce((a, s) => a + r[s.key], 0);
  const max = niceMax(Math.max(0, ...rows.map(stackTotal)));
  const ticks = [0, max / 2, max];
  chart.setAttribute("aria-label", `Stacked bar chart of checks per day over the last ${days} days. Use the table view for exact numbers.`);
  chart.innerHTML = `
    <div class="chart__axis">${ticks.map((v) => `<span style="bottom:${(v / max) * 100}%">${fmt(v)}</span>`).join("")}</div>
    <div class="chart__plot">
      ${ticks.slice(1).map((v) => `<div class="chart__grid" style="bottom:${(v / max) * 100}%"></div>`).join("")}
      <div class="chart__bars">${rows
        .map((r, i) => `<div class="chart__col" data-i="${i}">${SERIES.filter((s) => r[s.key] > 0)
          .map((s) => `<div class="chart__seg" style="height:calc(${(r[s.key] / max) * 100}% - 2px);background:var(--s-${s.key})"></div>`)
          .join("")}</div>`)
        .join("")}</div>
      ${rows.every((r) => stackTotal(r) === 0) ? `<div class="chart__empty">No checks in this period yet.</div>` : ""}
    </div>`;
  const x = document.createElement("div");
  x.className = "chart__x";
  x.innerHTML = `<span>${dayLabel(rows[0].day)}</span><span>${dayLabel(rows[rows.length - 1].day)}</span>`;
  chart.after(x);
  chart.parentElement.querySelectorAll(".chart__x").forEach((el) => el !== x && el.remove());

  const tip = $("tip");
  const card = chart.closest(".chartcard");
  chart.querySelectorAll(".chart__col").forEach((col) => {
    col.addEventListener("mouseenter", () => {
      const r = rows[Number(col.dataset.i)];
      tip.innerHTML = `<strong>${dayLabel(r.day)}</strong>${SERIES.map((s) =>
        `<div><span><i style="background:var(--s-${s.key})"></i>${s.label}</span><span>${fmt(r[s.key])}</span></div>`).join("")}
        <div><span>Not checked</span><span>${fmt(r.unreachable + r.rejected)}</span></div>`;
      tip.hidden = false;
      const c = col.getBoundingClientRect(), k = card.getBoundingClientRect();
      const left = Math.min(c.left - k.left + c.width / 2 + 10, k.width - tip.offsetWidth - 8);
      tip.style.left = `${Math.max(8, left)}px`;
      tip.style.top = `${c.top - k.top + 10}px`;
    });
    col.addEventListener("mouseleave", () => { tip.hidden = true; });
  });
}

function renderTable(rows) {
  const cols = [...SERIES, { key: "nc", label: "Not checked" }];
  $("table").innerHTML = `<thead><tr><th>Day</th>${cols.map((c) => `<th>${c.label}</th>`).join("")}</tr></thead><tbody>${rows
    .slice()
    .reverse()
    .map((r) => `<tr><td>${r.day}</td>${cols.map((c) => `<td>${fmt(c.key === "nc" ? r.unreachable + r.rejected : r[c.key])}</td>`).join("")}</tr>`)
    .join("")}</tbody>`;
}

const k = savedKey();
if (k) start(k); else $("keyForm").hidden = false;
