// Print anonymous verdict counts from the checker. Usage:
//   STATS_KEY=... npm run stats [-- days]
const base = process.env.CHECKER_API_URL || "https://php2shell-checker.arjun-basnet.workers.dev";
const key = process.env.STATS_KEY;
const days = Number(process.argv[2] || 30);
if (!key) {
  console.error("Set STATS_KEY, e.g.  STATS_KEY=xxxx npm run stats");
  process.exit(1);
}

const res = await fetch(`${base}/stats`, { headers: { Authorization: `Bearer ${key}` } });
if (!res.ok) {
  console.error(`Stats request failed: HTTP ${res.status}`);
  process.exit(1);
}
const { totals, daily } = await res.json();

const COLS = ["vulnerable", "unknown", "patched", "out-of-range", "unreachable", "rejected"];
const LABELS = { vulnerable: "Vulnerable", unknown: "Can't tell", patched: "Patched", "out-of-range": "Outside range", unreachable: "Unreachable", rejected: "Invalid input" };

const all = COLS.reduce((a, k) => a + (totals[k] || 0), 0);
console.log(`\nAll-time checks: ${all}`);
console.table(Object.fromEntries(COLS.map((k) => [LABELS[k], { checks: totals[k] || 0, share: all ? `${Math.round(((totals[k] || 0) / all) * 100)}%` : "-" }])));

const since = new Date(Date.now() - (days - 1) * 86400000).toISOString().slice(0, 10);
const byDay = {};
for (const { day, verdict, n } of daily) {
  if (day < since) continue;
  byDay[day] ??= Object.fromEntries(COLS.map((k) => [LABELS[k], 0]));
  byDay[day][LABELS[verdict]] += n;
}
console.log(`\nPer day, last ${days} days (UTC):`);
console.table(byDay);
