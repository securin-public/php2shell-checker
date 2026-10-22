// Anonymous usage counters: one row per (UTC day, verdict). No domains, IPs or results are kept.
import { DurableObject } from "cloudflare:workers";
import { VERDICTS } from "./buckets.js";

export class Stats extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS counts (day TEXT NOT NULL, verdict TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, verdict))"
    );
  }

  record(verdict) {
    if (!VERDICTS.includes(verdict)) return;
    const day = new Date().toISOString().slice(0, 10);
    this.ctx.storage.sql.exec(
      "INSERT INTO counts (day, verdict, n) VALUES (?, ?, 1) ON CONFLICT (day, verdict) DO UPDATE SET n = n + 1",
      day,
      verdict
    );
  }

  summary(days = 90) {
    const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
    const daily = this.ctx.storage.sql
      .exec("SELECT day, verdict, n FROM counts WHERE day >= ? ORDER BY day", since)
      .toArray();
    const totals = Object.fromEntries(VERDICTS.map((v) => [v, 0]));
    for (const row of this.ctx.storage.sql.exec("SELECT verdict, SUM(n) AS n FROM counts GROUP BY verdict")) {
      totals[row.verdict] = row.n;
    }
    return { totals, daily, since };
  }
}
