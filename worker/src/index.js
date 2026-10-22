// PHP2Shell checker — one passive GET / per check, returns X-Powered-By and a verdict.
import { assess, CVES } from "../../docs/js/php2shell.js";
import { normaliseTarget, checkUrl, isBlockedIp, InputError } from "./guard.js";
import { bucketFor } from "./buckets.js";

export { Stats } from "./stats.js";

const MAX_REDIRECTS = 2;
const TIMEOUT_MS = 8000;
const UA = "Securin-PHP2Shell-Checker/1.0 (+https://github.com/securin-public/php2shell-checker)";

export default {
  async fetch(request, env, ctx) {
    const cors = corsHeaders(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const { pathname, searchParams } = new URL(request.url);
    if (pathname === "/health") return json({ ok: true }, 200, cors);
    if (pathname === "/stats" && request.method === "GET") return stats(request, env, cors);
    if (pathname !== "/check" || request.method !== "GET") return json({ error: "Not found" }, 404, cors);
    if (!cors["Access-Control-Allow-Origin"] && request.headers.get("Origin")) {
      return json({ error: "Origin not allowed" }, 403, cors);
    }

    if (env.LIMITER) {
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const { success } = await env.LIMITER.limit({ key: ip });
      if (!success) return json({ error: "Too many checks — wait a minute and try again." }, 429, cors);
    }

    // Count the outcome only; the target is never passed to the counter.
    const count = (verdict) => env.STATS && ctx.waitUntil(statsStub(env).record(verdict).catch(() => {}));

    const raw = searchParams.get("target");
    try {
      const target = normaliseTarget(raw);
      const explicitScheme = /^https?:\/\//i.test(String(raw).trim());
      const result = await probe(target, explicitScheme);
      const assessment = assess(result.xPoweredBy);
      count(bucketFor(assessment.status));
      return json(
        {
          input: raw,
          ...result,
          assessment,
          cves: CVES,
          checkedAt: new Date().toISOString(),
        },
        200,
        cors
      );
    } catch (err) {
      if (err instanceof InputError) {
        count("rejected");
        return json({ error: err.message }, 400, cors);
      }
      count("unreachable");
      return json({ error: "The site could not be reached.", detail: String(err?.message || err) }, 502, cors);
    }
  },
};

function statsStub(env) {
  return env.STATS.get(env.STATS.idFromName("global"));
}

// Aggregate counts for the stats page, behind a bearer key (STATS_KEY secret).
async function stats(request, env, cors) {
  const key = env.STATS_KEY || "";
  const given = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const enc = new TextEncoder();
  const ok =
    key.length > 0 &&
    given.length === key.length &&
    crypto.subtle.timingSafeEqual(enc.encode(given), enc.encode(key));
  if (!ok) return json({ error: "Unauthorized" }, 401, cors);
  return json(await statsStub(env).summary(90), 200, cors);
}

async function probe(target, explicitScheme) {
  try {
    return await fetchWithRedirects(target);
  } catch (err) {
    // Bare domain: fall back to http:// when https:// is unreachable.
    if (!explicitScheme && target.protocol === "https:" && !(err instanceof InputError)) {
      return await fetchWithRedirects(new URL(`http://${target.host}/`));
    }
    throw err;
  }
}

async function fetchWithRedirects(start) {
  let url = start;
  for (let hop = 0; ; hop++) {
    checkUrl(url);
    await assertPublicDns(url.hostname);
    const res = await fetch(url.toString(), {
      method: "GET",
      redirect: "manual",
      headers: { "User-Agent": UA, Accept: "text/html,*/*;q=0.8" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    // Headers are all we need; don't download bodies.
    res.body?.cancel();

    const location = res.headers.get("Location");
    if (res.status >= 300 && res.status < 400 && location && hop < MAX_REDIRECTS) {
      url = new URL(location, url);
      continue;
    }
    return {
      finalUrl: url.toString(),
      httpStatus: res.status,
      xPoweredBy: res.headers.get("X-Powered-By"),
      server: res.headers.get("Server"),
    };
  }
}

// Resolve via DNS-over-HTTPS and refuse names that point at private/reserved space.
// This is defence in depth: Workers can't pin fetch() to the checked IP, so a DNS-rebinding
// race remains possible. The hard boundary is that Worker egress leaves Cloudflare's edge and
// cannot reach RFC1918, loopback or cloud-metadata addresses of any network.
async function assertPublicDns(hostname) {
  if (/^[\d.]+$/.test(hostname) || hostname.startsWith("[")) return; // IP literal, already checked
  const answers = await Promise.all(
    ["A", "AAAA"].map(async (type) => {
      const r = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`,
        { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(TIMEOUT_MS) }
      );
      if (!r.ok) return [];
      const body = await r.json();
      return (body.Answer || []).filter((a) => a.type === 1 || a.type === 28).map((a) => a.data);
    })
  );
  const ips = answers.flat();
  if (ips.length === 0) throw new InputError("That domain doesn't resolve to an address.");
  if (ips.some(isBlockedIp)) throw new InputError("That domain points to a private or reserved address.");
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const headers = {
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
  if (origin && allowed.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function json(body, status, extra) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
}
