<p align="center">
  <img src="docs/assets/securin-logo-light.png" alt="Securin" height="40">
</p>

<h1 align="center">PHP2Shell Checker</h1>

<p align="center">
  Find out whether a website runs a PHP version affected by <strong>PHP2Shell</strong><br>
  (CVE-2026-109618 / CVE-2026-109619 · Critical · CVSS 9.2)
</p>

<p align="center">
  <a href="https://securin-public.github.io/php2shell-checker/"><strong>Open the checker →</strong></a>
</p>

---

## What

PHP2Shell is the name for two critical memory-safety vulnerabilities (use-after-free, CWE-416) in the PHP runtime. They affect PHP installations that serve web requests, whatever application or framework runs on top.

This project is a free, public web tool. Anyone can enter a domain and learn in seconds whether the PHP version it advertises is affected.

## Why

An unauthenticated attacker can send crafted requests to a vulnerable server and may be able to:

- **execute code** as the web server's PHP worker account,
- **read sensitive memory**, such as sessions, credentials and keys, or
- **corrupt process memory** and disrupt the service.

PHP 8.1 and older are end-of-life and will not receive an upstream fix, so many servers on the internet will stay exposed. A quick, no-install check helps owners find and prioritise them.

## How

1. A visitor enters a domain or URL on the page.
2. A lightweight checker service sends **one passive `GET /`** request and returns the site's `X-Powered-By` header.
3. The page compares the reported PHP version with the fixed releases and shows a verdict.

| Verdict | Meaning |
|---|---|
| 🔴 **Likely vulnerable** | Version is in an affected range, or is a dev/alpha/beta/RC build of a fixed release |
| 🟢 **Not affected by version** | At or above the fixed release for its branch |
| ⚪ **Can't tell** | No header, no PHP version, or a version that was never released |
| 🟠 **Outside the advisory's ranges** | Older than PHP 5.4, which is end-of-life and should be upgraded anyway |

### Fixed versions

| Branch | Upgrade to |
|---|---|
| 8.5 | 8.5.12 or later |
| 8.4 | 8.4.27 or later |
| 8.3 | 8.3.36 or later |
| 8.2 | 8.2.35 or later |
| 8.1 and older | No upstream fix. Move to a supported branch or a vendor package with both fixes backported |

### Limitations

This is a remote **version check**, not an exploit or a configuration audit:

- OS vendors such as Debian, Ubuntu and RHEL often backport fixes without changing the version string, so confirm with your vendor's advisory.
- Many servers hide `X-Powered-By`. A hidden version is not proof of safety, so run `php -v` on the server.
- Only the site's home page is checked.

## Privacy and safety

- One read-only request per check. Nothing is exploited, and response bodies are discarded.
- No targets, results or visitor data are logged or stored.
- Only public hosts on ports 80 and 443 can be checked. Private, loopback, link-local, cloud-metadata and other reserved addresses are refused, both as literals and after DNS resolution.
- Redirects are limited to two, and each hop is re-validated.
- Requests are rate-limited per visitor, and the API answers only the official page's origin.

Only check systems you own or are authorised to assess.

## Demo targets

Two static test sites let you see both verdicts without touching a real server. They only send an `X-Powered-By` header. No PHP runs on them, and there is nothing to exploit.

| Site | Header sent | Expected verdict |
|---|---|---|
| [php2shell-demo-vulnerable.pages.dev](https://securin-public.github.io/php2shell-checker/?target=php2shell-demo-vulnerable.pages.dev) | `PHP/8.1.2-1ubuntu2.20` | 🔴 Likely vulnerable |
| [php2shell-demo-patched.pages.dev](https://securin-public.github.io/php2shell-checker/?target=php2shell-demo-patched.pages.dev) | `PHP/8.4.27` | 🟢 Not affected by version |

Their source is in `demo-targets/`, and they are hosted on Cloudflare Pages (`npm run deploy:demo`).

## Project structure

```
docs/                 Public website (GitHub Pages, no build step)
  js/php2shell.js     Version logic, shared by the website and the checker service
worker/               Checker service (Cloudflare Workers)
  src/index.js        GET /check?target=<domain-or-url>
  src/guard.js        Input validation and network safeguards
demo-targets/         Static demo sites (Cloudflare Pages)
test/                 Unit tests
```

## Development

Requires Node.js 20 or later.

```sh
npm test             # run unit tests
npm run dev:worker   # checker service at http://localhost:8787
npm run dev:site     # website at http://localhost:8080
```

## Deployment

| Component | Platform | Workflow |
|---|---|---|
| Website | GitHub Pages | `.github/workflows/pages.yml`, runs on every push to `main` |
| Checker service | Cloudflare Workers | `.github/workflows/worker.yml`, or `npm run deploy:worker` |
| Demo targets | Cloudflare Pages | `npm run deploy:demo` |

Configuration:

- **Repository variable** `CHECKER_API_URL`: the public URL of the checker service.
- **Repository secrets** `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`: needed for automated checker deployments.
- `ALLOWED_ORIGINS` in `worker/wrangler.toml`: the website origins allowed to call the checker.

## References

- [PHP.net release announcement](https://www.php.net/index.php#2026-10-21-5)
- [PHP security advisory GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP security advisory GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Wiz research: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)

## Disclaimer

This tool is provided as-is for defensive purposes, and results are indicative only. Always verify on the affected system and follow your vendor's guidance.

---

<p align="center">© 2026 <a href="https://www.securin.io/">Securin Inc.</a> All rights reserved.</p>
