<p align="center">
  <img src="docs/assets/securin-logo-light.png" alt="Securin" height="40">
</p>

<h1 align="center">Am I Vulnerable to PHP2Shell?</h1>

<p align="center">
  Find out whether a website runs a PHP version affected by <strong>PHP2Shell</strong><br>
  (<a href="https://www.securin.io/vulnerability-database/cve/CVE-2026-109618">CVE-2026-109618</a> / <a href="https://www.securin.io/vulnerability-database/cve/CVE-2026-109619">CVE-2026-109619</a> · Critical · CVSS 9.2)
</p>

<p align="center">
  <a href="https://securin-public.github.io/php2shell-checker/"><strong>Open the checker →</strong></a>
</p>

---

## What

PHP2Shell is the name researchers gave to two critical memory-safety vulnerabilities (use-after-free, CWE-416) in the PHP runtime. According to the PHP project, all PHP installations serving web requests are at risk, including PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed. Risk is highest for mod_php.

This project is a free, public web tool. Anyone can enter a domain and learn in seconds whether the PHP version it advertises is affected.

## Why

An unauthenticated attacker can send crafted requests to a vulnerable server and may be able to:

- **execute code** as the web server's PHP worker account,
- **read sensitive memory**, such as sessions, credentials and keys, or
- **corrupt process memory** and disrupt the service.

The PHP project states there is no complete workaround, and updating is the only safe choice. PHP 8.1 and older are end-of-life and get no official release; only source-code backports (7.4, 8.0, 8.1) or OS/LTS vendor packages are available. A quick, no-install check helps owners find and prioritise exposed servers.

## How

1. A visitor enters a domain or URL on the page.
2. A lightweight checker service sends **one passive `GET /`** request. It reads the PHP version from the `X-Powered-By` or `Server` header and looks in the same response for signs the site runs PHP (PHP session cookies, `.php` links, WordPress/Drupal/Joomla/Laravel/Magento markers).
3. The page compares the reported PHP version with the fixed releases and shows a verdict.

| Verdict | Meaning |
|---|---|
| 🔴 **Likely vulnerable** | 7.4 – 8.5 below the fixed release, a pre-release build of a fixed release, or a PHP 8.6.0 build before RC4 |
| 🟢 **Not affected by version** | At or above the fixed release for its branch |
| ⚪ **Runs PHP, version hidden** | The site shows PHP signs but doesn't reveal its version. Check with `php -v` |
| ⚪ **Can't tell** | No PHP version or PHP signs, or a version that was never released |
| 🟠 **End-of-life** | PHP 7.3 or older: not covered by the advisory and no longer receiving any security fixes |

### Fixed versions

| Branch | Upgrade to |
|---|---|
| 8.5 | 8.5.12 or later |
| 8.4 | 8.4.27 or later |
| 8.3 | 8.3.36 or later |
| 8.2 | 8.2.35 or later |
| 8.1, 8.0, 7.4 | No official release. Upgrade, use an OS/LTS vendor's backported package, or apply PHP's source backport |
| 7.3 and older | End-of-life and not covered by the advisory. Upgrade |
| 8.6 (pre-release) | 8.6.0RC4 or later (not for production) |

### Limitations

This is a remote **version check**, not an exploit or a configuration audit:

- OS vendors such as Debian, Ubuntu and RHEL often backport fixes without changing the version string, so confirm with your vendor's advisory.
- Many servers hide `X-Powered-By`. A hidden version is not proof of safety, so run `php -v` on the server.
- Only the site's home page is checked.

## Privacy and safety

- One read-only request per check. Nothing is exploited. At most the first 256 KB of the home page is scanned in memory for PHP signs and then discarded.
- No domains, results or IP addresses are logged or stored. The only thing kept is an anonymous daily count per verdict (vulnerable, patched, can't tell, outside range, not checked).
- Page visits are measured with privacy-friendly analytics, which is anonymous and cookie-free, with no personal data and no consent banner needed.
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

Their source is in `demo-targets/` (`npm run deploy:demo`).

## Project structure

```
docs/                 Public website (GitHub Pages, no build step)
  js/php2shell.js     Version logic, shared by the website and the checker service
worker/               Checker service
  src/index.js        GET /check?target=<domain-or-url>
  src/guard.js        Input validation and network safeguards
  src/stats.js        Anonymous per-day verdict counters
demo-targets/         Static demo sites
scripts/stats.mjs     Prints usage counts (maintainers only)
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
- **Worker secret** `STATS_KEY` (`wrangler secret put STATS_KEY`): the access key for `npm run stats`.

## References

- Securin Vulnerability Database: [CVE-2026-109618](https://www.securin.io/vulnerability-database/cve/CVE-2026-109618), [CVE-2026-109619](https://www.securin.io/vulnerability-database/cve/CVE-2026-109619) ([browse the full database](https://www.securin.io/vulnerability-database/vulnerabilities?explore=all))
- [PHP.net release announcement](https://www.php.net/index.php#2026-10-21-5)
- [PHP security advisory GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP security advisory GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Wiz research: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
- [PHP supported versions](https://www.php.net/supported-versions.php) and [end-of-life branches](https://www.php.net/eol.php)

## Disclaimer

This tool is provided as-is for defensive purposes, and results are indicative only. Always verify on the affected system and follow your vendor's guidance.

---

<p align="center">© 2026 <a href="https://www.securin.io/">Securin Inc.</a> All rights reserved.</p>
