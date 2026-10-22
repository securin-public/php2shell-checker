// PHP2Shell (CVE-2026-109618 / CVE-2026-109619) version logic.
// Sources: PHP advisories GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp (fixed releases) and the
// php.net announcement of 2026-10-21 (source backports for 7.4/8.0/8.1; 8.6.0 fixed from RC4).
// Shared by the browser page and the Cloudflare Worker, so keep it dependency-free.

export const CVES = ["CVE-2026-109618", "CVE-2026-109619"];

// First fixed release per supported branch.
export const FIXED = { "8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12" };

// End-of-life branches for which the PHP security team published source-only backports.
export const SOURCE_BACKPORT_BRANCHES = ["7.4", "8.0", "8.1"];

// [from inclusive, to exclusive].
const AFFECTED_RANGES = [
  ["7.4.0", "7.5.0"],
  ["8.0.0", "8.2.0"],
  ["8.2.0", "8.2.35"],
  ["8.3.0", "8.3.36"],
  ["8.4.0", "8.4.27"],
  ["8.5.0", "8.5.12"],
];

// Matches a leading "PHP/x.y.z" token, with an optional vendor/pre-release suffix.
const PHP_TOKEN =
  /^PHP\/([0-9]+\.[0-9]+\.[0-9]+)((?:[-+~_A-Za-z]|\.[A-Za-z])[0-9A-Za-z._+~-]*)?(?:[ \t;,)\r]|$)/i;

const PRERELEASE =
  /^[0-9]+\.[0-9]+\.[0-9]+[-+_~.]?(?:dev|alpha[0-9]*|a[0-9]+|beta[0-9]*|b[0-9]+|rc[0-9]+)(?:[-+_~.][0-9A-Za-z._+~-]*)?$/i;

// "PHP/x.y.z" anywhere in a Server header, e.g. "Apache/2.4.41 (Ubuntu) PHP/7.4.3 OpenSSL/1.1.1f".
const SERVER_PHP_TOKEN =
  /(?:^|[\s(])PHP\/([0-9]+\.[0-9]+\.[0-9]+)((?:[-+~_A-Za-z]|\.[A-Za-z])[0-9A-Za-z._+~-]*)?(?=[\s;,)]|$)/i;

// Suffixes that usually mean an OS/LTS vendor build which may carry backported fixes.
const DISTRO_HINT = /(ubuntu|deb|el[0-9]|\.el|amzn|suse|sury|alpine|centos|rhel|fc[0-9])/i;

export function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

// Sites sometimes advertise fake versions (e.g. "PHP/6.0.8"); PHP 6 and 7.5+ were never released.
// Branches newer than 8.x are assumed to postdate the fix.
function isRealBranch(base) {
  const [major, minor] = base.split(".").map(Number);
  if (major === 5) return minor <= 6;
  if (major === 7) return minor <= 4;
  return major === 8 || major >= 9;
}

// Accepts a raw header value. Multiple headers arrive comma-joined, e.g. "PHP/8.3.1, ASP.NET".
export function extractPhpVersion(xPoweredBy) {
  if (!xPoweredBy) return null;
  for (const part of String(xPoweredBy).split(",")) {
    const m = part.trim().match(PHP_TOKEN);
    if (m) return { base: m[1], full: m[1] + (m[2] || "") };
  }
  return null;
}

export function extractPhpFromServer(server) {
  const m = server ? String(server).match(SERVER_PHP_TOKEN) : null;
  return m ? { base: m[1], full: m[1] + (m[2] || "") } : null;
}

/**
 * "php-hidden" means the response shows PHP is in use (cookies, CMS markers, .php links) but no version.
 * "out-of-range" means end-of-life (7.3 and older): not covered by the advisory, upgrade anyway.
 * @returns {{status: "vulnerable"|"patched"|"out-of-range"|"unrecognised"|"php-hidden"|"no-php-header"|"no-header",
 *            version?: {base: string, full: string}, branch?: string, fixedIn?: string|null,
 *            prerelease?: boolean, distroBuild?: boolean, eol?: boolean, sourceBackport?: boolean,
 *            source?: "x-powered-by"|"server", phpSignals?: string[]}}
 */
export function assess(xPoweredBy, { server = null, phpSignals = [] } = {}) {
  let version = extractPhpVersion(xPoweredBy);
  let source = "x-powered-by";
  if (!version) {
    version = extractPhpFromServer(server);
    source = "server";
  }
  if (!version) {
    if (phpSignals.length) return { status: "php-hidden", phpSignals };
    return { status: xPoweredBy ? "no-php-header" : "no-header" };
  }

  const { base, full } = version;
  const branch = base.split(".").slice(0, 2).join(".");
  const fixedIn = FIXED[branch] || null;
  const prerelease = PRERELEASE.test(full);
  const distroBuild = DISTRO_HINT.test(full.slice(base.length));

  const inRange = AFFECTED_RANGES.some(
    ([lo, hi]) => compareVersions(base, lo) >= 0 && compareVersions(base, hi) < 0
  );
  // A dev/alpha/beta/RC build of the exact fixed version predates the fix.
  const prereleaseOfFix = prerelease && fixedIn !== null && compareVersions(base, fixedIn) === 0;
  // php.net: "earlier builds of PHP 8.6.0" are affected; RC4 is the first 8.6 build with the fixes.
  const early86 = base === "8.6.0" && prerelease && !/rc(?:[4-9]|[1-9][0-9])/i.test(full);

  const eol = compareVersions(base, "8.2.0") < 0;
  const sourceBackport = SOURCE_BACKPORT_BRANCHES.includes(branch);

  let status;
  if (!isRealBranch(base)) status = "unrecognised";
  else if (inRange || prereleaseOfFix || early86) status = "vulnerable";
  else if (compareVersions(base, "7.4.0") < 0) status = "out-of-range";
  else status = "patched";

  return { status, version, branch, fixedIn, prerelease, distroBuild, eol, sourceBackport, source, phpSignals };
}
