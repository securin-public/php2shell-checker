// PHP2Shell (CVE-2026-109618 / CVE-2026-109619) version logic.
// Affected ranges follow the PHP security advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp.
// Shared by the browser page and the Cloudflare Worker, so keep it dependency-free.

export const CVES = ["CVE-2026-109618", "CVE-2026-109619"];

// First fixed release per supported branch.
export const FIXED = { "8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12" };

// [from inclusive, to exclusive].
const AFFECTED_RANGES = [
  ["5.4.0", "5.7.0"],
  ["7.0.0", "7.5.0"],
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

/**
 * @returns {{status: "vulnerable"|"patched"|"out-of-range"|"unrecognised"|"no-php-header"|"no-header",
 *            version?: {base: string, full: string}, branch?: string, fixedIn?: string|null,
 *            prerelease?: boolean, distroBuild?: boolean}}
 */
export function assess(xPoweredBy) {
  if (!xPoweredBy) return { status: "no-header" };
  const version = extractPhpVersion(xPoweredBy);
  if (!version) return { status: "no-php-header" };

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

  let status;
  if (!isRealBranch(base)) status = "unrecognised";
  else if (inRange || prereleaseOfFix) status = "vulnerable";
  else if (compareVersions(base, "5.4.0") < 0) status = "out-of-range";
  else status = "patched";

  return { status, version, branch, fixedIn, prerelease, distroBuild };
}
