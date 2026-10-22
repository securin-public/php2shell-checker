// Input normalisation and SSRF guards for the checker Worker.

const MAX_INPUT = 253 + 64;

export class InputError extends Error {}

// "example.com", "https://example.com/path" -> URL limited to http(s) on default ports.
export function normaliseTarget(raw) {
  const input = String(raw || "").trim();
  if (!input) throw new InputError("Enter a domain or URL.");
  if (input.length > MAX_INPUT) throw new InputError("That input is too long.");

  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`);
  } catch {
    throw new InputError("That doesn't look like a valid domain or URL.");
  }
  checkUrl(url);
  // Only the site root is requested, so keep just the origin.
  return new URL(`${url.protocol}//${url.host}/`);
}

export function checkUrl(url) {
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new InputError("Only http:// and https:// are supported.");
  }
  if (url.username || url.password) throw new InputError("URLs with credentials are not allowed.");
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new InputError("Only ports 80 and 443 are checked.");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isIpLiteral(host)) {
    if (isBlockedIp(host)) throw new InputError("Private, local and reserved addresses are not checked.");
    return;
  }
  if (!host.includes(".") || /(^|\.)(localhost|local|internal|intranet|lan|home|corp|arpa)$/.test(host)) {
    throw new InputError("Enter a public domain name.");
  }
}

export function isIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

function ipv4ToInt(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

const V4_BLOCKS = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([ip, bits]) => [ipv4ToInt(ip), bits]);

export function isBlockedIp(ip) {
  if (ip.includes(":")) {
    const v6 = ip.toLowerCase();
    const mapped = v6.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return isBlockedIp(mapped[1]);
    // Allow only global unicast 2000::/3. This rejects ::/8 (loopback, IPv4-compatible/mapped),
    // 64:ff9b::/96 NAT64, 100::/64, fc00::/7, fe80::/10 and ff00::/8 in one go.
    if (v6.startsWith("::")) return true;
    const [h1, h2] = v6.split(":").map((h) => parseInt(h || "0", 16));
    if (!(h1 >= 0x2000 && h1 <= 0x3fff)) return true;
    // 6to4 and Teredo embed an IPv4 address; documentation prefix is never routable.
    return h1 === 0x2002 || (h1 === 0x2001 && (h2 === 0 || h2 === 0xdb8));
  }
  const n = ipv4ToInt(ip);
  if (n === null) return true;
  return V4_BLOCKS.some(([base, bits]) => (n >>> (32 - bits)) === (base >>> (32 - bits)));
}
