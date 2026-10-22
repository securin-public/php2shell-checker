// Signs that a site runs PHP, taken from the same single response (cookies, headers, first part of the HTML).
// Only the signal labels leave the Worker; the page itself is never stored or returned.
//
// The HTML is attacker-controlled, so every pattern is linear-time: no nested or adjacent unbounded
// quantifiers. Meta tags are pulled out with a bounded pattern and checked one by one.

const MAX_META_TAGS = 200;

function generators(html) {
  const out = [];
  for (const m of html.matchAll(/<meta\b[^>]{0,500}>/gi)) {
    if (out.length >= MAX_META_TAGS) break;
    const tag = m[0];
    if (/\bname\s{0,3}=\s{0,3}["']?generator\b/i.test(tag)) {
      out.push(/\bcontent\s{0,3}=\s{0,3}["']?([^"'>]{0,200})/i.exec(tag)?.[1] || "");
    }
  }
  return out;
}

// matchAll consumes each attribute value as it goes, so the scan is linear even for "href=href=href=...".
function hasPhpLink(html) {
  for (const m of html.matchAll(/(?:href|action|src)\s{0,5}=\s{0,5}["']?([^"'\s>]{0,200})/gi)) {
    const v = m[1];
    if (!/^https?:/i.test(v) && /\.php(?:[?#]|$)/i.test(v)) return true;
  }
  return false;
}

const RULES = [
  ["PHPSESSID session cookie", ({ cookies }) => cookies.some((c) => /^\s{0,5}PHPSESSID=/i.test(c))],
  ["Laravel session cookie", ({ cookies }) => cookies.some((c) => /^\s{0,5}laravel_session=/i.test(c))],
  ["WordPress (PHP application)", ({ html, gen }) => /\/wp-(?:content|includes)\//i.test(html) || gen.some((g) => /WordPress/i.test(g))],
  [
    "Drupal (PHP application)",
    ({ html, headers, gen }) =>
      /^Drupal/i.test(headers["x-generator"] || "") || gen.some((g) => /Drupal/i.test(g)) || html.includes("drupal-settings-json"),
  ],
  ["Joomla (PHP application)", ({ gen }) => gen.some((g) => /Joomla/i.test(g))],
  ["Statamic (PHP application)", ({ headers }) => /\bStatamic\b/i.test(headers["x-powered-by"] || "")],
  ["Craft CMS (PHP application)", ({ headers }) => /\bCraft CMS\b/i.test(headers["x-powered-by"] || "")],
  ["Magento (PHP application)", ({ html }) => html.includes("text/x-magento-init") || /Magento_[A-Z]\w{0,60}\//.test(html)],
  // Same-site links, forms or scripts pointing at .php files.
  ["Links to .php pages", ({ html }) => hasPhpLink(html)],
];

export function detectPhpSignals({ html = "", cookies = [], headers = {} }) {
  const ctx = { html, cookies, headers, gen: generators(html) };
  return RULES.filter(([, test]) => test(ctx)).map(([label]) => label);
}
