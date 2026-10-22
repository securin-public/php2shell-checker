// Signs that a site runs PHP, taken from the same single response (cookies, headers, first part of the HTML).
// Only the signal labels leave the Worker; the page itself is never stored or returned.

const RULES = [
  ["PHPSESSID session cookie", ({ cookies }) => cookies.some((c) => /^\s*PHPSESSID=/i.test(c))],
  ["Laravel session cookie", ({ cookies }) => cookies.some((c) => /^\s*laravel_session=/i.test(c))],
  ["WordPress (PHP application)", ({ html }) => /\/wp-(?:content|includes)\/|<meta[^>]+generator[^>]+WordPress/i.test(html)],
  [
    "Drupal (PHP application)",
    ({ html, headers }) => /^Drupal/i.test(headers["x-generator"] || "") || /<meta[^>]+generator[^>]+Drupal|drupal-settings-json/i.test(html),
  ],
  ["Joomla (PHP application)", ({ html }) => /<meta[^>]+generator[^>]+Joomla/i.test(html)],
  ["Statamic (PHP application)", ({ headers }) => /\bStatamic\b/i.test(headers["x-powered-by"] || "")],
  ["Craft CMS (PHP application)", ({ headers }) => /\bCraft CMS\b/i.test(headers["x-powered-by"] || "")],
  ["Magento (PHP application)", ({ html }) => /text\/x-magento-init|Magento_[A-Z]\w+\//.test(html)],
  // Same-site links, forms or scripts pointing at .php files.
  ["Links to .php pages", ({ html }) => /(?:href|action|src)\s*=\s*["']?(?!https?:\/\/)[^"'\s>]*\.php(?:[?#"'\s>]|$)/i.test(html)],
];

export function detectPhpSignals({ html = "", cookies = [], headers = {} }) {
  return RULES.filter(([, test]) => test({ html, cookies, headers })).map(([label]) => label);
}
