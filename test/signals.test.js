import { test } from "node:test";
import assert from "node:assert/strict";
import { detectPhpSignals } from "../worker/src/signals.js";

const sig = (html, cookies = [], headers = {}) => detectPhpSignals({ html, cookies, headers });

test("session cookies", () => {
  assert.ok(sig("", ["PHPSESSID=abc; path=/"]).includes("PHPSESSID session cookie"));
  assert.ok(sig("", ["laravel_session=xyz; HttpOnly"]).includes("Laravel session cookie"));
});

test("CMS and framework markers", () => {
  assert.ok(sig('<link href="/wp-content/themes/x/style.css">').includes("WordPress (PHP application)"));
  assert.ok(sig('<meta name="generator" content="Drupal 10 (https://www.drupal.org)">').includes("Drupal (PHP application)"));
  assert.ok(sig('<meta name="generator" content="Joomla! - Open Source Content Management">').includes("Joomla (PHP application)"));
  assert.ok(sig('<script type="text/x-magento-init">{}</script>').includes("Magento (PHP application)"));
  assert.ok(sig("", [], { "x-generator": "Drupal 10" }).includes("Drupal (PHP application)"));
});

test(".php links in the page", () => {
  assert.ok(sig('<a href="/index.php?id=1">x</a>').includes("Links to .php pages"));
  assert.ok(sig('<form action="login.php" method="post">').includes("Links to .php pages"));
  assert.deepEqual(sig('<a href="https://other.example/docs/php-guide">PHP guide</a> php.net'), []);
});

test("no signals on a plain page", () => {
  assert.deepEqual(sig("<html><body><h1>Hello</h1><script src=/app.js></script></body></html>", ["session=1"]), []);
});

test("each signal is reported once, in a stable order", () => {
  const s = sig('<a href="a.php"></a><a href="b.php"></a><link href="/wp-includes/x.css">', ["PHPSESSID=1"]);
  assert.deepEqual(s, ["PHPSESSID session cookie", "WordPress (PHP application)", "Links to .php pages"]);
});

test("PHP-only products named in X-Powered-By", () => {
  assert.ok(sig("", [], { "x-powered-by": "Statamic" }).includes("Statamic (PHP application)"));
  assert.ok(sig("", [], { "x-powered-by": "Craft CMS" }).includes("Craft CMS (PHP application)"));
  assert.deepEqual(sig("", [], { "x-powered-by": "Express" }), []);
});

test("crafted pages can't make detection slow (ReDoS)", () => {
  const N = 256 * 1024;
  const attacks = {
    "repeated href=": "href=".repeat(N / 5),
    "unclosed meta generator": "<meta " + "generator ".repeat(N / 10),
    "long path, no .php": 'href="' + "a".repeat(N),
    "many wp- fragments": "/wp-".repeat(N / 4),
  };
  for (const [name, html] of Object.entries(attacks)) {
    const t0 = performance.now();
    detectPhpSignals({ html });
    const ms = performance.now() - t0;
    assert.ok(ms < 50, `${name}: ${ms.toFixed(1)} ms`);
  }
});
