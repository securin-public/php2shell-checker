import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, extractPhpVersion, compareVersions } from "../docs/js/php2shell.js";

const status = (h) => assess(h).status;

test("compareVersions orders numerically, not lexically", () => {
  assert.equal(compareVersions("8.2.9", "8.2.35"), -1);
  assert.equal(compareVersions("8.10.0", "8.9.9"), 1);
  assert.equal(compareVersions("8.3.36", "8.3.36"), 0);
});

test("versions just below each fix are vulnerable", () => {
  for (const v of ["8.2.34", "8.3.35", "8.4.26", "8.5.11"]) assert.equal(status(`PHP/${v}`), "vulnerable", v);
});

test("fixed releases and later are patched", () => {
  for (const v of ["8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.20", "8.6.0"]) {
    assert.equal(status(`PHP/${v}`), "patched", v);
  }
});

test("EOL branches with PHP source backports (7.4, 8.0, 8.1) are vulnerable", () => {
  for (const v of ["7.4.0", "7.4.33", "8.0.30", "8.1.31"]) {
    const r = assess(`PHP/${v}`);
    assert.equal(r.status, "vulnerable", v);
    assert.equal(r.eol, true, v);
    assert.equal(r.sourceBackport, true, v);
  }
});

test("7.3 and older are end-of-life and not covered by the advisory", () => {
  for (const v of ["7.3.33", "7.0.0", "5.6.40", "5.4.0", "5.3.29", "5.0.0"]) {
    assert.equal(status(`PHP/${v}`), "out-of-range", v);
  }
});

test("PHP 8.6.0 builds before RC4 are vulnerable; RC4 and later are fixed", () => {
  for (const v of ["8.6.0-dev", "8.6.0alpha1", "8.6.0beta3", "8.6.0RC1", "8.6.0RC3"]) {
    assert.equal(status(`PHP/${v}`), "vulnerable", v);
  }
  for (const v of ["8.6.0RC4", "8.6.0RC5", "8.6.0", "8.6.1"]) assert.equal(status(`PHP/${v}`), "patched", v);
});

test("supported branches are not flagged end-of-life", () => {
  assert.equal(assess("PHP/8.2.10").eol, false);
  assert.equal(assess("PHP/8.2.10").sourceBackport, false);
});

test("pre-release builds of a fixed version are vulnerable", () => {
  for (const v of ["8.3.36-dev", "8.4.27RC1", "8.5.12beta2", "8.2.35alpha1"]) {
    assert.equal(status(`PHP/${v}`), "vulnerable", v);
  }
  assert.equal(status("PHP/8.3.37-dev"), "patched");
});

test("distro suffixes are kept and flagged", () => {
  const r = assess("PHP/8.1.2-1ubuntu2.20");
  assert.equal(r.status, "vulnerable");
  assert.equal(r.version.full, "8.1.2-1ubuntu2.20");
  assert.equal(r.distroBuild, true);
  assert.equal(assess("PHP/8.3.36").distroBuild, false);
  assert.equal(r.distroFrom, "version");
});

test("an OS vendor named in the Server header flags a distro build", () => {
  const r = assess("PHP/8.3.6", { server: "Apache/2.4.58 (Ubuntu)" });
  assert.equal(r.status, "vulnerable");
  assert.equal(r.distroBuild, true);
  assert.equal(r.distroFrom, "server");
  assert.equal(r.distroVendor, "Ubuntu");
  for (const s of ["Apache/2.4.57 (Debian)", "Apache/2.4.37 (Red Hat Enterprise Linux)", "Apache/2.4.62 (AlmaLinux)", "Apache/2.4.58 (Amazon)"]) {
    assert.equal(assess("PHP/8.2.20", { server: s }).distroBuild, true, s);
  }
  for (const s of ["Apache/2.4.62 (Unix)", "nginx/1.24.0", "Apache/2.4.62 (Win64)"]) {
    assert.equal(assess("PHP/8.2.20", { server: s }).distroBuild, false, s);
  }
});

test("version strings from branches that were never released are unrecognised", () => {
  for (const v of ["6.0.8", "5.7.1", "7.5.0", "4.4.9"]) assert.equal(status(`PHP/${v}`), "unrecognised", v);
  assert.equal(status("PHP/9.0.0"), "patched");
});

test("missing or non-PHP headers", () => {
  assert.equal(status(null), "no-header");
  assert.equal(status(""), "no-header");
  assert.equal(status("ASP.NET"), "no-php-header");
  assert.equal(status("Express"), "no-php-header");
  assert.equal(status("PHP/8"), "no-php-header");
});

test("comma-joined multiple X-Powered-By headers", () => {
  assert.equal(extractPhpVersion("PleskLin, PHP/8.2.10").base, "8.2.10");
  assert.equal(status("PHP/8.4.27, PleskLin"), "patched");
});

test("PHP token must lead the header value or follow a space", () => {
  assert.equal(status("NotPHP/8.2.1"), "no-php-header");
  assert.equal(extractPhpVersion("PleskLin PHP/8.2.10").base, "8.2.10");
  assert.equal(status("PleskLin PHP/8.2.10"), "vulnerable");
});

test("PHP version is read from the Server header when X-Powered-By lacks it", () => {
  const r = assess(null, { server: "Apache/2.4.41 (Ubuntu) PHP/7.4.3 OpenSSL/1.1.1f" });
  assert.equal(r.status, "vulnerable");
  assert.equal(r.version.full, "7.4.3");
  assert.equal(r.source, "server");
  assert.equal(assess(null, { server: "Apache/2.4.62 (Unix) PHP/8.4.27" }).status, "patched");
  assert.equal(assess(null, { server: "Apache/2.4.62 (Unix) mod_fcgid/2.3.9 PHP/8.2.10-2ubuntu1" }).version.full, "8.2.10-2ubuntu1");
});

test("X-Powered-By wins over Server, and records its source", () => {
  const r = assess("PHP/8.4.27", { server: "Apache PHP/7.4.3" });
  assert.equal(r.status, "patched");
  assert.equal(r.source, "x-powered-by");
});

test("Server header without a PHP token gives no version", () => {
  for (const s of ["nginx/1.24.0", "Apache/2.4.62 (Unix)", "cloudflare", "NotPHP/8.1.0"]) {
    assert.equal(assess(null, { server: s }).status, "no-header", s);
  }
});

test("PHP signals without a version give php-hidden", () => {
  const r = assess(null, { server: "nginx", phpSignals: ["WordPress (PHP application)"] });
  assert.equal(r.status, "php-hidden");
  assert.deepEqual(r.phpSignals, ["WordPress (PHP application)"]);
  assert.equal(assess("ASP.NET", { phpSignals: ["PHPSESSID session cookie"] }).status, "php-hidden");
  assert.equal(assess("PHP/8.4.27", { phpSignals: ["PHPSESSID session cookie"] }).status, "patched");
});
