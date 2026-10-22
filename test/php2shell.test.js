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

test("EOL branches in the advisory ranges are vulnerable", () => {
  for (const v of ["5.4.0", "5.6.40", "7.0.0", "7.4.33", "8.0.30", "8.1.31"]) {
    assert.equal(status(`PHP/${v}`), "vulnerable", v);
  }
});

test("versions older than 5.4 are outside the advisory ranges", () => {
  assert.equal(status("PHP/5.3.29"), "out-of-range");
  assert.equal(status("PHP/5.0.0"), "out-of-range");
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

test("PHP token must lead the header value", () => {
  assert.equal(status("NotPHP/8.2.1"), "no-php-header");
});
