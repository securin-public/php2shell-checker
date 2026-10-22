import { test } from "node:test";
import assert from "node:assert/strict";
import { bucketFor, VERDICTS } from "../worker/src/buckets.js";
import { assess } from "../docs/js/php2shell.js";

test("assessment statuses map onto stats buckets", () => {
  assert.equal(bucketFor(assess("PHP/8.1.2").status), "vulnerable");
  assert.equal(bucketFor(assess("PHP/8.4.27").status), "patched");
  assert.equal(bucketFor(assess("PHP/7.3.33").status), "out-of-range");
  for (const h of [null, "ASP.NET", "PHP/6.0.8"]) assert.equal(bucketFor(assess(h).status), "unknown", String(h));
});

test("every bucket is a known verdict", () => {
  for (const s of ["vulnerable", "patched", "out-of-range", "no-header", "no-php-header", "unrecognised"]) {
    assert.ok(VERDICTS.includes(bucketFor(s)), s);
  }
});
