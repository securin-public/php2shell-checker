import { test } from "node:test";
import assert from "node:assert/strict";
import { normaliseTarget, isBlockedIp, InputError } from "../worker/src/guard.js";

test("bare domains become https origins", () => {
  assert.equal(normaliseTarget("example.com").toString(), "https://example.com/");
  assert.equal(normaliseTarget(" https://Example.com/some/path?x=1 ").toString(), "https://example.com/");
  assert.equal(normaliseTarget("http://example.com:80").toString(), "http://example.com/");
});

test("rejects non-web schemes, odd ports and credentials", () => {
  for (const bad of ["ftp://example.com", "file:///etc/passwd", "https://example.com:8443", "https://u:p@example.com", ""]) {
    assert.throws(() => normaliseTarget(bad), InputError, bad);
  }
});

test("rejects internal names", () => {
  for (const bad of ["localhost", "intranet", "printer.local", "db.internal", "1.0.0.127.in-addr.arpa"]) {
    assert.throws(() => normaliseTarget(bad), InputError, bad);
  }
});

test("rejects private and reserved IP literals, including encoded forms", () => {
  for (const bad of [
    "127.0.0.1", "http://10.1.2.3", "192.168.1.1", "172.20.0.1", "169.254.169.254", "0.0.0.0",
    "2130706433", "0x7f.0.0.1", "[::1]", "[fd00::1]", "[::ffff:127.0.0.1]", "100.64.1.1",
  ]) {
    assert.throws(() => normaliseTarget(bad), InputError, bad);
  }
});

test("blocks IPv6 forms that can tunnel to private IPv4", () => {
  for (const ip of ["::a00:1", "::7f00:1", "2002:a00:1::1", "2001:0:4136:e378::1", "64:ff9b::a00:1", "100::1", "fe80::1"]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
  assert.throws(() => normaliseTarget("http://[::127.0.0.1]/"), InputError);
  assert.throws(() => normaliseTarget("http://[2002:7f00:1::]/"), InputError);
});

test("allows public IPs", () => {
  assert.equal(normaliseTarget("93.184.215.14").toString(), "https://93.184.215.14/");
  assert.equal(isBlockedIp("1.1.1.1"), false);
  assert.equal(isBlockedIp("2606:4700:4700::1111"), false);
});
