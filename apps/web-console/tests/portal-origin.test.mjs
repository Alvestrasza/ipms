import assert from "node:assert/strict";
import test from "node:test";
import { isTrustedPortalOrigin } from "../src/lib/portal-origin.ts";

test("portal writes accept only the exact explicitly configured canonical origin", () => {
  assert.equal(
    isTrustedPortalOrigin(
      "https://portal.example.invalid",
      "https://portal.example.invalid",
    ),
    true,
  );
  assert.equal(
    isTrustedPortalOrigin(
      "https://portal.example.invalid:8443",
      "https://portal.example.invalid:8443",
    ),
    true,
  );
  assert.equal(
    isTrustedPortalOrigin(
      "https://other.example.invalid",
      "https://portal.example.invalid",
    ),
    false,
  );
});

test("HTTP origins are limited to explicit loopback test endpoints", () => {
  for (const origin of [
    "http://127.0.0.1:3107",
    "http://localhost:3107",
    "http://[::1]:3107",
  ])
    assert.equal(isTrustedPortalOrigin(origin, origin), true);
  for (const origin of [
    "http://portal.example.invalid",
    "http://127.0.0.1.example.invalid",
    "ftp://localhost:3107",
  ])
    assert.equal(isTrustedPortalOrigin(origin, origin), false);
});

test("missing or noncanonical public origin configuration fails closed", () => {
  for (const configured of [
    undefined,
    "",
    "null",
    "https://portal.example.invalid/",
    "https://user:password@portal.example.invalid",
    "https://portal.example.invalid/path",
    "https://portal.example.invalid?query=1",
    "https://portal.example.invalid#fragment",
    " https://portal.example.invalid",
    "https://portal.example.invalid:443",
    "https://PORTAL.example.invalid",
  ]) {
    assert.equal(
      isTrustedPortalOrigin("https://portal.example.invalid", configured),
      false,
    );
    if (configured)
      assert.equal(isTrustedPortalOrigin(configured, configured), false);
  }
});

test("missing null malformed or multi-valued request origins are rejected", () => {
  for (const origin of [
    null,
    "",
    "null",
    "https://portal.example.invalid/",
    "https://portal.example.invalid https://other.example.invalid",
    "https://portal.example.invalid,https://other.example.invalid",
  ])
    assert.equal(
      isTrustedPortalOrigin(origin, "https://portal.example.invalid"),
      false,
    );
});
