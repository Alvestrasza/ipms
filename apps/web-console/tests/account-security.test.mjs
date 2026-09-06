import assert from "node:assert/strict";
import test from "node:test";
import { identityActionDocument } from "../src/lib/account-security.ts";

test("rename sends the requested username and actor password without credential normalization", () => {
  assert.deepEqual(
    identityActionDocument("rename", {
      username: " renamed-user ",
      current_password: " current secret ",
    }),
    {
      username: "renamed-user",
      current_password: " current secret ",
    },
  );
});
test("password change sends only the fixed API document, never its confirmation", () => {
  assert.deepEqual(
    identityActionDocument("password", {
      current_password: "current",
      new_password: " new secret 123 ",
      confirm_password: " new secret 123 ",
      username: "ignored",
    }),
    {
      current_password: "current",
      new_password: " new secret 123 ",
    },
  );
});
test("password mismatch is rejected before submitting a request", () => {
  assert.throws(
    () =>
      identityActionDocument("password", {
        current_password: "current",
        new_password: "new secret 123",
        confirm_password: "different 123",
      }),
    /password_mismatch/,
  );
});
test("credential document bounds reject missing, oversized and null-bearing fields", () => {
  for (const current_password of ["", "x".repeat(1025), "secret\0value"]) {
    assert.throws(
      () =>
        identityActionDocument("rename", {
          username: "valid",
          current_password,
        }),
      /invalid_request/,
    );
  }
  for (const username of [" ", "x".repeat(151), "user\0name"]) {
    assert.throws(
      () =>
        identityActionDocument("rename", {
          username,
          current_password: "current",
        }),
      /invalid_request/,
    );
  }
  for (const new_password of ["short", "x".repeat(1025), "null\0secret123"]) {
    assert.throws(
      () =>
        identityActionDocument("password", {
          current_password: "current",
          new_password,
          confirm_password: new_password,
        }),
      /invalid_request/,
    );
  }
});
