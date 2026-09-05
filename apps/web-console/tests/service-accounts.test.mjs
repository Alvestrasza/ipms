import assert from "node:assert/strict";
import test from "node:test";
import { serviceAccountDocument } from "../src/lib/service-account-types.ts";

test("creation sends only the fixed service-account contract and preserves password bytes", () => {
  assert.deepEqual(
    serviceAccountDocument(
      {
        name: " Host console ",
        username: " svc-console ",
        domain: " EXAMPLE ",
        password: "  fixture password  ",
      },
      false,
    ),
    {
      name: "Host console",
      kind: "hyperv_console",
      username: "svc-console",
      domain: "EXAMPLE",
      password: "  fixture password  ",
    },
  );
});

test("editing without a new password omits the field instead of sending a blank replacement", () => {
  const document = serviceAccountDocument(
    { name: "Console", username: "svc-console", domain: "", password: "" },
    true,
  );
  assert.equal(Object.hasOwn(document, "password"), false);
  assert.deepEqual(document, {
    name: "Console",
    username: "svc-console",
    domain: "",
  });
});

test("creation rejects empty credentials and bounds metadata without exposing secrets", () => {
  for (const changes of [
    { name: " " },
    { username: " " },
    { password: "" },
    { name: "x".repeat(129) },
    { password: "fixture-secret\0" },
  ]) {
    assert.throws(
      () =>
        serviceAccountDocument(
          {
            name: "Console",
            username: "svc-console",
            domain: "",
            password: "fixture-secret",
            ...changes,
          },
          false,
        ),
      /^Error: service_account_invalid$/,
    );
  }
});

test("name-only edits omit unchanged credential fields to avoid session interruption", () => {
  const original = { username: "svc-console", domain: "EXAMPLE" };
  assert.deepEqual(
    serviceAccountDocument(
      { name: "Renamed", ...original, password: "" },
      true,
      original,
    ),
    { name: "Renamed" },
  );
  assert.deepEqual(
    serviceAccountDocument(
      { name: "Renamed", username: "svc-new", domain: "", password: "" },
      true,
      original,
    ),
    { name: "Renamed", username: "svc-new", domain: "" },
  );
  assert.deepEqual(
    serviceAccountDocument(
      { name: "Renamed", ...original, password: "fixture-new" },
      true,
      original,
    ),
    { name: "Renamed", password: "fixture-new" },
  );
});
