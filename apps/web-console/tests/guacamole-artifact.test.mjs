import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

test("the official browser artifact and its SRI remain pinned", () => {
  const artifact = readFileSync(
    new URL("../public/vendor/guacamole/1.6.0/all.min.js", import.meta.url),
  );
  const integrity = `sha384-${createHash("sha384").update(artifact).digest("base64")}`;
  assert.equal(artifact.length, 78778);
  assert.equal(
    integrity,
    "sha384-KdJzE+xcyZMbc+g6Xf5GiFtoHW/nBPBbLMaiA/zm5jc5aMbvUf2aorH84gHjlfCV",
  );
  const component = readFileSync(
    new URL("../src/components/hyperv-native-console.tsx", import.meta.url),
    "utf8",
  );
  assert.ok(component.includes(`integrity="${integrity}"`));
  assert.ok(component.includes("/vendor/guacamole/1.6.0/all.min.js"));
});

test("upstream LICENSE and NOTICE are retained without modification", () => {
  const digests = {
    LICENSE:
      "e7b34e86f00df8bd4f4285b383c969b5d381ea8e3d2381919af9a4095c0c3984087ba833ffd343b29fb65ba6d3b55938d4b078aa8da444e062afec5fa2777144",
    NOTICE:
      "63f48417c420477a2b86c1b3a8657a9eb028b708e3ae2f128096bb0c900e830182dbc551c816517c039bb236c7487e9a38e15cdc7f2f17f8dad95e74473ad383",
  };
  for (const [name, digest] of Object.entries(digests)) {
    const artifact = readFileSync(
      new URL(`../public/vendor/guacamole/1.6.0/${name}`, import.meta.url),
    );
    assert.equal(createHash("sha512").update(artifact).digest("hex"), digest);
  }
});
