import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";

// Exercise the actual pinned browser decoder, not a second implementation of
// its length-prefix semantics. No DOM, credentials or remote system is used.
function decoder() {
  const context = { window: {}, navigator: {} };
  runInNewContext(
    readFileSync(
      new URL("../public/vendor/guacamole/1.6.0/all.min.js", import.meta.url),
      "utf8",
    ),
    context,
  );
  const parser = new context.Guacamole.Parser();
  const seen = [];
  parser.oninstruction = (opcode, parameters) =>
    seen.push([opcode, Array.from(parameters)]);
  return { parser, seen };
}

test("a transport ping inserted inside a fragmented image corrupts the real decoder", () => {
  const { parser } = decoder();
  assert.throws(() => {
    parser.receive("4.blob,1.1,8.YW");
    parser.receive("0.,4.ping,1.1;");
    parser.receive("JjZA==;4.sync,1.1;");
  }, /terminator/);
});

test("keepalive replies between complete image instructions preserve the real decoder", () => {
  const { parser, seen } = decoder();
  parser.receive("0.,4.ping,1.1;");
  parser.receive("4.blob,1.1,8.YWJjZA==;4.sync,1.1;");
  parser.receive("0.,4.ping,1.2;");
  assert.deepEqual(seen, [
    ["", ["ping", "1"]],
    ["blob", ["1", "YWJjZA=="]],
    ["sync", ["1"]],
    ["", ["ping", "2"]],
  ]);
});
