import assert from "node:assert/strict";
import test from "node:test";
import { NativeConsoleMetrics } from "../src/lib/native-console-metrics.ts";

test("FPS counts completed drawing batches, not receipt, pings, cursor or idle sync", () => {
  let now = 0;
  const metrics = new NativeConsoleMetrics(() => now);
  metrics.instruction("img", ["0", "14", "0"]);
  metrics.instruction("sync", ["1"]);
  now = 1000;
  assert.equal(metrics.sample().fps, 0); // Asynchronous image still loading.
  metrics.sent(["sync", 1]);
  metrics.sent(["sync", 1]); // Duplicate acknowledgment is not another frame.
  metrics.instruction("cursor", []);
  metrics.instruction("sync", ["2"]);
  metrics.sent(["sync", 2]);
  metrics.sent(["", "ping", 1]);
  metrics.instruction("", ["ping", "1"]);
  now = 2000;
  assert.equal(metrics.sample().fps, 1);
  now = 3000;
  assert.equal(metrics.sample().fps, 0);
});

test("RTT uses a matched monotonic heartbeat, rejects duplicates and expires", () => {
  let now = 100;
  const metrics = new NativeConsoleMetrics(() => now);
  metrics.sent(["", "ping", 7]);
  now = 125;
  metrics.instruction("", ["ping", "8"]);
  assert.equal(metrics.sample().rtt, null);
  metrics.instruction("", ["ping", "7"]);
  assert.equal(metrics.sample().rtt, 25);
  now = 200;
  metrics.instruction("", ["ping", "7"]);
  assert.equal(metrics.sample().rtt, 25);
  now = 4000;
  assert.equal(metrics.sample().rtt, null);
});

test("measurement metadata remains bounded under missing acknowledgments", () => {
  let now = 0;
  const metrics = new NativeConsoleMetrics(() => now);
  for (let i = 0; i < 2000; i++) {
    metrics.instruction("img", ["0", "14", "0"]);
    metrics.instruction("sync", [String(i)]);
    metrics.sent(["", "ping", i]);
  }
  now = 1000;
  assert.equal(metrics.sample().fps, null); // Do not claim a rate after overflow.
  metrics.instruction("", ["ping", "0"]);
  assert.equal(metrics.sample().rtt, null);
  metrics.instruction("", ["ping", "1999"]);
  assert.equal(metrics.sample().rtt, 1000);
});

test("hidden-window intervals and reconnects do not reuse stale measurements", () => {
  let now = 0;
  const metrics = new NativeConsoleMetrics(() => now);
  metrics.instruction("copy", ["-1", "0", "0", "10", "10", "14", "0"]);
  metrics.instruction("sync", ["1"]);
  metrics.sent(["sync", 1]);
  now = 10_000;
  assert.equal(metrics.sample().fps, null);
  metrics.reset();
  metrics.sent(["sync", 1]);
  now += 1000;
  assert.deepEqual(metrics.sample(), { fps: 0, rtt: null });
});

test("offscreen image cache and cursor shape changes do not inflate display FPS", () => {
  let now = 0;
  const metrics = new NativeConsoleMetrics(() => now);
  metrics.instruction("img", ["0", "14", "-1"]);
  metrics.instruction("size", ["-1", "32", "32"]);
  metrics.instruction("cursor", ["0", "0", "-1", "0", "0", "32", "32"]);
  metrics.instruction("sync", ["1"]);
  metrics.sent(["sync", 1]);
  now = 1000;
  assert.equal(metrics.sample().fps, 0);
  metrics.instruction("copy", ["-1", "0", "0", "10", "10", "14", "0"]);
  metrics.instruction("sync", ["2"]);
  metrics.sent(["sync", 2]);
  now = 2000;
  assert.equal(metrics.sample().fps, 1);
});
