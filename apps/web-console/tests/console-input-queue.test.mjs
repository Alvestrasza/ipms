import assert from "node:assert/strict";
import test from "node:test";
import { ConsoleInputQueue } from "../src/lib/console-input-queue.ts";

const move = (x) => ({ type: "mouse_move", payload: { x, y: 20 } });
const button = (is_down) => ({
  type: "mouse_button",
  payload: { button: 1, is_down },
});

test("coalesces a mouse flood but preserves click positions and key order", async () => {
  const delivered = [];
  const queue = new ConsoleInputQueue(
    async (events) => {
      delivered.push(...events);
    },
    () => assert.fail("delivery failed"),
  );
  for (let x = 0; x <= 100; x++) queue.push(move(x));
  queue.push(button(true));
  queue.push(move(200));
  queue.push(button(false));
  queue.push({ type: "key", payload: { key_code: 16, is_down: true } });
  queue.push({ type: "key", payload: { key_code: 16, is_down: false } });
  await queue.flush();
  assert.deepEqual(delivered.slice(0, 4), [
    move(100),
    button(true),
    move(200),
    button(false),
  ]);
  assert.deepEqual(
    delivered.slice(4).map((event) => event.payload.is_down),
    [true, false],
  );
  queue.dispose();
});

test("waits for acknowledgement before submitting the next ordered batch", async () => {
  const batches = [];
  let release;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  const queue = new ConsoleInputQueue(
    async (events) => {
      batches.push(events);
      if (batches.length === 1) await pending;
    },
    () => assert.fail("delivery failed"),
  );
  queue.push(button(true));
  const flushed = queue.flush();
  queue.push(button(false));
  const secondFlush = queue.flush();
  assert.equal(batches.length, 1);
  release();
  await Promise.all([flushed, secondFlush]);
  assert.deepEqual(batches, [[button(true)], [button(false)]]);
  queue.dispose();
});

test("does not replay input after an uncertain network failure", async () => {
  let attempts = 0;
  let failures = 0;
  const queue = new ConsoleInputQueue(
    async () => {
      attempts++;
      throw new Error("network lost");
    },
    () => {
      failures++;
    },
  );
  queue.push(button(true));
  await queue.flush();
  queue.push(button(false));
  await queue.flush();
  assert.equal(attempts, 1);
  assert.equal(failures, 1);
});
