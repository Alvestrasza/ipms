import assert from "node:assert/strict";
import test from "node:test";
import { ConsoleInputQueue } from "../src/lib/console-input-queue.ts";

const move = (x) => ({ type: "mouse_move", payload: { x, y: 20 } });
const button = (is_down) => ({
  type: "mouse_button",
  payload: { button: 1, is_down },
});

function manualScheduler() {
  let now = 0;
  const timers = new Set();
  return {
    schedule(callback, delay) {
      const timer = { callback, due: now + delay };
      timers.add(timer);
      return () => timers.delete(timer);
    },
    advance(milliseconds) {
      now += milliseconds;
      for (const timer of [...timers]) {
        if (timer.due <= now) {
          timers.delete(timer);
          timer.callback();
        }
      }
    },
    get pending() {
      return timers.size;
    },
  };
}

for (const event of [
  button(true),
  button(false),
  { type: "key", payload: { key_code: 65, is_down: true } },
  { type: "key", payload: { key_code: 65, is_down: false } },
  { type: "mouse_wheel", payload: { delta: -120 } },
  { type: "secure_attention", payload: {} },
]) {
  test(`delivers discrete ${event.type} ${JSON.stringify(event.payload)} without a debounce timer`, async () => {
    const clock = manualScheduler();
    const batches = [];
    const queue = new ConsoleInputQueue(
      async (events) => batches.push(events),
      () => assert.fail("delivery failed"),
      clock.schedule,
    );
    queue.push(event);
    assert.deepEqual(batches, [[event]]);
    assert.equal(clock.pending, 0);
    await queue.flush();
    queue.dispose();
  });
}

test("coalesces pure mouse motion for eight milliseconds without extending the deadline", async () => {
  const clock = manualScheduler();
  const batches = [];
  const queue = new ConsoleInputQueue(
    async (events) => batches.push(events),
    () => assert.fail("delivery failed"),
    clock.schedule,
  );
  queue.push(move(1));
  clock.advance(7);
  for (let x = 2; x <= 200; x++) queue.push(move(x));
  assert.deepEqual(batches, []);
  assert.equal(clock.pending, 1);
  clock.advance(1);
  assert.deepEqual(batches, [[move(200)]]);
  assert.equal(clock.pending, 0);
  await queue.flush();
  queue.dispose();
});

test("a click immediately flushes its latest pointer position and cancels the motion timer", async () => {
  const clock = manualScheduler();
  const batches = [];
  const queue = new ConsoleInputQueue(
    async (events) => batches.push(events),
    () => assert.fail("delivery failed"),
    clock.schedule,
  );
  queue.push(move(1));
  queue.push(move(2));
  queue.push(button(true));
  assert.deepEqual(batches, [[move(2), button(true)]]);
  assert.equal(clock.pending, 0);
  queue.push(move(3));
  queue.push(button(false));
  await queue.flush();
  assert.deepEqual(batches, [
    [move(2), button(true)],
    [move(3), button(false)],
  ]);
  clock.advance(100);
  assert.equal(batches.length, 2);
  queue.dispose();
});

test("disposing cancels a scheduled mouse update", async () => {
  const clock = manualScheduler();
  const batches = [];
  const queue = new ConsoleInputQueue(
    async (events) => batches.push(events),
    () => assert.fail("delivery failed"),
    clock.schedule,
  );
  queue.push(move(1));
  queue.dispose();
  clock.advance(100);
  await queue.flush();
  assert.deepEqual(batches, []);
  assert.equal(clock.pending, 0);
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

test("an uncertain in-flight acknowledgement discards later queued input without retry", async () => {
  const clock = manualScheduler();
  let reject;
  const acknowledgement = new Promise((_resolve, fail) => {
    reject = fail;
  });
  const batches = [];
  let failures = 0;
  const queue = new ConsoleInputQueue(
    async (events) => {
      batches.push(events);
      await acknowledgement;
    },
    () => failures++,
    clock.schedule,
  );
  queue.push(button(true));
  queue.push(move(30));
  queue.push(button(false));
  queue.push({ type: "secure_attention", payload: {} });
  assert.deepEqual(batches, [[button(true)]]);
  reject(new Error("acknowledgement lost"));
  await queue.flush();
  clock.advance(1000);
  queue.push(button(true));
  await queue.flush();
  assert.deepEqual(batches, [[button(true)]]);
  assert.equal(failures, 1);
  assert.equal(clock.pending, 0);
});

test("drains ordered input in batches of at most 32 with only one request in flight", async () => {
  let release;
  const acknowledgement = new Promise((resolve) => {
    release = resolve;
  });
  const batches = [];
  let inFlight = 0;
  let maximumInFlight = 0;
  const queue = new ConsoleInputQueue(
    async (events) => {
      inFlight++;
      maximumInFlight = Math.max(maximumInFlight, inFlight);
      batches.push(events);
      if (batches.length === 1) await acknowledgement;
      inFlight--;
    },
    () => assert.fail("delivery failed"),
  );
  const events = Array.from({ length: 81 }, (_, index) => ({
    type: "key",
    payload: { key_code: 65 + (index % 26), is_down: index % 2 === 0 },
  }));
  for (const event of events) queue.push(event);
  assert.equal(batches.length, 1);
  release();
  await queue.flush();
  assert.deepEqual(
    batches.map((batch) => batch.length),
    [1, 32, 32, 16],
  );
  assert.deepEqual(batches.flat(), events);
  assert.equal(maximumInFlight, 1);
  queue.dispose();
});

test("accepts at most 128 pending events and fails closed on overflow", async () => {
  let release;
  const acknowledgement = new Promise((resolve) => {
    release = resolve;
  });
  const batches = [];
  let failures = 0;
  const queue = new ConsoleInputQueue(
    async (events) => {
      batches.push(events);
      await acknowledgement;
    },
    () => failures++,
  );
  queue.push(button(true));
  for (let index = 0; index < 128; index++) queue.push(button(false));
  assert.equal(failures, 0);
  queue.push(button(false));
  assert.equal(failures, 1);
  release();
  await queue.flush();
  queue.push(button(true));
  await queue.flush();
  assert.deepEqual(batches, [[button(true)]]);
  assert.equal(failures, 1);
});
