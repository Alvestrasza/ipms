import assert from "node:assert/strict";
import test from "node:test";
import { NativeConsoleChannel } from "../src/lib/native-console-channel.ts";

const fingerprint = "a".repeat(64);
function setup(viewport = { width: 900, height: 600 }) {
  const sent = [];
  const events = [];
  const timers = new Set();
  const socket = {
    readyState: 0,
    bufferedAmount: 0,
    send: (value) => sent.push(value),
    close() {
      this.readyState = 3;
      this.onclose?.({});
    },
    onopen: null,
    onmessage: null,
    onerror: null,
    onclose: null,
  };
  const channel = new NativeConsoleChannel({
    url: "wss://portal.example/api/v1/hyper-v/console-sessions/test/native-stream/",
    width: viewport.width,
    height: viewport.height,
    socketFactory: (url, protocol) => {
      assert.equal(new URL(url).search, "");
      assert.equal(protocol, "guacamole");
      return socket;
    },
    schedule: (callback) => {
      timers.add(callback);
      return () => timers.delete(callback);
    },
    onCertificate: (value) => events.push(["certificate", value]),
    onReady: () => events.push(["ready"]),
    onProtocol: (value) => events.push(["protocol", value]),
    onFailure: (code) => events.push(["failure", code]),
  });
  channel.connect();
  socket.readyState = 1;
  socket.onopen();
  const receive = (value) =>
    socket.onmessage?.({
      data: typeof value === "string" ? value : JSON.stringify(value),
    });
  const certificate = () =>
    receive({
      type: "certificate",
      sha256: fingerprint,
      subject: "CN=Host",
      issuer: "CN=Host",
      not_before: "2026-01-01T00:00:00Z",
      not_after: "2027-01-01T00:00:00Z",
    });
  return { channel, socket, sent, events, timers, receive, certificate };
}

test("small or collapsed windows respect the broker's 200-pixel viewport minimum", () => {
  for (const [width, height] of [
    [0, 0],
    [160, 120],
    [199, 199],
    [200, 200],
  ]) {
    const h = setup({ width, height });
    assert.deepEqual(JSON.parse(h.sent[0]), {
      type: "connect",
      width: 200,
      height: 200,
    });
    h.channel.dispose();
    assert.equal(h.timers.size, 0);
  }
});

test("sends only viewport setup and waits for explicit exact certificate approval", () => {
  const h = setup();
  assert.deepEqual(JSON.parse(h.sent[0]), {
    type: "connect",
    width: 900,
    height: 600,
  });
  h.certificate();
  assert.equal(h.sent.length, 1);
  h.channel.trust("b".repeat(64));
  assert.equal(h.sent.length, 1);
  h.channel.trust(fingerprint);
  assert.deepEqual(JSON.parse(h.sent[1]), {
    type: "trust",
    sha256: fingerprint,
  });
  h.receive({ type: "ready" });
  h.receive("4.sync,1.1;");
  assert.deepEqual(h.events.slice(-2), [
    ["ready"],
    ["protocol", "4.sync,1.1;"],
  ]);
  h.channel.dispose();
});

for (const early of [{ type: "ready" }, "4.sync,1.1;"]) {
  test(`rejects protocol or ready before trust: ${JSON.stringify(early)}`, () => {
    const h = setup();
    h.receive(early);
    assert.deepEqual(h.events.at(-1), ["failure", "native_protocol_error"]);
    assert.equal(h.socket.readyState, 3);
  });
}

test("cancel during certificate review closes socket and clears timers without trust", () => {
  const h = setup();
  h.certificate();
  h.channel.dispose();
  h.channel.trust(fingerprint);
  assert.equal(h.sent.length, 1);
  assert.equal(h.socket.readyState, 3);
  assert.equal(h.timers.size, 0);
});

test("ready input is ordered and secure attention uses a separate audited control message", () => {
  const h = setup();
  h.certificate();
  h.channel.trust(fingerprint);
  h.receive({ type: "ready" });
  h.channel.sendProtocol("3.key,2.65,1.1;");
  h.channel.sendProtocol("3.key,2.65,1.0;");
  h.channel.secureAttention();
  assert.deepEqual(h.sent.slice(-3), [
    "3.key,2.65,1.1;",
    "3.key,2.65,1.0;",
    '{"type":"secure_attention"}',
  ]);
  h.channel.dispose();
});

test("backpressure fails closed without replaying ambiguous input", () => {
  const h = setup();
  h.certificate();
  h.channel.trust(fingerprint);
  h.receive({ type: "ready" });
  h.socket.bufferedAmount = 300_000;
  h.channel.sendProtocol("3.key,2.65,1.1;");
  assert.deepEqual(h.events.at(-1), ["failure", "native_stream_backpressure"]);
  h.socket.bufferedAmount = 0;
  h.channel.sendProtocol("3.key,2.65,1.1;");
  assert.equal(h.sent.length, 2);
});

test("unrecognized server errors never render arbitrary diagnostic text", () => {
  const h = setup();
  h.receive({ type: "error", code: "password=do-not-display" });
  assert.deepEqual(h.events.at(-1), ["failure", "native_stream_failed"]);
});

test("malformed certificate, duplicate trust and post-close messages fail or are ignored", () => {
  const h = setup();
  h.receive({ type: "certificate", sha256: "invalid" });
  assert.deepEqual(h.events.at(-1), ["failure", "native_protocol_error"]);
  const count = h.events.length;
  h.certificate();
  assert.equal(h.events.length, count);
  const valid = setup();
  valid.certificate();
  valid.channel.trust(fingerprint);
  valid.channel.trust(fingerprint);
  assert.equal(valid.sent.length, 2);
  valid.channel.dispose();
});

test("handshake timeout closes the connection without automatic downgrade", () => {
  const h = setup();
  [...h.timers][0]();
  assert.deepEqual(h.events.at(-1), ["failure", "native_stream_timeout"]);
  assert.equal(h.socket.readyState, 3);
});
