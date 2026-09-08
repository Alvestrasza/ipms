export type NativeMetricsSample = { fps: number | null; rtt: number | null };

// These instructions schedule display work. Cursor-only updates, control
// messages and empty syncs are deliberately not counted as desktop frames.
// This is a drawing-batch rate, not pixel-difference detection or monitor Hz.
// Destination-layer parameter indexes from the pinned Guacamole 1.6.0 client.
// Negative layers are offscreen caches (including cursor image buffers).
const drawing = new Map([
  ["img", 2],
  ["png", 1],
  ["jpeg", 1],
  ["copy", 6],
  ["transfer", 6],
  ["cfill", 1],
  ["lfill", 1],
  ["cstroke", 1],
  ["lstroke", 1],
  ["size", 0],
  ["move", 0],
  ["shade", 0],
  ["dispose", 0],
  ["distort", 0],
]);
const maximumPendingFrames = 512;
const maximumPendingPings = 4;
const freshness = 3000;

export class NativeConsoleMetrics {
  private readonly now: () => number;
  private pendingFrames = new Map<string, boolean>();
  private pendingPings = new Map<string, number>();
  private dirty = false;
  private completed = 0;
  private overflowed = false;
  private sampledAt = 0;
  private latency: { value: number; receivedAt: number } | null = null;

  constructor(now: () => number = () => performance.now()) {
    this.now = now;
    this.reset();
  }

  reset() {
    this.pendingFrames.clear();
    this.pendingPings.clear();
    this.dirty = false;
    this.completed = 0;
    this.overflowed = false;
    this.latency = null;
    this.sampledAt = this.now();
  }

  instruction(opcode: string, parameters: string[]) {
    const target = drawing.get(opcode);
    if (target !== undefined && /^\d{1,10}$/.test(parameters[target] ?? ""))
      this.dirty = true;
    if (opcode === "sync" && /^\d{1,16}$/.test(parameters[0] ?? "")) {
      if (this.pendingFrames.size >= maximumPendingFrames) {
        this.pendingFrames.clear();
        this.overflowed = true;
      }
      this.pendingFrames.set(parameters[0], this.dirty);
      this.dirty = false;
    }
    if (opcode === "" && parameters.length === 2 && parameters[0] === "ping") {
      const sent = this.pendingPings.get(parameters[1]);
      this.pendingPings.delete(parameters[1]);
      if (sent !== undefined) {
        const now = this.now();
        const elapsed = now - sent;
        if (elapsed >= 0 && elapsed <= freshness)
          this.latency = { value: elapsed, receivedAt: now };
      }
    }
  }

  sent(elements: (string | number)[]) {
    // The pinned Client sends this acknowledgment only from its display.flush
    // completion callback, after asynchronous PNG decoding / drawing finishes.
    if (elements[0] === "sync") {
      const key = String(elements[1]);
      if (this.pendingFrames.get(key)) this.completed++;
      this.pendingFrames.delete(key);
    }
    if (elements.length === 3 && elements[0] === "" && elements[1] === "ping") {
      if (this.pendingPings.size >= maximumPendingPings) {
        const oldest = this.pendingPings.keys().next().value;
        if (oldest !== undefined) this.pendingPings.delete(oldest);
      }
      this.pendingPings.set(String(elements[2]), this.now());
    }
  }

  sample(): NativeMetricsSample {
    const now = this.now();
    const elapsed = now - this.sampledAt;
    const fps =
      !this.overflowed && elapsed > 0 && elapsed <= freshness
        ? (this.completed * 1000) / elapsed
        : null;
    const rtt =
      this.latency && now - this.latency.receivedAt <= freshness
        ? this.latency.value
        : null;
    this.sampledAt = now;
    this.completed = 0;
    this.overflowed = false;
    return { fps, rtt };
  }
}
