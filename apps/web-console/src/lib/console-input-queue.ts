export type ConsoleInput = {
  type: string;
  payload: Record<string, number | boolean>;
};

/** Bounded, ordered delivery; only adjacent mouse moves may be replaced. */
export class ConsoleInputQueue {
  private pending: ConsoleInput[] = [];
  private sending: Promise<void> | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private deliver: (events: ConsoleInput[]) => Promise<void>;
  private failed: () => void;

  constructor(
    deliver: (events: ConsoleInput[]) => Promise<void>,
    failed: () => void,
  ) {
    this.deliver = deliver;
    this.failed = failed;
  }

  push(event: ConsoleInput) {
    if (this.stopped) return;
    const last = this.pending.at(-1);
    if (event.type === "mouse_move" && last?.type === "mouse_move") {
      this.pending[this.pending.length - 1] = event;
    } else if (this.pending.length < 128) {
      this.pending.push(event);
    } else {
      this.dispose();
      this.failed();
      return;
    }
    if (!this.timer && !this.sending) {
      this.timer = setTimeout(() => {
        this.timer = null;
        void this.flush();
      }, 25);
    }
  }

  async flush(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.sending) {
      await this.sending;
      return this.flush();
    }
    if (this.stopped || !this.pending.length) return;
    const events = this.pending.splice(0, 32);
    this.sending = this.deliver(events).catch(() => {
      // An uncertain acknowledgement must not replay clicks or secure attention.
      this.dispose();
      this.failed();
    });
    await this.sending;
    this.sending = null;
    if (!this.stopped && this.pending.length) await this.flush();
  }

  dispose() {
    this.stopped = true;
    this.pending = [];
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
}
