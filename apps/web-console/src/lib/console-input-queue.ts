export type ConsoleInput = {
  type: string;
  payload: Record<string, number | boolean>;
};

type ScheduleInput = (callback: () => void, delayMs: number) => () => void;

const scheduleInput: ScheduleInput = (callback, delayMs) => {
  const timer = setTimeout(callback, delayMs);
  return () => clearTimeout(timer);
};

/** Bounded, ordered delivery; only adjacent mouse moves may be replaced. */
export class ConsoleInputQueue {
  private pending: ConsoleInput[] = [];
  private sending: Promise<void> | null = null;
  private cancelTimer: (() => void) | null = null;
  private stopped = false;
  private deliver: (events: ConsoleInput[]) => Promise<void>;
  private failed: () => void;
  private schedule: ScheduleInput;

  constructor(
    deliver: (events: ConsoleInput[]) => Promise<void>,
    failed: () => void,
    schedule: ScheduleInput = scheduleInput,
  ) {
    this.deliver = deliver;
    this.failed = failed;
    this.schedule = schedule;
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
    if (this.sending) return;
    // Clicks and keys must not wait behind the motion-coalescing timer. The
    // ordered batch includes the latest pointer position preceding a click.
    if (event.type !== "mouse_move") {
      void this.flush();
    } else if (!this.cancelTimer) {
      this.cancelTimer = this.schedule(() => {
        this.cancelTimer = null;
        void this.flush();
      }, 8);
    }
  }

  async flush(): Promise<void> {
    if (this.cancelTimer) {
      this.cancelTimer();
      this.cancelTimer = null;
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
    this.cancelTimer?.();
    this.cancelTimer = null;
  }
}
