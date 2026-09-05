export type NativeCertificate = {
  sha256: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
};

export const nativeFailureCodes = [
  "native_protocol_error",
  "native_stream_failed",
  "native_stream_timeout",
  "native_stream_backpressure",
  "native_authentication_failed",
  "native_certificate_changed",
  "native_certificate_rejected",
  "native_agent_unavailable",
  "native_session_expired",
  "native_permission_denied",
  "native_configuration_required",
  "native_configuration_changed",
  "native_console_unavailable",
  "native_connection_failed",
] as const;
export type NativeFailureCode = (typeof nativeFailureCodes)[number];

export function safeNativeFailure(value: unknown): NativeFailureCode {
  return nativeFailureCodes.includes(value as NativeFailureCode)
    ? (value as NativeFailureCode)
    : "native_stream_failed";
}

type Socket = Pick<
  WebSocket,
  | "readyState"
  | "bufferedAmount"
  | "send"
  | "close"
  | "onopen"
  | "onmessage"
  | "onerror"
  | "onclose"
>;
type Options = {
  url: string;
  width: number;
  height: number;
  socketFactory?: (url: string, protocol: string) => Socket;
  schedule?: (callback: () => void, milliseconds: number) => () => void;
  onCertificate: (certificate: NativeCertificate) => void;
  onReady: () => void;
  onProtocol: (data: string) => void;
  onFailure: (code: NativeFailureCode) => void;
};

/** One fenced connection. Setup JSON never enters the Guacamole parser.
 * No reconnect/replay: a new session requires a fresh operator decision. */
export class NativeConsoleChannel {
  private options: Options;
  private socket: Socket | null = null;
  private phase:
    | "new"
    | "observing"
    | "trust"
    | "connecting"
    | "ready"
    | "closed" = "new";
  private certificate: NativeCertificate | null = null;
  private cancelDeadline: (() => void) | null = null;

  constructor(options: Options) {
    this.options = options;
  }

  private deadline(milliseconds: number) {
    this.cancelDeadline?.();
    const schedule =
      this.options.schedule ??
      ((callback, delay) => {
        const timer = setTimeout(callback, delay);
        return () => clearTimeout(timer);
      });
    this.cancelDeadline = schedule(
      () => this.fail("native_stream_timeout"),
      milliseconds,
    );
  }

  connect() {
    if (this.phase !== "new") return;
    const url = new URL(this.options.url);
    if (
      !["wss:", "ws:"].includes(url.protocol) ||
      url.search ||
      url.hash ||
      url.username ||
      url.password
    ) {
      this.fail("native_protocol_error");
      return;
    }
    this.phase = "observing";
    try {
      const socket = (
        this.options.socketFactory ??
        ((address, protocol) => new WebSocket(address, protocol))
      )(url.href, "guacamole");
      this.socket = socket;
      this.deadline(30_000);
      socket.onopen = () =>
        this.send(
          JSON.stringify({
            type: "connect",
            width: Math.max(
              200,
              Math.min(1920, Math.round(this.options.width)),
            ),
            height: Math.max(
              200,
              Math.min(1200, Math.round(this.options.height)),
            ),
          }),
        );
      socket.onmessage = (event) => this.receive(event.data);
      socket.onerror = () => this.fail("native_stream_failed");
      socket.onclose = () => this.fail("native_stream_failed");
    } catch {
      this.fail("native_stream_failed");
    }
  }

  private receive(data: unknown) {
    if (this.phase === "closed") return;
    if (typeof data !== "string" || data.length > 8_388_608) {
      this.fail("native_protocol_error");
      return;
    }
    if (this.phase === "ready" && !data.startsWith("{")) {
      this.deadline(20_000);
      try {
        this.options.onProtocol(data);
      } catch {
        this.fail("native_protocol_error");
      }
      return;
    }
    if (data.length > 16_384) {
      this.fail("native_protocol_error");
      return;
    }
    try {
      const message = JSON.parse(data);
      if (!message || typeof message !== "object" || Array.isArray(message))
        throw new Error();
      if (message.type === "error") {
        this.fail(safeNativeFailure(message.code));
        return;
      }
      if (message.type === "certificate" && this.phase === "observing") {
        if (
          typeof message.sha256 !== "string" ||
          !/^[a-fA-F0-9]{64}$/.test(message.sha256)
        )
          throw new Error();
        for (const key of ["subject", "issuer", "not_before", "not_after"])
          if (typeof message[key] !== "string" || message[key].length > 2048)
            throw new Error();
        this.certificate = {
          sha256: message.sha256,
          subject: message.subject,
          issuer: message.issuer,
          not_before: message.not_before,
          not_after: message.not_after,
        };
        this.phase = "trust";
        this.deadline(60_000);
        this.options.onCertificate(this.certificate);
        return;
      }
      if (message.type === "ready" && this.phase === "connecting") {
        this.phase = "ready";
        this.deadline(20_000);
        this.options.onReady();
        return;
      }
      throw new Error();
    } catch {
      this.fail("native_protocol_error");
    }
  }

  trust(sha256: string) {
    if (this.phase !== "trust" || sha256 !== this.certificate?.sha256) return;
    this.phase = "connecting";
    this.deadline(30_000);
    this.send(JSON.stringify({ type: "trust", sha256 }));
  }

  private send(data: string) {
    if (this.phase === "closed" || !this.socket || this.socket.readyState !== 1)
      return;
    if (this.socket.bufferedAmount + data.length > 262_144) {
      this.fail("native_stream_backpressure");
      return;
    }
    try {
      this.socket.send(data);
    } catch {
      this.fail("native_stream_failed");
    }
  }

  sendProtocol(data: string) {
    if (this.phase === "ready") this.send(data);
  }
  secureAttention() {
    if (this.phase === "ready") this.send('{"type":"secure_attention"}');
  }

  private fail(code: NativeFailureCode) {
    if (this.phase === "closed") return;
    this.dispose();
    this.options.onFailure(code);
  }

  dispose() {
    this.phase = "closed";
    this.cancelDeadline?.();
    this.cancelDeadline = null;
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      socket.close();
    }
  }
}
