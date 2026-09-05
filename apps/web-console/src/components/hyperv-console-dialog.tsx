"use client";

import { Keyboard, Monitor, ShieldAlert, X } from "lucide-react";
import {
  type MouseEvent as ReactMouseEvent,
  useEffect,
  useRef,
  useState,
} from "react";

import { ConsoleInputQueue } from "@/lib/console-input-queue";
import type {
  HyperVConsoleSession,
  HyperVVirtualMachine,
} from "@/lib/hyperv-types";

export type ConsoleCopy = {
  title: string;
  close: string;
  secureAttention: string;
  secureAttentionHint: string;
  connecting: string;
  waitingForFrame: string;
  directInput: string;
  sessionInUse: string;
  sessionInUseDetail: string;
  unavailable: string;
  failed: string;
  expired: string;
  native: {
    nativeMode: string;
    thumbnailMode: string;
    connect: string;
    cancel: string;
    externalWarning: string;
    externalAcknowledgement: string;
    configurationRequired: string;
    manageServiceAccounts: string;
    checkConfiguration: string;
    saved: string;
    certificateTitle: string;
    certificateDescription: string;
    trust: string;
    subject: string;
    issuer: string;
    validFrom: string;
    validUntil: string;
    fingerprint: string;
    ready: string;
    thumbnailHint: string;
    errors: Record<string, string>;
  };
};

export type ConsoleDialogState = {
  vm: HyperVVirtualMachine;
  session: HyperVConsoleSession | null;
  occupied: HyperVConsoleSession | null;
  loading: boolean;
  error: string;
};

const KEY_CODES: Record<string, number> = {
  Backspace: 8,
  Tab: 9,
  Enter: 13,
  ShiftLeft: 16,
  ShiftRight: 16,
  ControlLeft: 17,
  ControlRight: 17,
  AltLeft: 18,
  AltRight: 18,
  Pause: 19,
  CapsLock: 20,
  Escape: 27,
  Space: 32,
  PageUp: 33,
  PageDown: 34,
  End: 35,
  Home: 36,
  ArrowLeft: 37,
  ArrowUp: 38,
  ArrowRight: 39,
  ArrowDown: 40,
  Insert: 45,
  Delete: 46,
  MetaLeft: 91,
  MetaRight: 92,
  ContextMenu: 93,
  Numpad0: 96,
  Numpad1: 97,
  Numpad2: 98,
  Numpad3: 99,
  Numpad4: 100,
  Numpad5: 101,
  Numpad6: 102,
  Numpad7: 103,
  Numpad8: 104,
  Numpad9: 105,
  NumpadMultiply: 106,
  NumpadAdd: 107,
  NumpadSubtract: 109,
  NumpadDecimal: 110,
  NumpadDivide: 111,
  NumLock: 144,
  ScrollLock: 145,
  Semicolon: 186,
  Equal: 187,
  Comma: 188,
  Minus: 189,
  Period: 190,
  Slash: 191,
  Backquote: 192,
  BracketLeft: 219,
  Backslash: 220,
  BracketRight: 221,
  Quote: 222,
};

for (let index = 0; index <= 9; index += 1) {
  KEY_CODES[`Digit${index}`] = 48 + index;
}
for (let index = 0; index < 26; index += 1) {
  KEY_CODES[`Key${String.fromCharCode(65 + index)}`] = 65 + index;
}
for (let index = 1; index <= 24; index += 1) {
  KEY_CODES[`F${index}`] = 111 + index;
}

function buttonIndex(button: number) {
  if (button === 0) return 1;
  if (button === 2) return 2;
  if (button === 1) return 3;
  return null;
}

export function HyperVConsoleDialog({
  state,
  copy,
  csrfToken,
  tenantId,
  onClose,
}: {
  state: ConsoleDialogState;
  copy: ConsoleCopy;
  csrfToken: string;
  tenantId: string;
  onClose: () => void;
}) {
  const [session, setSession] = useState(state.session);
  const [frameUrl, setFrameUrl] = useState("");
  const [error, setError] = useState(state.error);
  const [frameError, setFrameError] = useState("");
  const frameSequence = useRef(0);
  const frameUrlRef = useRef("");
  const pressedKeys = useRef(new Set<number>());
  const pressedButtons = useRef(new Set<number>());
  const surface = useRef<HTMLDivElement | null>(null);
  const inputQueue = useRef<ConsoleInputQueue | null>(null);
  const activeSessionId = session?.id;

  useEffect(() => {
    if (!activeSessionId) return;
    const queue = new ConsoleInputQueue(
      async (events) => {
        const response = await fetch(
          `/api/v1/hyper-v/console-sessions/${activeSessionId}/input/`,
          {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/json",
              "X-CSRFToken": csrfToken,
              "X-IPMS-Tenant-ID": tenantId,
            },
            body: JSON.stringify({ events }),
            signal: AbortSignal.timeout(8000),
          },
        );
        if (!response.ok) throw new Error("input_rejected");
      },
      () => setError(copy.unavailable),
    );
    inputQueue.current = queue;
    return () => {
      queue.dispose();
      inputQueue.current = null;
    };
  }, [activeSessionId, copy.unavailable, csrfToken, tenantId]);

  function sendInput(type: string, payload: Record<string, number | boolean>) {
    if (session?.status === "active")
      inputQueue.current?.push({ type, payload });
  }

  useEffect(() => {
    const element = surface.current;
    if (!element || session?.status !== "active" || error || frameError) return;
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      inputQueue.current?.push({
        type: "mouse_wheel",
        payload: { delta: event.deltaY < 0 ? 120 : -120 },
      });
    };
    element.addEventListener("wheel", wheel, { passive: false });
    return () => element.removeEventListener("wheel", wheel);
  }, [session?.status, error, frameError]);

  useEffect(() => {
    if (!activeSessionId) return;
    let stopped = false;
    let timer = 0;
    const sessionId = activeSessionId;
    const controller = new AbortController();
    const poll = async () => {
      const started = performance.now();
      let retry = false;
      try {
        const response = await fetch(
          `/api/v1/hyper-v/console-sessions/${sessionId}/frame/?after=${frameSequence.current}`,
          {
            cache: "no-store",
            credentials: "same-origin",
            headers: { "X-IPMS-Tenant-ID": tenantId },
            signal: controller.signal,
          },
        );
        if (!response.ok) throw new Error("frame_rejected");
        if (stopped) return;
        setFrameError("");
        const status = response.headers.get(
          "X-IPMS-Console-Status",
        ) as HyperVConsoleSession["status"];
        if (
          !["requested", "active", "failed", "expired", "closed"].includes(
            status,
          )
        )
          throw new Error("status_rejected");
        const sequence = Number(response.headers.get("X-IPMS-Frame-Sequence"));
        setSession((current) =>
          current
            ? {
                ...current,
                status,
                failure_code:
                  response.headers.get("X-IPMS-Console-Failure") ?? "",
                frame_sequence: sequence,
                frame_width: Number(response.headers.get("X-IPMS-Frame-Width")),
                frame_height: Number(
                  response.headers.get("X-IPMS-Frame-Height"),
                ),
              }
            : current,
        );
        if (response.status === 200) {
          const nextUrl = URL.createObjectURL(await response.blob());
          if (stopped) {
            URL.revokeObjectURL(nextUrl);
            return;
          }
          if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
          frameUrlRef.current = nextUrl;
          frameSequence.current = sequence;
          setFrameUrl(nextUrl);
        }
        if (["failed", "expired", "closed"].includes(status)) {
          inputQueue.current?.dispose();
          return;
        }
      } catch {
        retry = true;
        if (!stopped) setFrameError(copy.unavailable);
      }
      if (!stopped)
        timer = window.setTimeout(
          poll,
          retry ? 1000 : Math.max(25, 150 - (performance.now() - started)),
        );
    };
    void poll();
    return () => {
      stopped = true;
      controller.abort();
      window.clearTimeout(timer);
      if (frameUrlRef.current) {
        URL.revokeObjectURL(frameUrlRef.current);
        frameUrlRef.current = "";
      }
    };
  }, [activeSessionId, copy.unavailable, tenantId]);

  function sendKey(code: string, isDown: boolean, repeat: boolean) {
    const keyCode = KEY_CODES[code];
    if (!keyCode || repeat) return;
    if (isDown) pressedKeys.current.add(keyCode);
    else pressedKeys.current.delete(keyCode);
    void sendInput("key", { key_code: keyCode, is_down: isDown });
  }

  function releasePressedKeys() {
    for (const keyCode of pressedKeys.current) {
      void sendInput("key", { key_code: keyCode, is_down: false });
    }
    pressedKeys.current.clear();
    for (const button of pressedButtons.current)
      sendInput("mouse_button", { button, is_down: false });
    pressedButtons.current.clear();
  }

  function queueMousePosition(event: ReactMouseEvent<HTMLDivElement>) {
    if (!session?.frame_width || !session.frame_height) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const scale = Math.min(
      bounds.width / session.frame_width,
      bounds.height / session.frame_height,
    );
    const renderedWidth = session.frame_width * scale;
    const renderedHeight = session.frame_height * scale;
    const renderedLeft = bounds.left + (bounds.width - renderedWidth) / 2;
    const renderedTop = bounds.top + (bounds.height - renderedHeight) / 2;
    sendInput("mouse_move", {
      x: Math.max(
        0,
        Math.min(
          session.frame_width - 1,
          Math.round(
            ((event.clientX - renderedLeft) / renderedWidth) *
              session.frame_width,
          ),
        ),
      ),
      y: Math.max(
        0,
        Math.min(
          session.frame_height - 1,
          Math.round(
            ((event.clientY - renderedTop) / renderedHeight) *
              session.frame_height,
          ),
        ),
      ),
    });
  }

  const terminalMessage =
    session?.status === "failed"
      ? `${copy.failed} (${session.failure_code || "unknown"})`
      : session?.status === "expired" || session?.status === "closed"
        ? copy.expired
        : error || frameError;

  return (
    <main
      className="hyperv-console-window"
      aria-labelledby="hyperv-console-heading"
    >
      <header className="hyperv-console-toolbar">
        <div>
          <Monitor aria-hidden="true" size={19} />
          <strong id="hyperv-console-heading">
            {copy.title}: {state.vm.name}
          </strong>
        </div>
        <div className="hyperv-console-toolbar__actions">
          <button
            type="button"
            className="outline-button hyperv-console-secure-attention"
            title={copy.secureAttentionHint}
            disabled={session?.status !== "active"}
            onClick={() => void sendInput("secure_attention", {})}
          >
            <ShieldAlert aria-hidden="true" size={16} />
            <span>{copy.secureAttention}</span>
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label={copy.close}
            onClick={async () => {
              releasePressedKeys();
              await inputQueue.current?.flush();
              onClose();
            }}
          >
            <X aria-hidden="true" size={18} />
          </button>
        </div>
      </header>
      {state.occupied ? (
        <div
          className="hyperv-console-notice hyperv-console-notice--warning"
          role="alert"
        >
          <ShieldAlert aria-hidden="true" size={24} />
          <strong>{copy.sessionInUse}</strong>
          <span>
            {copy.sessionInUseDetail
              .replace("{user}", state.occupied.requested_by)
              .replace(
                "{time}",
                new Date(state.occupied.created_at).toLocaleString(),
              )}
          </span>
        </div>
      ) : state.loading || session?.status === "requested" ? (
        <div className="hyperv-console-notice" role="status">
          <Keyboard aria-hidden="true" size={24} />
          <strong>{copy.connecting}</strong>
          <span>{copy.waitingForFrame}</span>
        </div>
      ) : terminalMessage ? (
        <div
          className="hyperv-console-notice hyperv-console-notice--error"
          role="alert"
        >
          <ShieldAlert aria-hidden="true" size={24} />
          <strong>{copy.unavailable}</strong>
          <span>{terminalMessage}</span>
        </div>
      ) : (
        <div
          ref={surface}
          className="hyperv-console-surface"
          // The console surface intentionally owns focus for direct VM input.
          // biome-ignore lint/a11y/noNoninteractiveTabindex: Interactive remote console surface.
          tabIndex={0}
          role="application"
          aria-label={copy.directInput}
          onKeyDown={(event) => {
            event.preventDefault();
            sendKey(event.code, true, event.repeat);
          }}
          onKeyUp={(event) => {
            event.preventDefault();
            sendKey(event.code, false, false);
          }}
          onBlur={releasePressedKeys}
          onPointerMove={queueMousePosition}
          onPointerDown={(event) => {
            event.currentTarget.focus();
            event.currentTarget.setPointerCapture(event.pointerId);
            queueMousePosition(event);
            const button = buttonIndex(event.button);
            if (button) {
              pressedButtons.current.add(button);
              void sendInput("mouse_button", { button, is_down: true });
            }
          }}
          onPointerUp={(event) => {
            const button = buttonIndex(event.button);
            if (button) {
              pressedButtons.current.delete(button);
              void sendInput("mouse_button", { button, is_down: false });
            }
          }}
          onPointerCancel={releasePressedKeys}
          onContextMenu={(event) => event.preventDefault()}
        >
          {frameUrl ? (
            // The frame is an authenticated, short-lived object URL and is never cached.
            // biome-ignore lint/performance/noImgElement: Next Image cannot render blob URLs.
            <img src={frameUrl} alt="" draggable={false} />
          ) : (
            <span>{copy.waitingForFrame}</span>
          )}
        </div>
      )}
    </main>
  );
}
