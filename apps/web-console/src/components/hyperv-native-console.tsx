"use client";

import { Monitor, ShieldAlert, X } from "lucide-react";
import Script from "next/script";
import { useEffect, useRef, useState } from "react";
import { createNativeTunnel } from "@/lib/guacamole-runtime";
import type {
  NativeCertificate,
  NativeFailureCode,
} from "@/lib/native-console-channel";
import type { ConsoleCopy } from "./hyperv-console-dialog";

export function HyperVNativeConsole({
  sessionId,
  name,
  copy,
  onClose,
}: {
  sessionId: string;
  name: string;
  copy: ConsoleCopy;
  onClose: () => void;
}) {
  const [loaded, setLoaded] = useState(false);
  const [certificate, setCertificate] = useState<NativeCertificate | null>(
    null,
  );
  const [active, setActive] = useState(false);
  const [failure, setFailure] = useState<NativeFailureCode | null>(null);
  const container = useRef<HTMLDivElement | null>(null);
  const trustDialog = useRef<HTMLDivElement | null>(null);
  const actions = useRef<{
    trust: (sha256: string) => void;
    secureAttention: () => void;
    release: () => void;
    disconnect: () => void;
  } | null>(null);

  useEffect(() => {
    if (!loaded || !container.current || !window.Guacamole) return;
    const host = container.current;
    const runtime = window.Guacamole;
    let cleanup = () => {};
    // Avoid a second fenced attachment during the development Strict Mode probe.
    const timer = window.setTimeout(() => {
      let stopped = false;
      const fail = (code: NativeFailureCode) => {
        if (!stopped) {
          setFailure(code);
          setActive(false);
        }
      };
      const endpoint = new URL(
        `/api/v1/hyper-v/console-sessions/${sessionId}/native-stream/`,
        window.location.origin,
      );
      endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
      const { tunnel, channel } = createNativeTunnel(runtime, {
        url: endpoint.href,
        width: host.clientWidth,
        height: host.clientHeight,
        onCertificate: (value) => {
          if (!stopped) setCertificate(value);
        },
        onReady: () => {
          if (!stopped) {
            setCertificate(null);
            setActive(true);
          }
        },
        onFailure: fail,
      });
      const client = new runtime.Client(tunnel);
      const display = client.getDisplay();
      const element = display.getElement();
      element.tabIndex = 0;
      element.setAttribute("role", "application");
      element.setAttribute("aria-label", copy.directInput);
      host.appendChild(element);
      const keyboard = new runtime.Keyboard(element);
      keyboard.onkeydown = (keysym) => {
        client.sendKeyEvent(true, keysym);
        return false;
      };
      keyboard.onkeyup = (keysym) => client.sendKeyEvent(false, keysym);
      const mouse = new runtime.Mouse(element);
      const mouseEvents = ["mousedown", "mouseup", "mousemove"];
      const onMouse = (event: { state: typeof mouse.currentState }) => {
        if (event.state.left || event.state.middle || event.state.right)
          element.focus({ preventScroll: true });
        client.sendMouseState(event.state, true);
      };
      mouse.onEach(mouseEvents, onMouse);
      const release = () => {
        keyboard.reset();
        mouse.reset();
        client.sendMouseState(
          {
            ...mouse.currentState,
            left: false,
            middle: false,
            right: false,
            up: false,
            down: false,
          },
          true,
        );
      };
      const resize = () => {
        const width = display.getWidth(),
          height = display.getHeight();
        if (width > 0 && height > 0)
          display.scale(
            Math.min(host.clientWidth / width, host.clientHeight / height),
          );
      };
      display.onresize = resize;
      const observer = new ResizeObserver(resize);
      observer.observe(host);
      element.addEventListener("blur", release);
      window.addEventListener("blur", release);
      client.onerror = () => {
        tunnel.disconnect();
        fail("native_stream_failed");
      };
      actions.current = {
        trust: (sha256) => {
          setCertificate(null);
          channel.trust(sha256);
        },
        secureAttention: () => {
          release();
          channel.secureAttention();
        },
        release,
        disconnect: () => {
          release();
          client.disconnect();
          channel.dispose();
        },
      };
      client.connect();
      cleanup = () => {
        stopped = true;
        release();
        keyboard.onkeydown = null;
        keyboard.onkeyup = null;
        mouse.offEach(mouseEvents, onMouse);
        client.onerror = null;
        display.onresize = null;
        client.disconnect();
        tunnel.disconnect();
        observer.disconnect();
        element.removeEventListener("blur", release);
        window.removeEventListener("blur", release);
        element.remove();
        actions.current = null;
      };
    }, 0);
    return () => {
      window.clearTimeout(timer);
      cleanup();
    };
  }, [loaded, sessionId, copy.directInput]);

  useEffect(() => {
    const dialog = trustDialog.current;
    if (!certificate || !dialog) return;
    const buttons = Array.from(dialog.querySelectorAll("button"));
    buttons[0]?.focus();
    const trapFocus = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const first = buttons[0],
        last = buttons.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    dialog.addEventListener("keydown", trapFocus);
    return () => dialog.removeEventListener("keydown", trapFocus);
  }, [certificate]);

  const close = () => {
    actions.current?.disconnect();
    onClose();
  };
  return (
    <main
      className="hyperv-console-window"
      aria-labelledby="native-console-title"
    >
      <Script
        src="/vendor/guacamole/1.6.0/all.min.js"
        strategy="afterInteractive"
        integrity="sha384-KdJzE+xcyZMbc+g6Xf5GiFtoHW/nBPBbLMaiA/zm5jc5aMbvUf2aorH84gHjlfCV"
        crossOrigin="anonymous"
        onReady={() => setLoaded(true)}
        onError={() => setFailure("native_stream_failed")}
      />
      <header className="hyperv-console-toolbar">
        <div>
          <Monitor size={19} aria-hidden="true" />
          <strong id="native-console-title">
            {copy.title}: {name}
          </strong>
        </div>
        <div className="hyperv-console-toolbar__actions">
          <button
            type="button"
            className="outline-button hyperv-console-secure-attention"
            disabled={!active || !!failure}
            title={copy.secureAttentionHint}
            onClick={() => actions.current?.secureAttention()}
          >
            <ShieldAlert size={16} aria-hidden="true" />
            {copy.secureAttention}
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label={copy.close}
            onClick={close}
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>
      </header>
      <div className="native-console-body">
        <div
          ref={container}
          className="native-console-display"
          style={{ visibility: active && !failure ? "visible" : "hidden" }}
        />
        {failure ? (
          <div
            className="hyperv-console-notice hyperv-console-notice--error native-console-overlay"
            role="alert"
          >
            <strong>{copy.unavailable}</strong>
            <span>
              {copy.native.errors[failure] ??
                copy.native.errors.native_stream_failed}
            </span>
            <button type="button" className="outline-button" onClick={close}>
              {copy.close}
            </button>
          </div>
        ) : certificate ? (
          <div
            ref={trustDialog}
            className="native-console-overlay native-certificate"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="native-certificate-title"
            aria-describedby="native-certificate-description"
          >
            <div className="native-console-card">
              <h2 id="native-certificate-title">
                {copy.native.certificateTitle}
              </h2>
              <p id="native-certificate-description">
                {copy.native.certificateDescription}
              </p>
              <dl>
                {(
                  [
                    [copy.native.subject, certificate.subject],
                    [copy.native.issuer, certificate.issuer],
                    [copy.native.validFrom, certificate.not_before],
                    [copy.native.validUntil, certificate.not_after],
                    [copy.native.fingerprint, certificate.sha256],
                  ] as const
                ).map(([label, value]) => (
                  <div key={label}>
                    <dt>{label}</dt>
                    <dd>{value}</dd>
                  </div>
                ))}
              </dl>
              <div className="native-console-buttons">
                <button
                  type="button"
                  className="outline-button"
                  onClick={close}
                >
                  {copy.native.cancel}
                </button>
                <button
                  type="button"
                  className="primary-button"
                  onClick={() => actions.current?.trust(certificate.sha256)}
                >
                  {copy.native.trust}
                </button>
              </div>
            </div>
          </div>
        ) : !active ? (
          <div
            className="hyperv-console-notice native-console-overlay"
            role="status"
          >
            <strong>{copy.connecting}</strong>
          </div>
        ) : (
          <span className="sr-only" role="status">
            {copy.native.ready}
          </span>
        )}
      </div>
    </main>
  );
}
