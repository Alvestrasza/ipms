"use client";

import { Monitor, ShieldAlert, X } from "lucide-react";
import Script from "next/script";
import { useEffect, useRef, useState } from "react";
import { createNativeTunnel } from "@/lib/guacamole-runtime";
import type { NativeFailureCode } from "@/lib/native-console-channel";
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
  const [active, setActive] = useState(false);
  const [failure, setFailure] = useState<NativeFailureCode | null>(null);
  const container = useRef<HTMLDivElement | null>(null);
  const actions = useRef<{
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
        onReady: () => {
          if (!stopped) {
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
        client.sendKeyEvent(1, keysym);
        return false;
      };
      keyboard.onkeyup = (keysym) => client.sendKeyEvent(0, keysym);
      const mouse = new runtime.Mouse(element);
      const mouseEvents = ["mousedown", "mouseup", "mousemove"];
      const focusInput = () => element.focus({ preventScroll: true });
      const sendMouse = (state: typeof mouse.currentState) => {
        client.sendMouseState(
          {
            ...state,
            x: Math.max(0, Math.min(element.clientWidth - 1, state.x)),
            y: Math.max(0, Math.min(element.clientHeight - 1, state.y)),
          },
          true,
        );
      };
      const onMouse = (event: { state: typeof mouse.currentState }) => {
        if (event.state.left || event.state.middle || event.state.right)
          focusInput();
        sendMouse(event.state);
      };
      mouse.onEach(mouseEvents, onMouse);
      const release = () => {
        keyboard.reset();
        mouse.reset();
        sendMouse({
          ...mouse.currentState,
          left: false,
          middle: false,
          right: false,
          up: false,
          down: false,
        });
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
      element.addEventListener("mouseenter", focusInput);
      window.addEventListener("blur", release);
      client.onerror = () => {
        tunnel.disconnect();
        fail("native_stream_failed");
      };
      actions.current = {
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
        element.removeEventListener("mouseenter", focusInput);
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
