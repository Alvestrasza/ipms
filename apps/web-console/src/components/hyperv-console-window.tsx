"use client";

import { Monitor, X } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  type ConsoleCopy,
  type ConsoleDialogState,
  HyperVConsoleDialog,
} from "@/components/hyperv-console-dialog";
import { HyperVNativeConsole } from "@/components/hyperv-native-console";
import type { HyperVVirtualMachine } from "@/lib/hyperv-types";

type Configuration = {
  configured: boolean;
  can_manage: boolean;
  native_supported: boolean;
};

export function HyperVConsoleWindow({
  vm,
  copy,
  csrfToken,
  tenantId,
  serviceAccountsHref,
}: {
  vm: HyperVVirtualMachine;
  copy: ConsoleCopy;
  csrfToken: string;
  tenantId: string;
  serviceAccountsHref: string;
}) {
  const [state, setState] = useState<ConsoleDialogState>({
    vm,
    session: null,
    occupied: null,
    loading: false,
    error: "",
  });
  const [configuration, setConfiguration] = useState<Configuration | null>(
    null,
  );
  const [transport, setTransport] = useState<"vmconnect" | "thumbnail">(
    "vmconnect",
  );
  const [acknowledged, setAcknowledged] = useState(false);
  const [checkingConfiguration, setCheckingConfiguration] = useState(false);
  const checking = useRef(false);
  const mounted = useRef(false);
  const creating = useRef(false);
  const sessionId = useRef<string | null>(null);
  const closeSession = useCallback(
    (id: string) =>
      fetch(`/api/v1/hyper-v/console-sessions/${id}/`, {
        method: "DELETE",
        credentials: "same-origin",
        keepalive: true,
        headers: { "X-CSRFToken": csrfToken, "X-IPMS-Tenant-ID": tenantId },
      }).catch(() => undefined),
    [csrfToken, tenantId],
  );

  useEffect(() => {
    document.title = `${copy.title}: ${vm.name} | IPMS`;
    mounted.current = true;
    const controller = new AbortController();
    const close = () => {
      mounted.current = false;
      const id = sessionId.current;
      sessionId.current = null;
      if (id) void closeSession(id);
    };
    void fetch(
      `/api/v1/hyper-v/virtual-machines/${vm.id}/console-configuration/`,
      {
        cache: "no-store",
        credentials: "same-origin",
        signal: controller.signal,
        headers: { "X-IPMS-Tenant-ID": tenantId },
      },
    )
      .then(async (response) => {
        if (!response.ok) throw new Error();
        const result = (await response.json()) as Configuration;
        if (
          [result.configured, result.can_manage, result.native_supported].some(
            (value) => typeof value !== "boolean",
          )
        )
          throw new Error();
        if (!controller.signal.aborted) {
          setConfiguration(result);
          setTransport(result.native_supported ? "vmconnect" : "thumbnail");
        }
      })
      .catch(() => {
        if (!controller.signal.aborted)
          setState((current) => ({ ...current, error: copy.unavailable }));
      });
    window.addEventListener("pagehide", close);
    return () => {
      controller.abort();
      window.removeEventListener("pagehide", close);
      close();
    };
  }, [vm.id, vm.name, copy.title, copy.unavailable, tenantId, closeSession]);

  async function checkConfiguration() {
    if (checking.current || creating.current || sessionId.current) return;
    checking.current = true;
    setCheckingConfiguration(true);
    try {
      const response = await fetch(
        `/api/v1/hyper-v/virtual-machines/${vm.id}/console-configuration/`,
        {
          cache: "no-store",
          credentials: "same-origin",
          signal: AbortSignal.timeout(15_000),
          headers: { "X-IPMS-Tenant-ID": tenantId },
        },
      );
      if (!response.ok) throw new Error();
      const result = (await response.json()) as Configuration;
      if (
        [result.configured, result.can_manage, result.native_supported].some(
          (value) => typeof value !== "boolean",
        )
      )
        throw new Error();
      if (mounted.current && !creating.current && !sessionId.current) {
        setConfiguration(result);
        setState((current) => ({ ...current, error: "" }));
      }
    } catch {
      if (mounted.current && !creating.current && !sessionId.current)
        setState((current) => ({ ...current, error: copy.unavailable }));
    } finally {
      checking.current = false;
      if (mounted.current) setCheckingConfiguration(false);
    }
  }

  const close = () => {
    mounted.current = false;
    const id = sessionId.current;
    sessionId.current = null;
    if (id) void closeSession(id);
    window.close();
  };

  const connect = async () => {
    if (
      creating.current ||
      !configuration ||
      (transport === "vmconnect" &&
        (!configuration.native_supported ||
          !configuration.configured ||
          !acknowledged))
    )
      return;
    creating.current = true;
    setState((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await fetch(
        `/api/v1/hyper-v/virtual-machines/${vm.id}/console-sessions/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify(
            transport === "vmconnect"
              ? { transport, external_session_acknowledged: true }
              : { transport },
          ),
        },
      );
      const result = await response.json();
      if (response.status === 409) {
        if (mounted.current)
          setState({
            vm,
            session: null,
            occupied: result.session ?? null,
            loading: false,
            error: result.session ? "" : copy.unavailable,
          });
        return;
      }
      if (!response.ok || typeof result.id !== "string") throw new Error();
      if (!mounted.current) {
        void closeSession(result.id);
        return;
      }
      sessionId.current = result.id;
      setState({
        vm,
        session: { ...result, transport },
        occupied: null,
        loading: false,
        error: "",
      });
    } catch {
      if (mounted.current)
        setState((current) => ({
          ...current,
          loading: false,
          error: copy.unavailable,
        }));
    } finally {
      creating.current = false;
    }
  };

  if (state.session?.transport === "vmconnect")
    return (
      <HyperVNativeConsole
        sessionId={state.session.id}
        name={vm.name}
        copy={copy}
        onClose={close}
      />
    );
  if (state.session || state.occupied || state.loading)
    return (
      <HyperVConsoleDialog
        key={state.session?.id ?? "notice"}
        state={state}
        copy={copy}
        csrfToken={csrfToken}
        tenantId={tenantId}
        onClose={close}
      />
    );
  return (
    <main
      className="hyperv-console-window"
      aria-labelledby="console-setup-title"
    >
      <header className="hyperv-console-toolbar">
        <div>
          <Monitor size={19} aria-hidden="true" />
          <strong id="console-setup-title">
            {copy.title}: {vm.name}
          </strong>
        </div>
        <button
          type="button"
          className="icon-button"
          aria-label={copy.close}
          onClick={close}
        >
          <X size={18} aria-hidden="true" />
        </button>
      </header>
      <div className="native-console-setup">
        <div className="native-console-card">
          {state.error && <p role="alert">{state.error}</p>}
          {!configuration && !state.error ? (
            <p role="status">{copy.connecting}</p>
          ) : configuration ? (
            <>
              <fieldset className="native-console-modes">
                <legend>{copy.title}</legend>
                <label>
                  <input
                    type="radio"
                    name="console-transport"
                    checked={transport === "vmconnect"}
                    disabled={!configuration.native_supported}
                    onChange={() => setTransport("vmconnect")}
                  />
                  {copy.native.nativeMode}
                </label>
                <label>
                  <input
                    type="radio"
                    name="console-transport"
                    checked={transport === "thumbnail"}
                    onChange={() => setTransport("thumbnail")}
                  />
                  {copy.native.thumbnailMode}
                </label>
              </fieldset>
              {transport === "vmconnect" ? (
                <>
                  <p>{copy.native.externalWarning}</p>
                  <label className="native-console-ack">
                    <input
                      type="checkbox"
                      checked={acknowledged}
                      onChange={(event) =>
                        setAcknowledged(event.target.checked)
                      }
                    />
                    {copy.native.externalAcknowledgement}
                  </label>
                  {configuration.configured ? (
                    <p role="status">{copy.native.saved}</p>
                  ) : (
                    <div>
                      <p role="status">{copy.native.configurationRequired}</p>
                      <button
                        className="outline-button"
                        type="button"
                        disabled={checkingConfiguration}
                        onClick={() => void checkConfiguration()}
                      >
                        {copy.native.checkConfiguration}
                      </button>
                      {configuration.can_manage ? (
                        <Link
                          className="outline-button"
                          href={serviceAccountsHref as Route}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {copy.native.manageServiceAccounts}
                        </Link>
                      ) : null}
                    </div>
                  )}
                </>
              ) : (
                <p>{copy.native.thumbnailHint}</p>
              )}
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
                  disabled={
                    transport === "vmconnect" &&
                    (!acknowledged || !configuration.configured)
                  }
                  onClick={() => void connect()}
                >
                  {copy.native.connect}
                </button>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </main>
  );
}
