"use client";

import { Monitor, X } from "lucide-react";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
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
}: {
  vm: HyperVVirtualMachine;
  copy: ConsoleCopy;
  csrfToken: string;
  tenantId: string;
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
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
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

  const saveAccount = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!configuration?.can_manage || saving) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    setSaving(true);
    setSaveError("");
    try {
      const response = await fetch(
        `/api/v1/hyper-v/virtual-machines/${vm.id}/console-configuration/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({
            username: fields.get("username"),
            password: fields.get("password"),
            domain: fields.get("domain"),
          }),
        },
      );
      if (!response.ok) throw new Error();
      const result = (await response.json()) as Configuration;
      if (!result.configured) throw new Error();
      if (mounted.current) {
        setConfiguration(result);
        setEditing(false);
      }
    } catch {
      if (mounted.current) setSaveError(copy.native.saveFailed);
    } finally {
      form.reset();
      fields.delete("password");
      if (mounted.current) setSaving(false);
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
                  {configuration.configured && !editing ? (
                    <div>
                      <p role="status">{copy.native.saved}</p>
                      {configuration.can_manage && (
                        <button
                          type="button"
                          className="outline-button"
                          onClick={() => setEditing(true)}
                        >
                          {copy.native.rotate}
                        </button>
                      )}
                    </div>
                  ) : configuration.can_manage ? (
                    <form
                      onSubmit={saveAccount}
                      autoComplete="off"
                      className="native-account-form"
                    >
                      <h2>{copy.native.configurationTitle}</h2>
                      <p>{copy.native.configurationDescription}</p>
                      <label>
                        {copy.native.username}
                        <input
                          name="username"
                          required
                          maxLength={256}
                          autoComplete="off"
                        />
                      </label>
                      <label>
                        {copy.native.domain}
                        <input
                          name="domain"
                          maxLength={256}
                          autoComplete="off"
                        />
                      </label>
                      <label>
                        {copy.native.password}
                        <input
                          name="password"
                          type="password"
                          required
                          maxLength={1024}
                          autoComplete="new-password"
                        />
                      </label>
                      {saveError && <p role="alert">{saveError}</p>}
                      <div className="native-console-buttons">
                        <button
                          type="submit"
                          className="primary-button"
                          disabled={saving}
                        >
                          {copy.native.configure}
                        </button>
                        {configuration.configured && (
                          <button
                            type="button"
                            className="outline-button"
                            disabled={saving}
                            onClick={() => setEditing(false)}
                          >
                            {copy.native.cancel}
                          </button>
                        )}
                      </div>
                    </form>
                  ) : (
                    <p role="status">{copy.native.configurationRequired}</p>
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
                    saving ||
                    editing ||
                    (transport === "vmconnect" &&
                      (!acknowledged || !configuration.configured))
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
