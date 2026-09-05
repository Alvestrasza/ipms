"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  type ConsoleCopy,
  type ConsoleDialogState,
  HyperVConsoleDialog,
} from "@/components/hyperv-console-dialog";
import type { HyperVVirtualMachine } from "@/lib/hyperv-types";

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
    loading: true,
    error: "",
  });
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
    let stopped = false;
    const close = () => {
      stopped = true;
      const id = sessionId.current;
      sessionId.current = null;
      if (id) void closeSession(id);
    };
    // Deferral prevents development Strict Mode's setup/cleanup probe from
    // creating a second remote session. Pending creation is closed on teardown.
    const timer = window.setTimeout(async () => {
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
            body: "{}",
          },
        );
        const document = await response.json();
        if (response.status === 409) {
          if (!stopped)
            setState({
              vm,
              session: null,
              occupied: document.session,
              loading: false,
              error: "",
            });
          return;
        }
        if (!response.ok) throw new Error("console_open_failed");
        if (stopped) {
          void closeSession(document.id);
          return;
        }
        sessionId.current = document.id;
        setState({
          vm,
          session: document,
          occupied: null,
          loading: false,
          error: "",
        });
      } catch {
        if (!stopped)
          setState({
            vm,
            session: null,
            occupied: null,
            loading: false,
            error: copy.unavailable,
          });
      }
    }, 0);
    window.addEventListener("pagehide", close);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("pagehide", close);
      close();
    };
  }, [vm, copy.title, copy.unavailable, csrfToken, tenantId, closeSession]);

  return (
    <HyperVConsoleDialog
      key={state.session?.id ?? (state.loading ? "loading" : "notice")}
      state={state}
      copy={copy}
      csrfToken={csrfToken}
      tenantId={tenantId}
      onClose={() => {
        const id = sessionId.current;
        sessionId.current = null;
        if (id) void closeSession(id);
        window.close();
      }}
    />
  );
}
