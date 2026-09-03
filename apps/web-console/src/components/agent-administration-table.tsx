"use client";

import { RefreshCw, Search, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useDeferredValue, useEffect, useState } from "react";

import type { Dictionary } from "@/i18n/dictionaries";
import type { ManagedAgent } from "@/lib/server-agents";

import { AgentLifecycleBootstrapDialog } from "./agent-lifecycle-bootstrap-dialog";

type Props = {
  agents: ManagedAgent[];
  csrfToken: string;
  tenantId: string;
  locale: "de" | "en";
  copy: Dictionary["agentAdministration"];
  deploymentCopy: Dictionary["addSystem"];
};

function formatDate(value: string | null, locale: "de" | "en") {
  if (!value) return "—";
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}

export function AgentAdministrationTable({
  agents,
  csrfToken,
  tenantId,
  locale,
  copy,
  deploymentCopy,
}: Props) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [busy, setBusy] = useState<Set<string>>(() => new Set());
  const [error, setError] = useState("");
  const [bootstrapAgent, setBootstrapAgent] = useState<ManagedAgent | null>(
    null,
  );
  const hasActiveJobs = agents.some((agent) => agent.active_job);
  const filtered = deferredQuery
    ? agents.filter((agent) =>
        [agent.fqdn, agent.operating_system, agent.agent_version].some(
          (value) => value.toLowerCase().includes(deferredQuery),
        ),
      )
    : agents;
  const selectedOutdated = filtered.filter(
    (agent) =>
      selected.has(agent.enrollment_id) &&
      agent.compliance === "outdated" &&
      !agent.active_job &&
      agent.status !== "revoked",
  );
  const outdated = filtered.filter(
    (agent) =>
      agent.compliance === "outdated" &&
      !agent.active_job &&
      agent.status !== "revoked",
  );

  useEffect(() => {
    if (!hasActiveJobs) return;
    const timer = window.setInterval(() => router.refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [hasActiveJobs, router]);

  function toggle(enrollmentId: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(enrollmentId)) next.delete(enrollmentId);
      else next.add(enrollmentId);
      return next;
    });
  }

  async function queue(agent: ManagedAgent, action: "update" | "uninstall") {
    setBusy((current) => new Set(current).add(agent.enrollment_id));
    setError("");
    try {
      const response = await fetch(
        `/api/v1/agents/${encodeURIComponent(agent.enrollment_id)}/lifecycle/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({ action }),
        },
      );
      if (!response.ok) throw new Error("lifecycle-job-rejected");
      router.refresh();
    } catch {
      setError(copy.actionFailed);
    } finally {
      setBusy((current) => {
        const next = new Set(current);
        next.delete(agent.enrollment_id);
        return next;
      });
    }
  }

  async function updateSelected() {
    const bootstrap = selectedOutdated.find(
      (agent) => !agent.lifecycle_capable,
    );
    if (bootstrap) {
      setBootstrapAgent(bootstrap);
      return;
    }
    for (const agent of selectedOutdated) await queue(agent, "update");
    setSelected(new Set());
  }

  async function updateAllOutdated() {
    const bootstrap = outdated.find((agent) => !agent.lifecycle_capable);
    if (bootstrap) {
      setBootstrapAgent(bootstrap);
      return;
    }
    for (const agent of outdated) await queue(agent, "update");
  }

  return (
    <section
      className="inventory-panel agent-admin-panel"
      aria-labelledby="agent-table-heading"
    >
      <div className="panel__header agent-admin-toolbar">
        <div>
          <p className="eyebrow">{copy.inventory}</p>
          <h2 id="agent-table-heading">{copy.tableHeading}</h2>
        </div>
        <div className="agent-admin-toolbar__actions">
          <label className="agent-search">
            <Search aria-hidden="true" size={16} />
            <span className="sr-only">{copy.search}</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={copy.search}
            />
          </label>
          <button
            className="outline-button"
            type="button"
            disabled={selectedOutdated.length === 0 || busy.size > 0}
            onClick={updateSelected}
          >
            <RefreshCw aria-hidden="true" size={16} />
            {copy.updateSelected} ({selectedOutdated.length})
          </button>
          <button
            className="outline-button"
            type="button"
            disabled={outdated.length === 0 || busy.size > 0}
            onClick={updateAllOutdated}
          >
            <RefreshCw aria-hidden="true" size={16} />
            {copy.updateAllOutdated} ({outdated.length})
          </button>
        </div>
      </div>
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">
                <span className="sr-only">{copy.select}</span>
              </th>
              <th scope="col">{copy.fqdn}</th>
              <th scope="col">{copy.status}</th>
              <th scope="col">{copy.operatingSystem}</th>
              <th scope="col">{copy.agentVersion}</th>
              <th scope="col">{copy.lastContact}</th>
              <th scope="col">{copy.actions}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((agent) => {
              const pending = Boolean(agent.active_job);
              const isBusy = busy.has(agent.enrollment_id);
              return (
                <tr key={agent.enrollment_id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(agent.enrollment_id)}
                      onChange={() => toggle(agent.enrollment_id)}
                      aria-label={`${copy.select} ${agent.fqdn}`}
                    />
                  </td>
                  <td>
                    <strong>{agent.fqdn}</strong>
                  </td>
                  <td>
                    <span
                      className={`agent-state agent-state--${agent.status}`}
                    >
                      {copy.states[agent.status]}
                    </span>
                    {agent.active_job ? (
                      <small className="agent-job-state">
                        {copy.jobStates[agent.active_job.status]}
                      </small>
                    ) : null}
                  </td>
                  <td>
                    {agent.operating_system || "—"}
                    {agent.os_version ? (
                      <small>{agent.os_version}</small>
                    ) : null}
                  </td>
                  <td>
                    <span>
                      {agent.agent_version ? `v${agent.agent_version}` : "—"}
                    </span>
                    <small
                      className={`agent-compliance agent-compliance--${agent.compliance}`}
                    >
                      {copy.compliance[agent.compliance]}
                      {agent.target_version
                        ? ` · v${agent.target_version}`
                        : ""}
                    </small>
                    {!agent.lifecycle_capable ? (
                      <small>{copy.bootstrapRequired}</small>
                    ) : null}
                  </td>
                  <td>{formatDate(agent.last_seen_at, locale)}</td>
                  <td>
                    <div className="agent-row-actions">
                      <button
                        className="icon-button icon-button--compact"
                        type="button"
                        disabled={
                          isBusy || pending || agent.compliance !== "outdated"
                        }
                        onClick={() => {
                          if (agent.lifecycle_capable)
                            void queue(agent, "update");
                          else setBootstrapAgent(agent);
                        }}
                        title={
                          agent.lifecycle_capable
                            ? copy.update
                            : copy.bootstrapAction
                        }
                        aria-label={`${
                          agent.lifecycle_capable
                            ? copy.update
                            : copy.bootstrapAction
                        } ${agent.fqdn}`}
                      >
                        <RefreshCw aria-hidden="true" size={16} />
                      </button>
                      <button
                        className="icon-button icon-button--compact icon-button--danger"
                        type="button"
                        disabled={
                          isBusy || pending || agent.status === "revoked"
                        }
                        onClick={() => {
                          if (!agent.lifecycle_capable) {
                            setBootstrapAgent(agent);
                            return;
                          }
                          if (
                            window.confirm(
                              `${copy.uninstallConfirm} ${agent.fqdn}?`,
                            )
                          ) {
                            void queue(agent, "uninstall");
                          }
                        }}
                        title={
                          agent.lifecycle_capable
                            ? copy.uninstall
                            : copy.bootstrapAction
                        }
                        aria-label={`${copy.uninstall} ${agent.fqdn}`}
                      >
                        <Trash2 aria-hidden="true" size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {filtered.length === 0 ? (
        <p className="table-empty">{copy.noAgents}</p>
      ) : null}
      {bootstrapAgent ? (
        <AgentLifecycleBootstrapDialog
          agent={bootstrapAgent}
          csrfToken={csrfToken}
          tenantId={tenantId}
          locale={locale}
          copy={copy}
          deploymentCopy={deploymentCopy}
          onClose={() => setBootstrapAgent(null)}
        />
      ) : null}
    </section>
  );
}
