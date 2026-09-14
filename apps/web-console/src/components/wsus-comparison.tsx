/**
 * File Name: wsus-comparison.tsx
 * Version: v0.1.0
 * Created: 2026-09-13 | Modified: 2026-09-13
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Present WSUS evidence and separate Agent observations without deployment controls.
 */
import type { WsusCopy } from "@/i18n/wsus-copy";
import type {
  WsusComparison,
  WsusServer,
  WsusServerUpdates,
  WsusUpdateState,
} from "@/lib/wsus-types";
import styles from "./wsus-console.module.css";

export function WsusPagination({
  data,
  busy,
  copy,
  onPage,
}: {
  data: { count: number; page: number; page_size: number };
  busy: boolean;
  copy: WsusCopy;
  onPage: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(data.count / data.page_size));
  return (
    <div className={styles.pagination}>
      <span>
        {copy.total}: {data.count} · {copy.page} {data.page} / {pages}
      </span>
      <button
        className="outline-button"
        type="button"
        disabled={busy || data.page <= 1}
        onClick={() => onPage(data.page - 1)}
      >
        {copy.previous}
      </button>
      <button
        className="outline-button"
        type="button"
        disabled={busy || data.page >= pages}
        onClick={() => onPage(data.page + 1)}
      >
        {copy.next}
      </button>
    </div>
  );
}

export function WsusComparisonView({
  data,
  copy,
  busy,
  date,
  observedAt,
  onPage,
  onDetails,
}: {
  data: WsusComparison;
  copy: WsusCopy;
  busy: boolean;
  date: (value: string | null) => string;
  observedAt: number;
  onPage: (page: number) => void;
  onDetails: (server: WsusServer) => void;
}) {
  const hasWsusClients = (data.snapshot?.computer_count ?? 0) > 0;
  return (
    <>
      <section
        className={`inventory-panel ${styles.panel}`}
        aria-labelledby="wsus-snapshot-heading"
      >
        <div className="panel__header">
          <h2 id="wsus-snapshot-heading">{copy.snapshot}</h2>
        </div>
        {data.snapshot ? (
          <dl className={styles.summary}>
            <div>
              <dt>{copy.observed}</dt>
              <dd>{date(data.snapshot.observed_at)}</dd>
            </div>
            <div>
              <dt>{copy.received}</dt>
              <dd>{date(data.snapshot.received_at)}</dd>
            </div>
            <div>
              <dt>{copy.updates}</dt>
              <dd>{data.snapshot.update_count}</dd>
            </div>
            <div>
              <dt>{copy.computers}</dt>
              <dd>{data.snapshot.computer_count}</dd>
            </div>
            <div>
              <dt>{copy.unmatched}</dt>
              <dd>{data.unmatched_computers}</dd>
            </div>
            <div>
              <dt>{copy.ambiguous}</dt>
              <dd>{data.ambiguous_computers}</dd>
            </div>
          </dl>
        ) : (
          <p className="table-empty">{copy.noSnapshot}</p>
        )}
      </section>
      {data.snapshot && data.snapshot.computer_count === 0 ? (
        <p className="preview-notice">{copy.catalogOnly}</p>
      ) : null}
      <section
        className={`inventory-panel ${styles.panel}`}
        aria-labelledby="wsus-comparison-heading"
      >
        <div className="panel__header">
          <h2 id="wsus-comparison-heading">{copy.comparison}</h2>
        </div>
        <p className={styles.hint}>{copy.agentHint}</p>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">{copy.hostname}</th>
                <th scope="col">{copy.agentEvidence}</th>
                {hasWsusClients ? (
                  <>
                    <th scope="col">{copy.match}</th>
                    <th scope="col">{copy.wsusStatus}</th>
                    <th scope="col">{copy.counts}</th>
                  </>
                ) : null}
                <th scope="col">{copy.agent}</th>
                <th scope="col">{copy.details}</th>
              </tr>
            </thead>
            <tbody>
              {data.results.map((server) => (
                <tr key={server.server_id}>
                  <td>
                    <strong>{server.hostname}</strong>
                    <small>{server.fqdn}</small>
                    <small>
                      {copy.inventory}: {date(server.inventory_at)}
                    </small>
                    {server.inventory_stale ? (
                      <small className={styles.warning}>
                        {copy.inventoryStale}
                      </small>
                    ) : null}
                  </td>
                  <td>
                    <dl className={styles.counts}>
                      <div>
                        <dt>{copy.agentEvidenceStatus}</dt>
                        <dd>
                          {server.agent_evidence
                            ? (copy.agentEvidenceStates[
                                server.agent_evidence.status
                              ] ?? copy.unknown)
                            : copy.unknown}
                        </dd>
                      </div>
                      <div>
                        <dt>{copy.observed}</dt>
                        <dd>
                          {date(server.agent_evidence?.observed_at ?? null)}
                        </dd>
                      </div>
                      <div>
                        <dt>{copy.agentInstalled}</dt>
                        <dd>
                          {server.agent_evidence?.status === "collected"
                            ? server.agent_evidence.installed_matches
                            : copy.unknown}
                        </dd>
                      </div>
                      <div>
                        <dt>{copy.agentRevision}</dt>
                        <dd>
                          {server.agent_evidence?.status === "collected"
                            ? server.agent_evidence.revision_mismatches
                            : copy.unknown}
                        </dd>
                      </div>
                      <div>
                        <dt>{copy.agentUnknown}</dt>
                        <dd>
                          {server.agent_evidence?.unknown ?? copy.unknown}
                        </dd>
                      </div>
                    </dl>
                    {server.agent_evidence?.stale ? (
                      <small className={styles.warning}>
                        {copy.evidenceStale}
                      </small>
                    ) : null}
                  </td>
                  {hasWsusClients ? (
                    <>
                      <td>
                        {copy.matchStates[server.match_status] ?? copy.unknown}
                      </td>
                      <td>
                        <strong>
                          {copy.wsusStates[server.wsus_status] ?? copy.unknown}
                        </strong>
                        <small>
                          {copy.reported}: {date(server.reported_at)}
                        </small>
                      </td>
                      <td>
                        {server.match_status === "matched" ? (
                          <dl className={styles.counts}>
                            {(
                              Object.keys(
                                copy.updateStates,
                              ) as WsusUpdateState[]
                            ).map((state) => (
                              <div key={state}>
                                <dt>{copy.updateStates[state]}</dt>
                                <dd>{server.counts[state] ?? copy.unknown}</dd>
                              </div>
                            ))}
                          </dl>
                        ) : (
                          copy.unknown
                        )}
                      </td>
                    </>
                  ) : null}
                  <td>
                    {server.agent ? (
                      <dl className={styles.counts}>
                        <div>
                          <dt>{copy.scanStatus}</dt>
                          <dd>
                            {copy.agentScanStates[
                              server.agent
                                .scan_status as keyof WsusCopy["agentScanStates"]
                            ] ?? copy.unknown}
                          </dd>
                        </div>
                        <div>
                          <dt>{copy.scan}</dt>
                          <dd>{date(server.agent.last_scan_at)}</dd>
                        </div>
                        <div>
                          <dt>{copy.availableUpdates}</dt>
                          <dd>
                            {["current", "updates-available"].includes(
                              server.agent.scan_status,
                            )
                              ? (server.agent.updates_available ?? copy.unknown)
                              : copy.unknown}
                          </dd>
                        </div>
                        <div>
                          <dt>{copy.reboot}</dt>
                          <dd>
                            {server.agent.reboot_required === true
                              ? copy.yes
                              : server.agent.reboot_required === false
                                ? copy.no
                                : copy.unknown}
                          </dd>
                        </div>
                        {!server.agent.last_scan_at ||
                        !Number.isFinite(
                          Date.parse(server.agent.last_scan_at),
                        ) ||
                        Date.parse(server.agent.last_scan_at) <
                          observedAt - 86_400_000 ? (
                          <div className={styles.warning}>
                            <dt>{copy.agentStale}</dt>
                            <dd>—</dd>
                          </div>
                        ) : null}
                      </dl>
                    ) : (
                      copy.unknown
                    )}
                  </td>
                  <td>
                    <button
                      className="outline-button"
                      type="button"
                      disabled={busy || !data.snapshot}
                      onClick={() => onDetails(server)}
                      aria-label={`${copy.details}: ${server.hostname}`}
                    >
                      {copy.details}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!data.results.length ? (
          <p className="table-empty">{copy.noServers}</p>
        ) : null}
        <WsusPagination data={data} busy={busy} copy={copy} onPage={onPage} />
      </section>
    </>
  );
}

export function WsusServerUpdatesView({
  data,
  server,
  copy,
  busy,
  onPage,
  onClose,
  date,
  hasWsusClients,
}: {
  data: WsusServerUpdates;
  server: WsusServer;
  copy: WsusCopy;
  busy: boolean;
  onPage: (page: number) => void;
  onClose: () => void;
  date: (value: string | null) => string;
  hasWsusClients: boolean;
}) {
  return (
    <section
      className={`inventory-panel ${styles.panel}`}
      aria-labelledby="wsus-updates-heading"
    >
      <div className="panel__header">
        <div>
          <h2 id="wsus-updates-heading">{copy.serverUpdates}</h2>
          <p>{server.fqdn || server.hostname}</p>
        </div>
        <button
          className="outline-button"
          type="button"
          disabled={busy}
          onClick={onClose}
        >
          {copy.closeDetails}
        </button>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">{copy.update}</th>
              <th scope="col">{copy.products}</th>
              <th scope="col">{copy.severity}</th>
              <th scope="col">{copy.agentEvidence}</th>
              {hasWsusClients ? <th scope="col">{copy.state}</th> : null}
            </tr>
          </thead>
          <tbody>
            {data.results.map((update) => (
              <tr key={`${update.update_id}:${update.revision}`}>
                <td className={styles.updateTitle}>
                  <strong>{update.title}</strong>
                  <small>
                    {update.kb_articles.join(", ") || "—"} · {copy.revision}{" "}
                    {update.revision}
                  </small>
                </td>
                <td className={styles.updateTitle}>
                  {update.products.join(", ") || copy.unknown}
                  <small>{update.classification || copy.unknown}</small>
                </td>
                <td>{update.severity || copy.unknown}</td>
                <td>
                  {copy.agentUpdateStates[update.agent_state] ?? copy.unknown}
                  <small>
                    {copy.observed}: {date(update.agent_observed_at)}
                  </small>
                </td>
                {hasWsusClients ? (
                  <td>{copy.updateStates[update.state] ?? copy.unknown}</td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!data.results.length ? (
        <p className="table-empty">{copy.noUpdates}</p>
      ) : null}
      <WsusPagination data={data} busy={busy} copy={copy} onPage={onPage} />
    </section>
  );
}
