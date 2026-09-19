/**
 * File Name: gpo-directory-viewer.tsx
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Render validated read-only directory and managed GPO observations.
 */
import type { Locale } from "@/i18n/config";
import { getGpoDirectoryCopy } from "@/i18n/gpo-directory-copy";
import type {
  GpoDirectoryItem,
  GpoDirectoryView,
} from "@/lib/gpo-production-types";
import styles from "./gpo-production.module.css";

function status(
  value: boolean | null,
  copy: ReturnType<typeof getGpoDirectoryCopy>,
) {
  return value === null ? copy.unknown : value ? copy.enabled : copy.disabled;
}

function versions(
  value: GpoDirectoryItem["computer_version"],
  unknown: string,
) {
  return value ? `${value.directory} / ${value.sysvol}` : unknown;
}

export function GpoDirectoryViewer({
  directory,
  locale,
}: {
  directory: GpoDirectoryView;
  locale: Locale;
}) {
  const c = getGpoDirectoryCopy(locale);
  const observed = directory.nodes.filter((node) => node.observed).length;
  return (
    <section className={styles.viewer} aria-labelledby="gpo-directory-title">
      <div className={styles.heading}>
        <div>
          <h3 id="gpo-directory-title">{c.title}</h3>
          <p>{c.description}</p>
        </div>
        <strong>{directory.domain_dns_name}</strong>
      </div>
      <p className={styles.viewerBoundary}>{c.boundary}</p>
      <dl className={styles.viewerStats}>
        <div>
          <dt>{c.configuredTargets}</dt>
          <dd>{directory.nodes.length}</dd>
        </div>
        <div>
          <dt>{c.observedTargets}</dt>
          <dd>{observed}</dd>
        </div>
        <div>
          <dt>{c.managedGpos}</dt>
          <dd>{directory.gpos.length}</dd>
        </div>
      </dl>
      <details open>
        <summary>{c.configuredTargets}</summary>
        <div className={styles.viewerGrid}>
          {directory.nodes.map((node) => (
            <article key={node.dn} className={styles.viewerCard}>
              <div className={styles.heading}>
                <strong>{node.dn}</strong>
                <span>Tier {node.tiers.join(", ")}</span>
              </div>
              <p>{node.observed ? c.observed : c.notObserved}</p>
              {node.blocked !== null ? (
                <p>
                  {node.blocked ? c.inheritanceBlocked : c.inheritanceEnabled}
                </p>
              ) : null}
              <small>
                {c.directLinks}: {node.links.length} · {c.inheritedLinks}:{" "}
                {node.inherited_links.length}
              </small>
            </article>
          ))}
        </div>
      </details>
      <details open>
        <summary>{c.managedGpos}</summary>
        {directory.gpos.length ? (
          <div className={styles.viewerGrid}>
            {directory.gpos.map((gpo) => (
              <article key={gpo.managed_id} className={styles.viewerCard}>
                <div className={styles.heading}>
                  <strong>{gpo.name}</strong>
                  <span>{c.sources[gpo.source]}</span>
                </div>
                <dl className={styles.metadata}>
                  <div>
                    <dt>{c.state}</dt>
                    <dd>{gpo.state}</dd>
                  </div>
                  <div>
                    <dt>{c.tier}</dt>
                    <dd>{gpo.tier}</dd>
                  </div>
                  <div>
                    <dt>{c.computer}</dt>
                    <dd>{status(gpo.computer_enabled, c)}</dd>
                  </div>
                  <div>
                    <dt>{c.user}</dt>
                    <dd>{status(gpo.user_enabled, c)}</dd>
                  </div>
                  <div>
                    <dt>{c.versions} Computer</dt>
                    <dd>{versions(gpo.computer_version, c.unknown)}</dd>
                  </div>
                  <div>
                    <dt>{c.versions} User</dt>
                    <dd>{versions(gpo.user_version, c.unknown)}</dd>
                  </div>
                  <div>
                    <dt>{c.owner}</dt>
                    <dd>{gpo.owner_sid ?? c.unknown}</dd>
                  </div>
                  <div>
                    <dt>{c.wmi}</dt>
                    <dd>{gpo.wmi_filter || c.none}</dd>
                  </div>
                </dl>
                <p>
                  {c.targets}: {gpo.targets.join(" · ")}
                </p>
                <p>
                  {c.links}: {gpo.links.length}
                </p>
                {!gpo.observed_at ? <p>{c.noEvidence}</p> : null}
                <details>
                  <summary>{c.technical}</summary>
                  <pre>{JSON.stringify(gpo, null, 2)}</pre>
                </details>
              </article>
            ))}
          </div>
        ) : (
          <p>{c.noGpos}</p>
        )}
      </details>
    </section>
  );
}
