/**
 * File Name: gpo-state-review.tsx
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Render immutable directory observations without interpreting them as authority.
 */
import type { Locale } from "@/i18n/config";
import { getGpoProductionCopy } from "@/i18n/gpo-production-copy";
import type { GpoSnapshot } from "@/lib/gpo-production-types";
import styles from "./gpo-production.module.css";
export function GpoStateReview({
  state,
  displayName,
  locale,
}: {
  state: GpoSnapshot;
  displayName: string;
  locale: Locale;
}) {
  const c = getGpoProductionCopy(locale);
  return (
    <section className={styles.review} aria-label={c.inspection}>
      <h4>{c.inspection}</h4>
      <dl className={styles.metadata}>
        <div>
          <dt>{c.proposedName}</dt>
          <dd>{displayName}</dd>
        </div>
        <div>
          <dt>{c.existing}</dt>
          <dd>{state.gpo?.name ?? c.newIdentity}</dd>
        </div>
        {state.gpo ? (
          <>
            <div>
              <dt>Computer</dt>
              <dd>{state.gpo.computer_enabled ? c.enabled : c.disabled}</dd>
            </div>
            <div>
              <dt>User</dt>
              <dd>{state.gpo.user_enabled ? c.enabled : c.disabled}</dd>
            </div>
          </>
        ) : null}
      </dl>
      {!state.name_available ? <p role="alert">{c.unavailableName}</p> : null}
      <h5>
        {state.ous.some((ou) => /^DC=/i.test(ou.dn)) ? c.domainRoot : c.ou}
      </h5>
      {state.ous.length ? (
        <ul className={styles.targets}>
          {state.ous.map((ou) => (
            <li key={ou.guid}>
              <strong>{ou.dn}</strong>
              <span>
                {c.links}: {ou.links.length}
                {ou.blocked ? ` · ${c.blocked}` : ""}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p>{c.noOus}</p>
      )}
      <p>{c.unchanged}</p>
      <details>
        <summary>{c.technical}</summary>
        <pre>{JSON.stringify(state, null, 2)}</pre>
      </details>
    </section>
  );
}
