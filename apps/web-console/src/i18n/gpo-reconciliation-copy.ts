/**
 * File Name: gpo-reconciliation-copy.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Explain observation, explicit acceptance and the remaining import uncertainty.
 */
import type { Locale } from "./config";
import { gpoApiError } from "./gpo-error-copy";

const en = {
  title: "Directory reconciliation",
  requestedAt: "Requested at (UTC)",
  expiresAt: "Valid until (UTC)",
  incompleteLinks: "Not fully determinable",
  fields: {
    guid: "GPO GUID",
    name: "GPO name",
    computer_enabled: "Computer policy enabled",
    user_enabled: "User policy enabled",
    computer_ds: "Computer AD version",
    computer_sysvol: "Computer SYSVOL version",
    user_ds: "User AD version",
    user_sysvol: "User SYSVOL version",
  },
  request: "Reconcile directory",
  accept: "Accept reconciliation",
  retry: "Retry the same request",
  refresh: "Refresh reconciliation",
  boundary:
    "The Agent reads the directory and its execution journal. Requesting or accepting reconciliation does not change GPOs, permissions or links in AD.",
  acceptance:
    "Acceptance records this observation only after the Agent reads it again and acknowledges it. The domain remains locked until that acknowledgement.",
  content:
    "Baseline content import is not confirmed. GPO version counters and links do not prove that the baseline content was imported successfully.",
  unavailable:
    "Reconciliation could not be loaded or its response is invalid. Refresh before continuing.",
  uncertain:
    "The request result is uncertain. Refresh to reconcile its existing ID, or retry the same request. Do not start another request.",
  rejected:
    "Reconciliation was rejected. Refresh and check the displayed prerequisites before continuing.",
  observed: "Observed directory state",
  expected: "Approved target links",
  actual: "Observed forest links",
  none: "None",
  unknown: "Unknown",
  yes: "Yes",
  no: "No",
  presence: "GPO presence",
  complete: "Forest link search complete",
  acl: "AD and SYSVOL permissions consistent",
  quiescent: "Agent worker stopped and journal settled",
  issues: "Findings requiring attention",
  before: "State at original approval",
  after: "Observed now",
  field: "Property",
  missing: "Approved target link missing",
  extra: "Link outside the approved targets",
  order: "Order",
  enabled: "Enabled",
  enforced: "Enforced",
  retained:
    "The original failure remains in the history. Reconciliation is not a successful import receipt.",
  statuses: {
    requested: "Agent observation requested",
    observed: "Observation available",
    accept_requested: "Awaiting Agent verification and acknowledgement",
    accepted: "Reconciliation accepted",
    failed: "Observation failed",
    stale: "Observation no longer current",
  },
  presenceValues: { present: "Present", absent: "Absent", unknown: "Unknown" },
};
const de: typeof en = {
  title: "Verzeichnisabgleich",
  requestedAt: "Angefordert am (UTC)",
  expiresAt: "Gültig bis (UTC)",
  incompleteLinks: "Nicht vollständig ermittelbar",
  fields: {
    guid: "GPO-GUID",
    name: "GPO-Name",
    computer_enabled: "Computerrichtlinien aktiv",
    user_enabled: "Benutzerrichtlinien aktiv",
    computer_ds: "Computer-AD-Version",
    computer_sysvol: "Computer-SYSVOL-Version",
    user_ds: "Benutzer-AD-Version",
    user_sysvol: "Benutzer-SYSVOL-Version",
  },
  request: "Verzeichnis abgleichen",
  accept: "Abgleich übernehmen",
  retry: "Denselben Auftrag erneut senden",
  refresh: "Abgleich aktualisieren",
  boundary:
    "Der Agent liest das Verzeichnis und sein Ausführungsjournal. Anfordern und Übernehmen des Abgleichs ändern keine GPOs, Berechtigungen oder Verknüpfungen im AD.",
  acceptance:
    "Die Übernahme erfasst diese Beobachtung erst, nachdem der Agent sie erneut gelesen und bestätigt hat. Bis zu dieser Bestätigung bleibt die Domäne gesperrt.",
  content:
    "Der Import des Baseline-Inhalts ist nicht bestätigt. GPO-Versionszähler und Verknüpfungen belegen keinen erfolgreichen Import der Baseline-Inhalte.",
  unavailable:
    "Der Abgleich konnte nicht geladen werden oder seine Antwort ist ungültig. Aktualisiere die Ansicht vor dem Fortfahren.",
  uncertain:
    "Das Auftragsergebnis ist unklar. Aktualisiere die Ansicht zum Abgleich der bestehenden ID oder sende denselben Auftrag erneut. Starte keinen weiteren Auftrag.",
  rejected:
    "Der Abgleich wurde abgelehnt. Aktualisiere die Ansicht und prüfe die angezeigten Voraussetzungen vor dem Fortfahren.",
  observed: "Beobachteter Verzeichniszustand",
  expected: "Freigegebene Zielverknüpfungen",
  actual: "Beobachtete Forest-Verknüpfungen",
  none: "Keine",
  unknown: "Unbekannt",
  yes: "Ja",
  no: "Nein",
  presence: "GPO vorhanden",
  complete: "Forest-Linksuche vollständig",
  acl: "AD- und SYSVOL-Berechtigungen konsistent",
  quiescent: "Agent-Arbeitsprozess beendet und Journal geklärt",
  issues: "Zu prüfende Feststellungen",
  before: "Zustand bei ursprünglicher Freigabe",
  after: "Jetzt beobachtet",
  field: "Eigenschaft",
  missing: "Freigegebene Zielverknüpfung fehlt",
  extra: "Verknüpfung außerhalb der freigegebenen Ziele",
  order: "Reihenfolge",
  enabled: "Aktiviert",
  enforced: "Erzwungen",
  retained:
    "Der ursprüngliche Fehler bleibt im Verlauf erhalten. Der Abgleich ist kein erfolgreicher Importnachweis.",
  statuses: {
    requested: "Agent-Beobachtung angefordert",
    observed: "Beobachtung verfügbar",
    accept_requested: "Wartet auf erneute Agent-Prüfung und Bestätigung",
    accepted: "Abgleich übernommen",
    failed: "Beobachtung fehlgeschlagen",
    stale: "Beobachtung nicht mehr aktuell",
  },
  presenceValues: {
    present: "Vorhanden",
    absent: "Nicht vorhanden",
    unknown: "Unbekannt",
  },
};
const reasons: Record<string, [string, string]> = {
  legacy_journal_unsupported: [
    "This legacy job cannot use automatic reconciliation. Have an administrator inspect its original journal.",
    "Dieser Altauftrag unterstützt keinen automatischen Abgleich. Lasse einen Administrator sein ursprüngliches Journal prüfen.",
  ],
  job_not_reconcilable: [
    "This job does not require reconciliation.",
    "Dieser Auftrag benötigt keinen Abgleich.",
  ],
  already_reconciled: [
    "The directory result has already been reconciled.",
    "Das Verzeichnisergebnis wurde bereits abgeglichen.",
  ],
  domain_tier_not_authorized: [
    "An explicit authorization for this domain and tier is required.",
    "Eine ausdrückliche Berechtigung für diese Domäne und dieses Tier ist erforderlich.",
  ],
  agent_update_required: [
    "Update the original executing Agent to version 0.2.37 or newer.",
    "Aktualisiere den ursprünglich ausführenden Agent auf Version 0.2.37 oder neuer.",
  ],
  executor_unavailable: [
    "The original executing Agent is unavailable. Check its connection and domain identity.",
    "Der ursprünglich ausführende Agent ist nicht verfügbar. Prüfe seine Verbindung und Domänenidentität.",
  ],
  original_job_changed: [
    "The original job changed. Refresh its Logs before requesting reconciliation.",
    "Der ursprüngliche Auftrag hat sich geändert. Aktualisiere seine Logs vor einem Abgleich.",
  ],
  configuration_changed: [
    "The domain configuration changed. Review it and request a new observation.",
    "Die Domänenkonfiguration hat sich geändert. Prüfe sie und fordere eine neue Beobachtung an.",
  ],
  policy_unavailable: [
    "The managed GPO identity is unavailable. Have an administrator verify the original policy record.",
    "Die verwaltete GPO-Identität ist nicht verfügbar. Lasse den ursprünglichen Richtliniendatensatz prüfen.",
  ],
  reconciliation_pending: [
    "A reconciliation is already pending. Wait for its Agent result.",
    "Ein Abgleich ist bereits offen. Warte auf sein Agent-Ergebnis.",
  ],
  reconciliation_limit: [
    "The reconciliation limit was reached. Have an administrator review the request history.",
    "Das Abgleichlimit wurde erreicht. Lasse einen Administrator den Auftragsverlauf prüfen.",
  ],
  observation_pending: [
    "Wait for the Agent observation before accepting it.",
    "Warte vor der Übernahme auf die Agent-Beobachtung.",
  ],
  observation_stale: [
    "The observation expired or changed. Request a fresh observation.",
    "Die Beobachtung ist abgelaufen oder hat sich geändert. Fordere eine neue Beobachtung an.",
  ],
  acceptance_pending: [
    "The Agent must verify and acknowledge the accepted observation. The domain is still locked.",
    "Der Agent muss die übernommene Beobachtung erneut prüfen und bestätigen. Die Domäne bleibt gesperrt.",
  ],
  already_accepted: [
    "This observation has already been accepted.",
    "Diese Beobachtung wurde bereits übernommen.",
  ],
  four_eyes_required: [
    "A different administrator authorized for this domain and tier must accept the observation.",
    "Ein anderer, für Domäne und Tier berechtigter Administrator muss die Beobachtung übernehmen.",
  ],
  observation_unverifiable: [
    "The Agent could not verify the observation. Inspect its findings before requesting another observation.",
    "Der Agent konnte die Beobachtung nicht bestätigen. Prüfe seine Feststellungen vor einer weiteren Beobachtung.",
  ],
  unknown_guid: [
    "The original GPO GUID is unknown. The GPO cannot safely be identified by name alone.",
    "Die ursprüngliche GPO-GUID ist unbekannt. Der Name allein identifiziert die GPO nicht sicher.",
  ],
  ownership_unverified: [
    "The GPO ownership marker does not prove IPMS ownership. Verify its identity before continuing.",
    "Die Eigentumsmarkierung bestätigt keine IPMS-Zuordnung. Prüfe die GPO-Identität vor dem Fortfahren.",
  ],
  gpo_not_disabled: [
    "The observed GPO is enabled. Reconciliation cannot accept an active policy as a disabled import.",
    "Die beobachtete GPO ist aktiviert. Der Abgleich kann eine aktive Richtlinie nicht als deaktivierten Import übernehmen.",
  ],
  forest_incomplete: [
    "The Agent could not inspect all forest links. Check access to the forest domains and retry the observation.",
    "Der Agent konnte nicht alle Forest-Verknüpfungen prüfen. Prüfe den Zugriff auf die Forest-Domänen und wiederhole die Beobachtung.",
  ],
  link_scope_conflict: [
    "Observed links exceed or conflict with the approved targets. Compare every listed link with the original request.",
    "Beobachtete Verknüpfungen überschreiten die freigegebenen Ziele oder widersprechen ihnen. Vergleiche jede aufgeführte Verknüpfung mit dem ursprünglichen Auftrag.",
  ],
  acl_inconsistent: [
    "AD and SYSVOL permissions do not match. Have an administrator verify both permission sets.",
    "AD- und SYSVOL-Berechtigungen stimmen nicht überein. Lasse beide Berechtigungssätze prüfen.",
  ],
  state_inconsistent: [
    "The directory observation is inconsistent. Review the GPO identity, versions and targets.",
    "Die Verzeichnisbeobachtung ist widersprüchlich. Prüfe GPO-Identität, Versionsstände und Ziele.",
  ],
  observation_issues: [
    "The observation contains unresolved findings. Review them before another attempt.",
    "Die Beobachtung enthält ungeklärte Feststellungen. Prüfe sie vor einem weiteren Versuch.",
  ],
  gpo_reconciliation_quiescence_unavailable: [
    "The Agent cannot prove its worker has stopped. The domain remains locked; check the worker and journal.",
    "Der Agent kann nicht bestätigen, dass sein Arbeitsprozess beendet ist. Die Domäne bleibt gesperrt; prüfe Prozess und Journal.",
  ],
  gpo_reconciliation_guid_unknown: [
    "The journal does not identify a GPO GUID. Do not infer identity from the GPO name.",
    "Das Journal enthält keine bestätigte GPO-GUID. Leite die Identität nicht aus dem GPO-Namen ab.",
  ],
  gpo_reconciliation_state_unavailable: [
    "The Agent did not return a readable directory state. This older report does not identify the failed step or prove an access problem. A diagnostic Agent update and a fresh observation are required.",
    "Der Agent hat keinen lesbaren Verzeichniszustand geliefert. Dieser ältere Bericht benennt den fehlgeschlagenen Schritt nicht und belegt kein Zugriffsproblem. Für die Diagnose sind ein Agent-Update und ein neuer Abgleich erforderlich.",
  ],
  gpo_reconciliation_domain_open_failed: [
    "The Agent could not open the GPMC connection to the assigned domain controller. Review the accompanying Windows error code and the executor identity.",
    "Der Agent konnte die GPMC-Verbindung zum zugewiesenen Domain Controller nicht öffnen. Prüfe den zusätzlichen Windows-Fehlercode und die Identität des ausführenden Agents.",
  ],
  gpo_reconciliation_gpo_open_failed: [
    "GPMC could not open or verify the GPO using its recorded GUID. Review the accompanying Windows error code and this exact GPO. This does not prove that the GPO is absent.",
    "GPMC konnte die GPO anhand der gespeicherten GUID nicht öffnen oder bestätigen. Prüfe den zusätzlichen Windows-Fehlercode und genau diese GPO. Damit ist nicht bewiesen, dass die GPO fehlt.",
  ],
  gpo_reconciliation_metadata_failed: [
    "The GPO was opened, but its target or policy metadata could not be read completely. Review the accompanying Windows error code.",
    "Die GPO wurde geöffnet, ihre Ziel- oder Richtlinienmetadaten konnten aber nicht vollständig gelesen werden. Prüfe den zusätzlichen Windows-Fehlercode.",
  ],
  gpo_reconciliation_worker_failed: [
    "The isolated reconciliation process failed before returning a valid report. Review Agent process and protected journal diagnostics; this does not prove an AD permission problem.",
    "Der isolierte Abgleichprozess ist ohne gültigen Bericht fehlgeschlagen. Prüfe die Agent-Prozess- und Journaldiagnose; ein AD-Berechtigungsproblem ist damit nicht belegt.",
  ],
  gpo_reconciliation_worker_timeout: [
    "The reconciliation process exceeded its time limit or was cancelled. Check Agent availability and domain controller connectivity before retrying.",
    "Der Abgleichprozess hat sein Zeitlimit überschritten oder wurde abgebrochen. Prüfe Agent-Verfügbarkeit und Erreichbarkeit des Domain Controllers vor einem neuen Versuch.",
  ],
  gpo_reconciliation_result_invalid: [
    "The Agent rejected an inconsistent or oversized observation. Keep the domain locked and have the Agent report validation investigated.",
    "Der Agent hat einen widersprüchlichen oder zu großen Bericht verworfen. Die Domäne bleibt gesperrt; die Validierung des Agent-Berichts muss untersucht werden.",
  ],
  gpo_permission_denied: [
    "Windows reported access denied for the indicated step. Review the executing service identity and its permissions on that target.",
    "Windows hat für den angegebenen Schritt Zugriff verweigert gemeldet. Prüfe die ausführende Dienstidentität und ihre Rechte auf diesem Ziel.",
  ],
  gpo_reconciliation_acl_inconsistent: [
    "AD and SYSVOL permissions differ; inspect both ACLs.",
    "AD- und SYSVOL-Berechtigungen unterscheiden sich; prüfe beide ACLs.",
  ],
  gpo_preflight_required: [
    "A fresh directory observation is required.",
    "Eine neue Verzeichnisbeobachtung ist erforderlich.",
  ],
  gpo_identity_mismatch: [
    "The observed domain or GPO identity does not match the original request.",
    "Die beobachtete Domänen- oder GPO-Identität stimmt nicht mit dem ursprünglichen Auftrag überein.",
  ],
  gpo_state_changed: [
    "The directory changed after observation. Request another observation.",
    "Das Verzeichnis hat sich nach der Beobachtung geändert. Fordere eine weitere Beobachtung an.",
  ],
  gpo_target_invalid: [
    "A target could not be verified. Check its identity and the original target list.",
    "Ein Ziel konnte nicht bestätigt werden. Prüfe seine Identität und die ursprüngliche Zielliste.",
  ],
};
export const getReconciliationCopy = (locale: Locale) =>
  locale === "de" ? de : en;
export function reconciliationReason(code: string | null, locale: Locale) {
  if (code && /^gpo_reconciliation_hresult_[89a-f][0-9a-f]{7}$/.test(code)) {
    const value = `0x${code.slice(-8).toUpperCase()}`;
    return locale === "de"
      ? `Windows-Fehlercode (HRESULT): ${value}. Zusammen mit dem fehlgeschlagenen Schritt für die Diagnose verwenden.`
      : `Windows error code (HRESULT): ${value}. Use it together with the failed step for diagnosis.`;
  }
  return code && Object.hasOwn(reasons, code)
    ? reasons[code][locale === "de" ? 1 : 0]
    : locale === "de"
      ? "Die Voraussetzung für diesen Schritt ist nicht bestätigt. Aktualisiere den Abgleich und lasse den Auftrag prüfen."
      : "The prerequisite for this step is not verified. Refresh reconciliation and have the request reviewed.";
}
export function reconciliationApiError(
  status: number,
  payload: unknown,
  locale: Locale,
) {
  if (
    payload &&
    typeof payload === "object" &&
    "error" in payload &&
    payload.error &&
    typeof payload.error === "object" &&
    "code" in payload.error
  ) {
    const code = payload.error.code;
    if (
      typeof code === "string" &&
      code.startsWith("security_gpo_reconciliation_")
    ) {
      const reason = code.slice("security_gpo_reconciliation_".length);
      const mapped =
        reason === "observation_changed"
          ? "observation_stale"
          : reason === "limit"
            ? "reconciliation_limit"
            : reason;
      if (Object.hasOwn(reasons, mapped))
        return reconciliationReason(mapped, locale);
    }
  }
  return gpoApiError(status, payload, locale);
}
