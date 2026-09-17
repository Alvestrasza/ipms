/**
 * File Name: gpo-error-copy.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Translate allowlisted GPO failure codes into safe causes and recovery steps.
 */

import type { Locale } from "./config";

const messages = {
  busy: [
    "Another GPO request is pending for this domain. Open Baseline Logs and complete or resolve that request before starting another.",

    "Für diese Domäne ist bereits ein GPO-Auftrag offen. Öffne die Baseline-Logs und schließe oder kläre diesen Auftrag, bevor du einen weiteren startest.",
  ],

  limit: [
    "This tenant has reached its total GPO request limit. Have an administrator review the request inventory and retention policy before creating more requests.",

    "Dieser Tenant hat das Gesamtlimit für GPO-Aufträge erreicht. Lasse einen Administrator den Auftragsbestand und die Aufbewahrungsregeln prüfen, bevor weitere Aufträge erstellt werden.",
  ],

  executor: [
    "No eligible domain controller Agent is available for this action. Check its connection, domain assignment, GPMC readiness and Agent version; import and link requires 0.2.36, other managed actions require 0.2.35.",

    "Für diese Aktion ist kein geeigneter Domain-Controller-Agent verfügbar. Prüfe Verbindung, Domänenzuordnung, GPMC-Bereitschaft und Agent-Version; Import und Verknüpfung benötigen 0.2.36, andere verwaltete Aktionen 0.2.35.",
  ],

  artifact: [
    "The verified baseline package is unavailable or invalid. Have an administrator check the availability and integrity of this baseline package on the Appliance before creating a new request.",

    "Das geprüfte Baseline-Paket fehlt oder ist ungültig. Lasse einen Administrator die Verfügbarkeit und Integrität dieses Baseline-Pakets auf der Appliance prüfen, bevor du einen neuen Auftrag erstellst.",
  ],

  exists: [
    "IPMS already manages this GPO identity. Refresh and select the existing managed GPO instead of creating it again.",

    "IPMS verwaltet diese GPO-Identität bereits. Aktualisiere die Ansicht und wähle die vorhandene verwaltete GPO aus, statt sie erneut anzulegen.",
  ],

  collision: [
    "The requested GPO name is already occupied. Check the existing GPO and the configured naming scheme, then inspect again with a unique name.",

    "Der gewünschte GPO-Name ist bereits belegt. Prüfe die vorhandene GPO und das konfigurierte Namensschema und starte anschließend eine neue Prüfung mit einem eindeutigen Namen.",
  ],

  conflict: [
    "This request ID is already bound to different content. Refresh and reconcile the existing request in Baseline Logs before creating a new request.",

    "Diese Auftrags-ID ist bereits an einen anderen Inhalt gebunden. Aktualisiere die Ansicht und gleiche den bestehenden Auftrag in den Baseline-Logs ab, bevor du einen neuen erstellst.",
  ],

  revision: [
    "The domain configuration changed after this form was loaded. Refresh, review the current targets and settings, then create the request again.",

    "Die Domänenkonfiguration wurde seit dem Laden geändert. Aktualisiere die Ansicht, prüfe die aktuellen Ziele und Einstellungen und erstelle den Auftrag erneut.",
  ],

  root: [
    "This GPO action requires explicit confirmation of the domain root and Tier 0 authorization. Select Tier 0 and confirm the displayed domain root before creating the request.",

    "Diese GPO-Aktion benötigt eine ausdrückliche Bestätigung der Domänenwurzel und Tier-0-Berechtigung. Wähle Tier 0 und bestätige die angezeigte Domänenwurzel vor dem Erstellen des Auftrags.",
  ],

  inspection: [
    "A successful, current AD inspection is required. Create the request again to run a new read-only inspection before any change can be approved.",

    "Eine erfolgreiche, aktuelle AD-Prüfung ist erforderlich. Erstelle den Auftrag erneut, damit vor einer Änderungsfreigabe eine neue lesende Prüfung läuft.",
  ],

  state: [
    "AD state changed since inspection. Review the current GPO and target links, then create a new request with a fresh inspection.",

    "Der AD-Zustand hat sich seit der Prüfung geändert. Prüfe die aktuelle GPO und ihre Zielverknüpfungen und erstelle einen neuen Auftrag mit aktueller Prüfung.",
  ],

  content: [
    "The prepared GPO version changed. Refresh, review the desired version and create a new request against that prepared content.",

    "Die vorbereitete GPO-Version hat sich geändert. Aktualisiere die Ansicht, prüfe die gewünschte Version und erstelle einen neuen Auftrag für diesen vorbereiteten Inhalt.",
  ],

  reconciliation: [
    "A previous GPO request needs reconciliation; changes may already have occurred. Open its Baseline Logs, check the GPO GUID there and compare the actual GPO content and links with the approved request. Clarify the result before creating another change; do not bypass the domain lock.",

    "Ein vorheriger GPO-Auftrag benötigt einen Abgleich; Änderungen könnten bereits erfolgt sein. Öffne seine Baseline-Logs, prüfe dort die GPO-GUID und gleiche den tatsächlichen GPO-Inhalt sowie die Verknüpfungen mit dem freigegebenen Auftrag ab. Kläre das Ergebnis vor einer weiteren Änderung; umgehe die Domänensperre nicht.",
  ],

  unmanaged: [
    "The target is not a verified IPMS-managed GPO. Refresh and select a managed GPO or a supported existing IPMS import; default policies cannot be adopted.",

    "Das Ziel ist keine bestätigte, von IPMS verwaltete GPO. Aktualisiere die Ansicht und wähle eine verwaltete GPO oder einen unterstützten vorhandenen IPMS-Import; Standardrichtlinien können nicht übernommen werden.",
  ],

  links: [
    "The target links or their order conflict with the approved configuration. Review the tier OUs or domain-root target and baseline order, then run a new inspection.",

    "Zielverknüpfungen oder ihre Reihenfolge widersprechen der freizugebenden Konfiguration. Prüfe Tier-OUs beziehungsweise Domänenwurzel und Baseline-Reihenfolge und starte eine neue Prüfung.",
  ],

  authentication: [
    "Your session is no longer authenticated. Sign in again, return to this tenant and review existing requests before retrying.",

    "Deine Sitzung ist nicht mehr angemeldet. Melde dich erneut an, wähle diesen Tenant und prüfe bestehende Aufträge vor einem neuen Versuch.",
  ],

  forbidden: [
    "The request was not authorized. Refresh your session; if access is still denied, have an administrator check your tenant and explicit domain/tier permissions. An expired session or CSRF check can also cause this response.",

    "Der Auftrag wurde nicht autorisiert. Aktualisiere deine Sitzung; bleibt der Zugriff verweigert, lasse Tenant- und ausdrückliche Domänen-/Tier-Berechtigungen prüfen. Auch eine abgelaufene Sitzung oder CSRF-Prüfung kann diese Antwort verursachen.",
  ],

  missing: [
    "The selected domain or request is no longer available in this tenant. Refresh and select an accessible domain or request.",

    "Die gewählte Domäne oder der Auftrag ist in diesem Tenant nicht mehr verfügbar. Aktualisiere die Ansicht und wähle eine zugängliche Domäne oder einen Auftrag.",
  ],

  invalid: [
    "The request contains unsupported or incomplete values. Check the selected GPO, tier, target alias, version and required confirmations, then retry.",

    "Der Auftrag enthält unvollständige oder nicht unterstützte Werte. Prüfe GPO, Tier, Zielkürzel, Version und erforderliche Bestätigungen und versuche es erneut.",
  ],

  rate: [
    "Too many requests were sent. Wait briefly, refresh existing requests and then retry the intended action once.",

    "Es wurden zu viele Anfragen gesendet. Warte kurz, aktualisiere bestehende Aufträge und versuche die gewünschte Aktion anschließend einmal erneut.",
  ],

  fallback: [
    "IPMS could not accept this request. Refresh the page and check the selected settings and existing Baseline Logs; if it persists, ask an administrator to investigate the Portal response.",

    "IPMS konnte diesen Auftrag nicht annehmen. Aktualisiere die Seite und prüfe die gewählten Einstellungen und vorhandenen Baseline-Logs; bleibt der Fehler bestehen, lasse die Portal-Antwort durch einen Administrator prüfen.",
  ],

  agentPermission: [
    "The Agent could not access the required AD objects. Check the configured service account and its delegated rights for this domain and target; Portal approval alone does not grant AD permissions.",

    "Der Agent konnte auf benötigte AD-Objekte nicht zugreifen. Prüfe den konfigurierten Service Account und seine delegierten Rechte für Domäne und Ziel; eine Portal-Freigabe vergibt keine AD-Berechtigungen.",
  ],

  identity: [
    "The Agent could not verify the domain or GPO identity. Check domain membership, DNS and AD connectivity, then refresh the Agent report and inspect again.",

    "Der Agent konnte die Domänen- oder GPO-Identität nicht bestätigen. Prüfe Domänenmitgliedschaft, DNS und AD-Erreichbarkeit, aktualisiere den Agent-Bericht und starte die Prüfung erneut.",
  ],

  dc: [
    "The selected Agent is not a writable domain controller. Select a writable DC in the target domain and refresh its Agent report.",

    "Der ausgewählte Agent ist kein beschreibbarer Domain Controller. Wähle einen beschreibbaren DC der Zieldomäne und aktualisiere seinen Agent-Bericht.",
  ],

  gpmc: [
    "The Agent cannot access the Group Policy Management interfaces. Check that GPMC is installed and available to the Agent service account, then inspect again.",

    "Der Agent kann die Gruppenrichtlinienverwaltung nicht verwenden. Prüfe, ob GPMC installiert und für den Agent-Service-Account verfügbar ist, und starte die Prüfung erneut.",
  ],

  provider: [
    "The Agent could not complete the AD inspection or GPO operation. Open this request in Logs and check AD connectivity, GPMC and the Agent service account before retrying.",

    "Der Agent konnte die AD-Prüfung oder GPO-Aktion nicht abschließen. Öffne diesen Auftrag in den Logs und prüfe AD-Erreichbarkeit, GPMC und den Agent-Service-Account vor einem neuen Versuch.",
  ],

  timeout: [
    "The Agent worker timed out or stopped. Check the Agent service and AD connectivity, then review this request in Logs before retrying.",

    "Der Agent-Arbeitsprozess wurde beendet oder hat das Zeitlimit erreicht. Prüfe Agent-Dienst und AD-Erreichbarkeit und kontrolliere diesen Auftrag in den Logs vor einem neuen Versuch.",
  ],

  disabled: [
    "This action requires a disabled GPO. Review its current state and use a separately approved deactivation before changing its links.",

    "Diese Aktion benötigt eine deaktivierte GPO. Prüfe ihren aktuellen Zustand und verwende vor Linkänderungen eine separat freigegebene Deaktivierung.",
  ],

  backup: [
    "The Agent could not create the protected GPO backup. Check the backup location, permissions and available space before approving another activation.",

    "Der Agent konnte die geschützte GPO-Sicherung nicht erstellen. Prüfe Sicherungspfad, Berechtigungen und freien Speicher vor einer weiteren Aktivierungsfreigabe.",
  ],

  approval: [
    "The Agent could not verify authorization for this exact request. Review its current approval, expiry and Agent enrollment in Logs; use a new Portal-approved request when required.",

    "Der Agent konnte die Freigabe für genau diesen Auftrag nicht bestätigen. Prüfe Freigabe, Ablauf und Agent-Registrierung in den Logs; erstelle bei Bedarf einen neuen, im Portal freigegebenen Auftrag.",
  ],

  unsupported: [
    "The Agent does not support this GPO component or request. Check the selected component and the required Agent version, then prepare a supported request.",

    "Der Agent unterstützt diese GPO-Komponente oder diesen Auftrag nicht. Prüfe die gewählte Komponente und benötigte Agent-Version und bereite einen unterstützten Auftrag vor.",
  ],

  preflight_inventory: [
    "The forest domain inventory could not be read. Check forest discovery and the Agent service account access, then run a new inspection.",

    "Das Domänenverzeichnis des Forests konnte nicht gelesen werden. Prüfe Forest-Erkennung und Zugriff des Agent-Service-Accounts und starte eine neue Prüfung.",
  ],

  preflight_controller: [
    "A domain controller for the forest link check could not be located. Check DNS, domain controller discovery and connectivity for every forest domain.",

    "Für die forestweite Linkprüfung konnte ein Domain Controller nicht ermittelt werden. Prüfe DNS, DC-Erkennung und Erreichbarkeit für jede Forest-Domäne.",
  ],

  preflight_directory: [
    "The directory connection for the forest link check failed. Check LDAP connectivity and the Agent service identity before retrying.",

    "Die Verzeichnisverbindung für die forestweite Linkprüfung ist fehlgeschlagen. Prüfe LDAP-Erreichbarkeit und Dienstidentität des Agents vor einem neuen Versuch.",
  ],

  preflight_domain_visibility: [
    "The Agent could not verify access to every forest domain root. Check domain visibility and directory read access for its service account.",

    "Der Agent konnte den Zugriff auf die Wurzeln aller Forest-Domänen nicht bestätigen. Prüfe Domänensichtbarkeit und lesenden Verzeichniszugriff des Service-Accounts.",
  ],

  preflight_domain_search: [
    "The forest domain link search did not complete. Check directory connectivity and read access, then repeat the inspection.",

    "Die Suche nach Verknüpfungen in den Forest-Domänen wurde nicht abgeschlossen. Prüfe Verzeichnisverbindung und Lesezugriff und wiederhole die Prüfung.",
  ],

  preflight_site_visibility: [
    "The Agent could not verify access to the forest Sites container. Check visibility and read access to the Configuration partition.",

    "Der Agent konnte den Zugriff auf den Sites-Container des Forests nicht bestätigen. Prüfe Sichtbarkeit und Lesezugriff auf die Configuration-Partition.",
  ],

  preflight_site_search: [
    "The forest site link search did not complete. Check connectivity and read access to the Configuration partition, then repeat the inspection.",

    "Die Suche nach Standortverknüpfungen wurde nicht abgeschlossen. Prüfe Verbindung und Lesezugriff auf die Configuration-Partition und wiederhole die Prüfung.",
  ],

  preflight_census_mismatch: [
    "GPMC and LDAP returned different GPO link inventories. Check current domain, OU and site links and replication, then inspect again. Changes remain blocked until the inventories agree.",

    "GPMC und LDAP liefern unterschiedliche GPO-Verknüpfungen. Prüfe aktuelle Domänen-, OU- und Standortverknüpfungen sowie die Replikation und starte eine neue Prüfung. Änderungen bleiben bis zur Übereinstimmung blockiert.",
  ],

  preflight_domain_open: [
    "GPMC could not open a forest domain for the link check. Check domain controller discovery, connectivity and GPMC access for the Agent service account.",
    "GPMC konnte eine Forest-Domäne für die Linkprüfung nicht öffnen. Prüfe DC-Erkennung, Verbindung und GPMC-Zugriff des Agent-Service-Accounts.",
  ],
  preflight_domain_identity: [
    "GPMC returned a domain or controller identity that differs from the requested target. Check DNS, domain controller discovery and the configured domain before retrying.",
    "GPMC hat eine abweichende Domänen- oder Controller-Identität geliefert. Prüfe DNS, DC-Erkennung und die konfigurierte Domäne vor einem neuen Versuch.",
  ],
  preflight_domain_query: [
    "GPMC could not search the domain for GPO links. Check domain connectivity and directory read access, then repeat the inspection.",
    "GPMC konnte die Domäne nicht nach GPO-Verknüpfungen durchsuchen. Prüfe Domänenverbindung und lesenden Verzeichniszugriff und wiederhole die Prüfung.",
  ],
  preflight_domain_links: [
    "GPMC could not enumerate the returned domain or OU links. Check the target links, directory connectivity and read access, then inspect again.",
    "GPMC konnte die ermittelten Domänen- oder OU-Verknüpfungen nicht auslesen. Prüfe die Zielverknüpfungen, Verzeichnisverbindung und Lesezugriff und starte eine neue Prüfung.",
  ],
  preflight_domain_merge: [
    "The GPO link inventory contains duplicate target identities or exceeds the supported limit. Review domain and OU link targets and their count before another request; changes remain blocked.",
    "Das GPO-Linkverzeichnis enthält doppelte Zielidentitäten oder überschreitet das unterstützte Limit. Prüfe Domänen- und OU-Ziele sowie deren Anzahl vor einem neuen Auftrag; Änderungen bleiben blockiert.",
  ],
  agentUnknown: [
    "The Agent did not complete this request successfully. Open its Logs and review the recorded result before creating another change.",

    "Der Agent hat diesen Auftrag nicht erfolgreich abgeschlossen. Öffne seine Logs und prüfe das protokollierte Ergebnis, bevor du eine weitere Änderung erstellst.",
  ],
} as const;

type Message = keyof typeof messages;

const apiCodes: Record<string, Message> = {
  security_gpo_domain_busy: "busy",

  security_gpo_job_limit: "limit",

  security_gpo_executor_unavailable: "executor",

  security_gpo_artifact_unavailable: "artifact",

  security_gpo_managed_exists: "exists",

  security_gpo_pilot_exists: "exists",

  security_gpo_name_collision: "collision",

  security_gpo_request_conflict: "conflict",

  security_domain_revision_changed: "revision",

  security_gpo_domain_root_confirmation_required: "root",

  security_override_revision_changed: "content",
  security_override_disabled: "content",
  security_override_empty: "content",
  security_gpo_preflight_required: "inspection",

  security_gpo_state_changed: "state",

  security_gpo_prepared_content_changed: "content",

  security_gpo_reconciliation_required: "reconciliation",

  security_gpo_unmanaged_target: "unmanaged",

  security_gpo_link_conflict: "links",

  authentication_failed: "authentication",

  forbidden: "forbidden",

  not_found: "missing",

  invalid_request: "invalid",

  rate_limited: "rate",
};

const agentCodes: Record<string, Message> = {
  gpo_local_approval_required: "approval",

  gpo_job_expired: "inspection",

  gpo_invalid_job: "unsupported",

  gpo_unsupported_component: "unsupported",

  gpo_identity_mismatch: "identity",

  gpo_not_writable_dc: "dc",

  gpo_domain_identity_unavailable: "identity",

  gpmc_unavailable: "gpmc",

  gpo_permission_denied: "agentPermission",

  gpo_name_collision: "collision",

  gpo_source_mismatch: "artifact",

  gpo_artifact_invalid: "artifact",

  gpo_local_approval_invalid: "approval",

  gpo_reconciliation_required: "reconciliation",

  gpo_provider_failed: "provider",

  gpo_verification_failed: "reconciliation",

  gpo_worker_timeout: "timeout",

  gpo_worker_failed: "timeout",

  gpo_journal_invalid: "reconciliation",

  gpo_claim_uncertain: "reconciliation",

  gpo_authority_expired: "approval",

  gpo_enrollment_changed: "approval",

  gpo_portal_approval_invalid: "approval",

  gpo_portal_approval_required: "approval",

  gpo_state_changed: "state",

  gpo_requires_disabled: "disabled",

  gpo_unmanaged_target: "unmanaged",

  gpo_target_invalid: "links",

  gpo_link_conflict: "links",

  gpo_backup_failed: "backup",

  gpo_preflight_inventory_failed: "preflight_inventory",

  gpo_preflight_controller_failed: "preflight_controller",

  gpo_preflight_directory_failed: "preflight_directory",

  gpo_preflight_domain_visibility_failed: "preflight_domain_visibility",

  gpo_preflight_domain_search_failed: "preflight_domain_search",

  gpo_preflight_site_visibility_failed: "preflight_site_visibility",

  gpo_preflight_site_search_failed: "preflight_site_search",

  gpo_preflight_census_mismatch: "preflight_census_mismatch",

  gpo_preflight_domain_open_failed: "preflight_domain_open",
  gpo_preflight_domain_identity_failed: "preflight_domain_identity",
  gpo_preflight_domain_query_failed: "preflight_domain_query",
  gpo_preflight_domain_links_failed: "preflight_domain_links",
  gpo_preflight_domain_merge_failed: "preflight_domain_merge",
  gpo_preflight_required: "inspection",
};

const translated = (key: Message, locale: Locale) =>
  messages[key][locale === "de" ? 1 : 0];

export function gpoApiErrorCode(payload: unknown): string | null {
  let code: unknown;

  if (payload && typeof payload === "object" && "error" in payload) {
    const error = payload.error;

    if (error && typeof error === "object" && "code" in error)
      code = error.code;
  }

  return typeof code === "string" && Object.hasOwn(apiCodes, code)
    ? code
    : null;
}

export function gpoApiError(
  status: number,

  payload: unknown,

  locale: Locale,

  reconciliation = false,
): string {
  const code = gpoApiErrorCode(payload);

  // Authentication responses do not establish whether a session or a domain grant failed.

  const key =
    status === 401
      ? "authentication"
      : status === 403
        ? "forbidden"
        : code === "security_gpo_domain_busy" && reconciliation
          ? "reconciliation"
          : typeof code === "string" && Object.hasOwn(apiCodes, code)
            ? apiCodes[code]
            : status === 400
              ? "invalid"
              : status === 404
                ? "missing"
                : status === 429
                  ? "rate"
                  : "fallback";

  return translated(key, locale);
}

export function gpoAgentError(code: unknown, locale: Locale): string {
  return translated(
    typeof code === "string" && Object.hasOwn(agentCodes, code)
      ? agentCodes[code]
      : "agentUnknown",

    locale,
  );
}
