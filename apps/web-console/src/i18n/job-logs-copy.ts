/**
 * File Name: job-logs-copy.ts
 * Version: v0.1.1 | Created: 2026-09-14 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Localize tenant job histories, filters, exports and log navigation.
 */

import type { Locale } from "./config";

const en = {
  navigation: "Logs",

  agents: "Agents",

  baselines: "Baselines",

  bmcCommunication: "BMC communication",

  bmcEvents: "BMC events",

  agentsTitle: "Agent logs",

  baselinesTitle: "Baseline logs",

  description:
    "Review requests, progress and results for this tenant. Times are shown in UTC.",

  historyHint:
    "History includes baselines that are currently hidden. Only operations permitted for your account are shown.",

  filters: "Filter logs",

  search: "Search",

  searchPlaceholder: "System, target, result code or requester",

  kind: "Operation type",

  status: "Status",

  all: "All",

  from: "From (UTC)",

  to: "To (UTC)",

  dateHint:
    "Use YYYY-MM-DD or an ISO timestamp with a time zone. The end date includes the whole day.",

  baseline: "Baseline ID",

  domain: "Domain",

  agent: "Agent enrollment ID",

  pageSize: "Rows per page",

  apply: "Apply filters",

  clear: "Clear filters",

  requested: "Requested (UTC)",

  started: "Started (UTC)",

  completed: "Completed (UTC)",

  system: "System",

  target: "Target",

  action: "Action",

  result: "Result code",

  requestedBy: "Requested by",

  empty: "No log entries match these filters.",

  unavailable: "The log history could not be loaded. Reload to try again.",

  invalid:
    "Some filters are invalid. Check dates, IDs and filter values, or clear the filters.",

  forbidden: "Your account does not have permission to view these logs.",

  total: "{count} entries",

  page: "Page {page} of {pages}",

  pagination: "Log pages",

  previous: "Previous page",

  next: "Next page",

  sortAscending: "Sort {column} ascending",

  sortDescending: "Sort {column} descending",

  exportCsv: "Export CSV",

  exporting: "Exporting…",

  exportHint: "Exports every matching entry, up to 10,000 rows.",

  exportError: "The export could not be downloaded. Try again.",

  exportLimit:
    "More than 10,000 entries match. Narrow the filters and export again.",

  sessionExpired: "Your session has expired. Sign in again.",

  gpoDetails: "GPO request details",

  openDetails: "View GPO request details",

  closeDetails: "Close details",

  detailUnavailable:
    "This GPO request is unavailable for the selected tenant or your account.",

  detailLoadFailed:
    "The GPO request details could not be loaded or validated. Reload the page; if this persists, check Portal and Agent versions and the server logs.",

  requestId: "Request ID",

  componentId: "Component backup ID",

  noApproval: "No local approval document is available for this request.",

  kinds: {
    agent_lifecycle: "Agent maintenance",

    agent_deployment: "Agent deployment",

    baseline_scan: "Baseline scan",

    gpo_import: "GPO request",

    hyperv_power: "Hyper-V power action",

    hyperv_management: "Hyper-V management",
  },

  statuses: {
    queued: "Queued",

    delivered: "Delivered",

    running: "Running",

    succeeded: "Succeeded",

    failed: "Failed",

    cancelled: "Cancelled",

    completed: "Completed",

    expired: "Expired",

    awaiting_approval: "Awaiting approval",

    staged: "Prepared, not applied",

    inspected: "AD state inspected",

    linked: "Linked, inactive",

    activated: "Activated",

    deactivated: "Deactivated",

    reconciled: "Directory reconciled; import not confirmed",

    blocked: "Blocked",

    reconciliation_required: "Directory reconciliation required",

    requires_reconciliation: "Reconciliation required",
  },
};

export type JobLogsCopy = typeof en;

const de: JobLogsCopy = {
  navigation: "Logs",

  agents: "Agents",

  baselines: "Baselines",

  bmcCommunication: "BMC-Kommunikation",

  bmcEvents: "BMC-Ereignisse",

  agentsTitle: "Agent-Protokolle",

  baselinesTitle: "Baseline-Protokolle",

  description:
    "Aufträge, Fortschritt und Ergebnisse dieses Mandanten. Alle Zeiten werden in UTC angezeigt.",

  historyHint:
    "Der Verlauf enthält auch derzeit ausgeblendete Baselines. Es werden nur Vorgänge angezeigt, für die dein Konto berechtigt ist.",

  filters: "Protokolle filtern",

  search: "Suche",

  searchPlaceholder: "System, Ziel, Ergebniscode oder Auftraggeber",

  kind: "Vorgangsart",

  status: "Status",

  all: "Alle",

  from: "Von (UTC)",

  to: "Bis (UTC)",

  dateHint:
    "YYYY-MM-DD oder einen ISO-Zeitstempel mit Zeitzone verwenden. Das Enddatum schließt den ganzen Tag ein.",

  baseline: "Baseline-ID",

  domain: "Domäne",

  agent: "Agent-Registrierungs-ID",

  pageSize: "Zeilen pro Seite",

  apply: "Filter anwenden",

  clear: "Filter zurücksetzen",

  requested: "Angefordert (UTC)",

  started: "Gestartet (UTC)",

  completed: "Abgeschlossen (UTC)",

  system: "System",

  target: "Ziel",

  action: "Aktion",

  result: "Ergebniscode",

  requestedBy: "Auftraggeber",

  empty: "Keine Protokolleinträge entsprechen diesen Filtern.",

  unavailable:
    "Der Verlauf konnte nicht geladen werden. Lade die Seite erneut.",

  invalid:
    "Einige Filter sind ungültig. Prüfe Datum, IDs und Filterwerte oder setze die Filter zurück.",

  forbidden: "Dein Konto hat keine Berechtigung für diese Protokolle.",

  total: "{count} Einträge",

  page: "Seite {page} von {pages}",

  pagination: "Protokollseiten",

  previous: "Vorherige Seite",

  next: "Nächste Seite",

  sortAscending: "{column} aufsteigend sortieren",

  sortDescending: "{column} absteigend sortieren",

  exportCsv: "CSV exportieren",

  exporting: "Export läuft…",

  exportHint: "Exportiert alle passenden Einträge, maximal 10.000 Zeilen.",

  exportError:
    "Der Export konnte nicht heruntergeladen werden. Versuche es erneut.",

  exportLimit:
    "Mehr als 10.000 Einträge gefunden. Grenze die Filter ein und exportiere erneut.",

  sessionExpired: "Deine Sitzung ist abgelaufen. Melde dich erneut an.",

  gpoDetails: "Details zum GPO-Auftrag",

  openDetails: "Details zum GPO-Auftrag anzeigen",

  closeDetails: "Details schließen",

  detailUnavailable:
    "Dieser GPO-Auftrag ist für den gewählten Mandanten oder dein Konto nicht verfügbar.",

  detailLoadFailed:
    "Die Details des GPO-Auftrags konnten nicht geladen oder geprüft werden. Lade die Seite erneut; prüfe bei anhaltendem Fehler Portal- und Agent-Version sowie die Server-Logs.",

  requestId: "Auftrags-ID",

  componentId: "Komponenten-Backup-ID",

  noApproval: "Für diesen Auftrag ist kein lokales Freigabedokument verfügbar.",

  kinds: {
    agent_lifecycle: "Agent-Wartung",

    agent_deployment: "Agent-Bereitstellung",

    baseline_scan: "Baseline-Scan",

    gpo_import: "GPO-Auftrag",

    hyperv_power: "Hyper-V-Energieaktion",

    hyperv_management: "Hyper-V-Verwaltung",
  },

  statuses: {
    queued: "In Warteschlange",

    delivered: "Zugestellt",

    running: "Läuft",

    succeeded: "Erfolgreich",

    failed: "Fehlgeschlagen",

    cancelled: "Abgebrochen",

    completed: "Abgeschlossen",

    expired: "Abgelaufen",

    awaiting_approval: "Wartet auf Freigabe",

    staged: "Vorbereitet, nicht angewendet",

    inspected: "AD-Zustand geprüft",

    linked: "Verknüpft, inaktiv",

    activated: "Aktiviert",

    deactivated: "Deaktiviert",

    reconciled: "Verzeichnis abgeglichen; Import nicht bestätigt",

    blocked: "Blockiert",

    reconciliation_required: "Verzeichnisabgleich erforderlich",

    requires_reconciliation: "Abgleich erforderlich",
  },
};

export function getJobLogsCopy(locale: Locale): JobLogsCopy {
  return locale === "de" ? de : en;
}

export function logStatusLabel(status: string, copy: JobLogsCopy): string {
  return Object.hasOwn(copy.statuses, status)
    ? copy.statuses[status as keyof typeof copy.statuses]
    : status;
}
