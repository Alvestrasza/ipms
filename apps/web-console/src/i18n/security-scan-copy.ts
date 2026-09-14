/**
 * File Name: security-scan-copy.ts
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Explain native read-only scans, queue state and limited evidence in EN/DE.
 */
import type { Locale } from "./config";

const en = {
  title: "Read-only Agent assessment",
  readOnly: "Read-only assessment",
  boundary:
    "The Agent reads machine settings without changing policies. User settings, domain settings and unreadable values remain unknown. Partial findings do not establish full baseline compliance.",
  requirement:
    "Available enrolled Windows Agents require version 0.2.31 or later.",
  target: "Scan target",
  allSystems: "All matching systems",
  pageSystems: "Individual systems on this inventory page",
  limit:
    "A request can include up to 250 systems. For a larger scope, select an individual system from the current inventory page.",
  queueFull:
    "The tenant scan queue is full. Refresh the job status and wait for active jobs to finish before trying again.",
  queue: "Request read-only scan",
  queuing: "Requesting…",
  queued: "Newly queued",
  existing: "Already active",
  unavailableAgents: "Unavailable Agents",
  unavailableHint:
    "These systems were not queued because their Agent is offline, unavailable or too old. Update or reconnect the Agent before trying again.",
  receipt: "Scan request received",
  requestFailed:
    "The scan request could not be confirmed. Refresh the job status before trying again.",
  jobs: "Recent scan jobs",
  recent:
    "The latest 25 jobs are shown. Completion describes the scan job, not baseline compliance.",
  refresh: "Refresh job status",
  refreshing: "Refreshing…",
  loadResults: "Load latest results",
  active: "Active jobs",
  noJobs: "No scan jobs have been requested for this baseline.",
  statusUnavailable:
    "The job status could not be loaded. Refresh to try again.",
  paused:
    "Automatic refresh paused after five minutes. Refresh the job status to continue.",
  polling:
    "Active jobs refresh every five seconds while this page is visible, for up to five minutes.",
  permission:
    "Your tenant role does not permit scans. Reload the page to check your access.",
  sessionExpired: "Your session has expired. Sign in again.",
  invalid:
    "The scan target was rejected. Select an available matching system or reload the page.",
  missing:
    "This baseline or system is no longer available. Reload the overview.",
  requested: "Requested (UTC)",
  completed: "Completed (UTC)",
  statuses: {
    queued: "Queued",
    running: "Running",
    completed: "Completed",
    failed: "Failed",
    expired: "Expired",
  },
  findings: "Control findings",
  openFindings: "View findings",
  back: "Back to baseline",
  noAssessment: "No assessment is available for this system.",
  findingsUnavailable:
    "The control findings could not be loaded. Reload to try again.",
  scopeVerified: "Assessment scope verified",
  scopePartial: "Assessment scope incomplete",
  noFindings: "The latest attempt contains no control findings.",
  scopeHint:
    "This view shows the latest attempt, including incomplete or failed attempts. Passed machine checks alone do not prove the entire baseline is met.",
  total: "Total controls",
  passed: "Passed",
  failed: "Failed",
  unknown: "Unknown",
  control: "Control",
  scope: "Scope",
  result: "Result",
  expected: "Expected",
  observed: "Observed",
  reason: "Reason",
  assessment: "Assessment ID",
  systemId: "System ID",
  scopes: { machine: "Machine", user: "User", domain: "Domain" },
  findingReasons: {
    matched: "Matches the expected value",
    different: "Differs from the expected value",
    missing: "Value is missing; compliance remains unknown",
    unsupported: "This setting cannot yet be assessed",
    scope_unverified: "The required scope could not be verified",
    access_denied: "Access denied",
    invalid_value: "The observed value has an unexpected type",
    error: "The setting could not be read",
    limit: "The read limit was reached",
  },
  jobErrors: {
    collection_failed: "The Agent could not complete the assessment",
    unsupported_manifest: "The Agent does not support this baseline revision",
    cancelled: "The assessment was cancelled",
    scope_changed: "The system or authorized scope changed",
    attempt_limit: "The retry limit was reached",
    expired: "The scan request expired",
  },
};
export type SecurityScanCopy = typeof en;
const de: SecurityScanCopy = {
  title: "Lesende Agent-Prüfung",
  readOnly: "Lesende Prüfung",
  boundary:
    "Der Agent liest Computereinstellungen und ändert keine Richtlinien. Benutzereinstellungen, Domäneneinstellungen und nicht lesbare Werte bleiben unbekannt. Teilergebnisse belegen keine vollständige Baseline-Erfüllung.",
  requirement:
    "Verfügbare, registrierte Windows Agents benötigen Version 0.2.31 oder neuer.",
  target: "Prüfziel",
  allSystems: "Alle passenden Systeme",
  pageSystems: "Einzelne Systeme auf dieser Inventarseite",
  limit:
    "Ein Auftrag kann bis zu 250 Systeme umfassen. Wähle bei größerem Umfang ein einzelnes System auf der aktuellen Inventarseite aus.",
  queueFull:
    "Die Prüfwarteschlange des Mandanten ist voll. Aktualisiere den Auftragsstatus und warte vor einem weiteren Versuch auf den Abschluss aktiver Aufträge.",
  queue: "Lesende Prüfung anfordern",
  queuing: "Wird angefordert…",
  queued: "Neu eingereiht",
  existing: "Bereits aktiv",
  unavailableAgents: "Nicht verfügbare Agents",
  unavailableHint:
    "Diese Systeme wurden nicht eingereiht, weil ihr Agent offline, nicht verfügbar oder zu alt ist. Aktualisiere oder verbinde den Agent vor einem weiteren Versuch.",
  receipt: "Prüfauftrag angenommen",
  requestFailed:
    "Der Prüfauftrag konnte nicht bestätigt werden. Aktualisiere vor einem weiteren Versuch den Auftragsstatus.",
  jobs: "Letzte Prüfaufträge",
  recent:
    "Angezeigt werden die letzten 25 Aufträge. Abgeschlossen bezeichnet den Prüfauftrag, nicht die Erfüllung der Baseline.",
  refresh: "Auftragsstatus aktualisieren",
  refreshing: "Wird aktualisiert…",
  loadResults: "Aktuelle Ergebnisse laden",
  active: "Aktive Aufträge",
  noJobs: "Für diese Baseline wurden noch keine Prüfaufträge angefordert.",
  statusUnavailable:
    "Der Auftragsstatus konnte nicht geladen werden. Aktualisiere ihn erneut.",
  paused:
    "Die automatische Aktualisierung wurde nach fünf Minuten angehalten. Aktualisiere den Auftragsstatus, um fortzufahren.",
  polling:
    "Aktive Aufträge werden auf der sichtbaren Seite alle fünf Sekunden aktualisiert, höchstens fünf Minuten lang.",
  permission:
    "Deine Mandantenrolle erlaubt keine Prüfungen. Lade die Seite zur erneuten Zugriffsprüfung.",
  sessionExpired: "Deine Sitzung ist abgelaufen. Melde dich erneut an.",
  invalid:
    "Das Prüfziel wurde abgelehnt. Wähle ein verfügbares, passendes System oder lade die Seite erneut.",
  missing:
    "Diese Baseline oder dieses System ist nicht mehr verfügbar. Lade die Übersicht erneut.",
  requested: "Angefordert (UTC)",
  completed: "Abgeschlossen (UTC)",
  statuses: {
    queued: "Eingereiht",
    running: "Läuft",
    completed: "Abgeschlossen",
    failed: "Fehlgeschlagen",
    expired: "Abgelaufen",
  },
  findings: "Einzelne Prüfergebnisse",
  openFindings: "Prüfergebnisse anzeigen",
  back: "Zurück zur Baseline",
  noAssessment: "Für dieses System liegt noch keine Prüfung vor.",
  findingsUnavailable:
    "Die einzelnen Prüfergebnisse konnten nicht geladen werden. Lade die Seite erneut.",
  scopeVerified: "Prüfumfang bestätigt",
  scopePartial: "Prüfumfang unvollständig",
  noFindings: "Der letzte Versuch enthält keine einzelnen Prüfergebnisse.",
  scopeHint:
    "Diese Ansicht zeigt den letzten Versuch, auch wenn er unvollständig oder fehlgeschlagen ist. Erfüllte Computerprüfungen allein belegen nicht die Erfüllung der gesamten Baseline.",
  total: "Prüfpunkte gesamt",
  passed: "Erfüllt",
  failed: "Nicht erfüllt",
  unknown: "Unbekannt",
  control: "Prüfpunkt",
  scope: "Bereich",
  result: "Ergebnis",
  expected: "Erwartet",
  observed: "Ermittelt",
  reason: "Grund",
  assessment: "Prüfungs-ID",
  systemId: "System-ID",
  scopes: { machine: "Computer", user: "Benutzer", domain: "Domäne" },
  findingReasons: {
    matched: "Entspricht dem erwarteten Wert",
    different: "Weicht vom erwarteten Wert ab",
    missing: "Der Wert fehlt; die Erfüllung bleibt unbekannt",
    unsupported: "Diese Einstellung kann noch nicht geprüft werden",
    scope_unverified: "Der erforderliche Bereich konnte nicht bestätigt werden",
    access_denied: "Zugriff verweigert",
    invalid_value: "Der ermittelte Wert hat einen unerwarteten Typ",
    error: "Die Einstellung konnte nicht gelesen werden",
    limit: "Die Lesegrenze wurde erreicht",
  },
  jobErrors: {
    collection_failed: "Der Agent konnte die Prüfung nicht abschließen",
    unsupported_manifest: "Der Agent unterstützt diese Baseline-Revision nicht",
    cancelled: "Die Prüfung wurde abgebrochen",
    scope_changed:
      "Das System oder der berechtigte Prüfumfang hat sich geändert",
    attempt_limit: "Die Grenze für Wiederholungen wurde erreicht",
    expired: "Der Prüfauftrag ist abgelaufen",
  },
};
export function getSecurityScanCopy(locale: Locale): SecurityScanCopy {
  return locale === "de" ? de : en;
}
