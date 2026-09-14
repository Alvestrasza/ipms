/**
 * File Name: domain-security-copy.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Localize domain mapping, GPO names, baseline order and unlinked pilot imports.
 */
import type { Locale } from "./config";

const en = {
  navigation: "Domains & GPOs",
  title: "Domain security settings",
  eyebrow: "Tenant administration / Security",
  description:
    "Map existing OUs to security tiers, name GPOs and arrange baseline layers for each domain.",
  boundary:
    "Saving these settings records a plan. It does not create or move OUs, modify GPOs, or apply policy.",
  domains: "Configured domains",
  add: "Add domain",
  edit: "Edit domain",
  empty: "No domain settings have been saved for this tenant.",
  unavailable:
    "Domain security settings could not be loaded. Reload to try again.",
  reload: "Reload data",
  domain: "Domain DNS name",
  domainHint:
    "Use the complete DNS name. The domain identity cannot be changed after saving.",
  mappings: "Tier OU mappings",
  mappingHint:
    "Enter one existing OU distinguished name per line. Several OUs may belong to a tier. Leave a tier empty if it is not used here.",
  unverified: "Directory verification pending",
  verificationHint:
    "Saved OU paths have not been checked against Active Directory. No existing directory objects have been adopted or moved.",
  naming: "GPO naming",
  nameTemplate: "GPO naming template",
  tokens:
    "Use each field exactly once: {tier}, {scope}, {target}, {purpose}, {version}. Maximum 160 characters. Scope is C or U. A shared template produces separate GPOs for tiers 0, 1 and 2.",
  preview: "Name examples",
  exampleHint:
    "Draft examples use Computer, ALL, Baseline and version 1.0.0. Saved examples are validated by the server.",
  invalidPreview: "An example cannot be rendered with this template.",
  production: "Production",
  pilot: "Pilot",
  order: "Baseline composition order",
  orderHint:
    "Arrange layers from first to last. This is a proposed composition order, not AD link order. Saving the order does not apply policy or resolve conflicting settings.",
  providersHint:
    "Only available catalog entries are listed. CIS content can be added when a supported package is available.",
  moveUp: "Move up",
  moveDown: "Move down",
  drag: "Drag to reorder",
  moved: "{name} moved to position {position} of {total}.",
  revision: "Saved revision",
  save: "Save domain settings",
  saving: "Saving…",
  saved: "Domain settings saved. No directory policies were applied.",
  unsaved: "Unsaved changes",
  reset: "Discard changes",
  discardHint: "Save or discard the current changes before switching domains.",
  invalid:
    "The settings were rejected. Check the domain, OU paths and naming template.",
  conflict:
    "The saved settings changed in another session. Your draft is retained. Reload the saved version before making another change.",
  uncertain:
    "The result could not be confirmed. Your draft is retained. Reload the saved version before trying again.",
  permission: "Your current tenant permissions do not allow this action.",
  sessionExpired: "Your session has expired. Sign in again to continue.",
  importsTitle: "Unlinked pilot GPOs",
  importBoundary:
    "Prepare a separate pilot GPO on a domain controller. The Agent requires local approval for this exact job. The pilot remains unlinked with Computer and User settings disabled; this does not apply the baseline.",
  saveFirst: "Save the domain settings before requesting a pilot import.",
  importsUnavailable: "Pilot jobs and eligible Agents could not be loaded.",
  importsRefresh: "Refresh pilot jobs",
  executor: "Domain controller Agent",
  noExecutor: "No eligible Agent in this domain",
  executorHint:
    "The selected Agent must report the expected domain identity and permit this bounded operation locally.",
  baseline: "Baseline package",
  component: "GPO component",
  unavailableComponent: "Artifact unavailable",
  tier: "Target tier",
  target: "Target name token",
  version: "GPO version",
  importAction: "Request unlinked pilot import",
  requesting: "Requesting…",
  importReceived:
    "Pilot import request recorded. Local approval is required before the Agent can create the GPO.",
  importInvalid:
    "The pilot request was rejected. Check the saved domain revision, Agent and package selection.",
  importUncertain:
    "The request result is uncertain. Refresh pilot jobs before retrying. No new request will be created automatically.",
  noJobs: "No pilot imports have been requested for this domain.",
  jobs: "Pilot import jobs",
  status: "Status",
  agent: "Agent",
  requested: "Requested (UTC)",
  approval: "Local approval document",
  approvalHint:
    "An authorized administrator must verify and approve this exact job through the protected local Agent configuration. Showing this document does not approve or execute it.",
  copyApproval: "Copy approval document",
  copied: "Approval document copied.",
  copyFailed:
    "The document could not be copied. Select and copy its contents manually.",
  staged:
    "Unlinked; Computer and User settings disabled. Policy has not been applied.",
  errorCode: "Result code",
  states: {
    queued: "Queued",
    awaiting_approval: "Awaiting local approval",
    running: "Running",
    staged: "Prepared, not applied",
    blocked: "Blocked",
    failed: "Failed",
    expired: "Expired",
    reconciliation_required: "Directory reconciliation required",
  },
};

export type DomainSecurityCopy = typeof en;
const de: DomainSecurityCopy = {
  navigation: "Domänen & GPOs",
  title: "Domänen-Sicherheitseinstellungen",
  eyebrow: "Tenant-Administration / Security",
  description:
    "Vorhandene OUs den Sicherheits-Tiers zuordnen, GPOs benennen und Baselines je Domäne anordnen.",
  boundary:
    "Das Speichern hält die Planung fest. Es erstellt oder verschiebt keine OUs, ändert keine GPOs und wendet keine Richtlinien an.",
  domains: "Konfigurierte Domänen",
  add: "Domäne hinzufügen",
  edit: "Domäne bearbeiten",
  empty:
    "Für diesen Tenant wurden noch keine Domäneneinstellungen gespeichert.",
  unavailable:
    "Die Domäneneinstellungen konnten nicht geladen werden. Bitte erneut laden.",
  reload: "Daten neu laden",
  domain: "DNS-Name der Domäne",
  domainHint:
    "Vollständigen DNS-Namen verwenden. Die Domänenidentität kann nach dem Speichern nicht geändert werden.",
  mappings: "OU-Zuordnung je Tier",
  mappingHint:
    "Pro Zeile den Distinguished Name einer vorhandenen OU eintragen. Mehrere OUs pro Tier sind möglich. Nicht verwendete Tiers bleiben leer.",
  unverified: "Prüfung im Verzeichnis ausstehend",
  verificationHint:
    "Die gespeicherten OU-Pfade wurden noch nicht mit Active Directory abgeglichen. Bestehende Verzeichnisobjekte wurden weder übernommen noch verschoben.",
  naming: "GPO-Namensschema",
  nameTemplate: "Vorlage für GPO-Namen",
  tokens:
    "Jedes Feld genau einmal verwenden: {tier}, {scope}, {target}, {purpose}, {version}. Maximal 160 Zeichen. Scope ist C oder U. Eine gemeinsame Vorlage erzeugt getrennte GPOs für Tier 0, 1 und 2.",
  preview: "Namensbeispiele",
  exampleHint:
    "Entwurfsbeispiele verwenden Computer, ALL, Baseline und Version 1.0.0. Gespeicherte Beispiele werden vom Server geprüft.",
  invalidPreview: "Mit dieser Vorlage kann kein Beispiel erzeugt werden.",
  production: "Produktiv",
  pilot: "Pilot",
  order: "Reihenfolge der Baseline-Zusammenstellung",
  orderHint:
    "Die Baselines werden von oben nach unten eingeplant. Dies ist die geplante Zusammenstellung, nicht die AD-Verknüpfungsreihenfolge. Das Speichern wendet keine Richtlinien an und löst keine Einstellungskonflikte.",
  providersHint:
    "Angezeigt werden vorhandene Katalogeinträge. CIS-Inhalte können ergänzt werden, sobald ein unterstütztes Paket verfügbar ist.",
  moveUp: "Nach oben",
  moveDown: "Nach unten",
  drag: "Zum Sortieren ziehen",
  moved: "{name} auf Position {position} von {total} verschoben.",
  revision: "Gespeicherte Revision",
  save: "Domäneneinstellungen speichern",
  saving: "Wird gespeichert…",
  saved:
    "Domäneneinstellungen gespeichert. Es wurden keine Verzeichnisrichtlinien angewendet.",
  unsaved: "Ungespeicherte Änderungen",
  reset: "Änderungen verwerfen",
  discardHint:
    "Die aktuellen Änderungen vor einem Domänenwechsel speichern oder verwerfen.",
  invalid:
    "Die Einstellungen wurden abgelehnt. Bitte Domäne, OU-Pfade und Namensschema prüfen.",
  conflict:
    "Die gespeicherten Einstellungen wurden zwischenzeitlich geändert. Der Entwurf bleibt erhalten. Vor einer weiteren Änderung die gespeicherte Version neu laden.",
  uncertain:
    "Das Ergebnis konnte nicht bestätigt werden. Der Entwurf bleibt erhalten. Vor einem weiteren Versuch die gespeicherte Version neu laden.",
  permission:
    "Die aktuellen Tenant-Berechtigungen erlauben diese Aktion nicht.",
  sessionExpired: "Die Sitzung ist abgelaufen. Bitte erneut anmelden.",
  importsTitle: "Unverknüpfte Pilot-GPOs",
  importBoundary:
    "Eine separate Pilot-GPO auf einem Domain Controller vorbereiten. Der Agent benötigt eine lokale Freigabe für genau diesen Auftrag. Die GPO bleibt unverknüpft; Computer- und Benutzereinstellungen sind deaktiviert. Die Baseline wird dadurch nicht angewendet.",
  saveFirst: "Vor einem Pilot-Import die Domäneneinstellungen speichern.",
  importsUnavailable:
    "Pilot-Aufträge und geeignete Agents konnten nicht geladen werden.",
  importsRefresh: "Pilot-Aufträge aktualisieren",
  executor: "Domain-Controller-Agent",
  noExecutor: "Kein geeigneter Agent in dieser Domäne",
  executorHint:
    "Der ausgewählte Agent muss die erwartete Domänenidentität melden und diese begrenzte Operation lokal erlauben.",
  baseline: "Baseline-Paket",
  component: "GPO-Komponente",
  unavailableComponent: "Artefakt nicht verfügbar",
  tier: "Ziel-Tier",
  target: "Zielgruppen-Kürzel im Namen",
  version: "GPO-Version",
  importAction: "Unverknüpften Pilot-Import anfordern",
  requesting: "Wird angefordert…",
  importReceived:
    "Pilot-Import erfasst. Bevor der Agent die GPO erstellen kann, ist die lokale Freigabe erforderlich.",
  importInvalid:
    "Der Pilot-Auftrag wurde abgelehnt. Bitte gespeicherte Domänenrevision, Agent und Paket prüfen.",
  importUncertain:
    "Das Auftragsergebnis ist unklar. Vor einem erneuten Versuch die Pilot-Aufträge aktualisieren. Es wird kein neuer Auftrag automatisch erstellt.",
  noJobs: "Für diese Domäne wurden noch keine Pilot-Importe angefordert.",
  jobs: "Pilot-Import-Aufträge",
  status: "Status",
  agent: "Agent",
  requested: "Angefordert (UTC)",
  approval: "Lokales Freigabedokument",
  approvalHint:
    "Ein berechtigter Administrator muss genau diesen Auftrag über die geschützte lokale Agent-Konfiguration prüfen und freigeben. Das Anzeigen des Dokuments genehmigt oder startet den Auftrag nicht.",
  copyApproval: "Freigabedokument kopieren",
  copied: "Freigabedokument kopiert.",
  copyFailed:
    "Das Dokument konnte nicht kopiert werden. Den Inhalt bitte manuell markieren und kopieren.",
  staged:
    "Unverknüpft; Computer- und Benutzereinstellungen deaktiviert. Die Richtlinie wurde nicht angewendet.",
  errorCode: "Ergebniscode",
  states: {
    queued: "Eingereiht",
    awaiting_approval: "Lokale Freigabe ausstehend",
    running: "Wird ausgeführt",
    staged: "Vorbereitet, nicht angewendet",
    blocked: "Blockiert",
    failed: "Fehlgeschlagen",
    expired: "Abgelaufen",
    reconciliation_required: "Abgleich mit Verzeichnis erforderlich",
  },
};

export function getDomainSecurityCopy(locale: Locale): DomainSecurityCopy {
  return locale === "de" ? de : en;
}
