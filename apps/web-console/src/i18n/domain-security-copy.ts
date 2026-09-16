/**
 * File Name: domain-security-copy.ts
 * Version: v0.1.2 | Created: 2026-09-14 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Localize domain mapping, GPO names and managed GPO requests.
 */
import type { Locale } from "./config";

const en = {
  navigation: "Domains & tiers",
  title: "Domain security settings",
  eyebrow: "Tenant administration / Security",
  description: "Configure domain DNS names, tier OUs and GPO naming.",
  boundary:
    "Saving these settings records a plan. It does not create or move OUs, modify GPOs, or apply policy.",
  domains: "Configured domains",
  policyTitle: "Domain GPO configuration",
  policyDomain: "Configured domain",
  policyDescription:
    "Set the naming template for this domain. It is saved together with the tier OU mappings.",
  deploymentTitle: "GPO preparation",
  deploymentDescription:
    "Select the configured domain for this baseline. GPO names and OU mappings are maintained in tenant administration.",
  deploymentUnavailable:
    "Saved domain configuration could not be loaded. Reload to try again.",
  deploymentEmpty:
    "Configure a domain and its tier OUs in tenant administration before preparing GPOs.",
  configureDomains: "Configure domains & tiers",
  scanLogs: "View scan logs",
  importLogs: "View GPO import logs",
  openImportLog: "Open request and approval in Logs",
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
    "Enter one existing OU per line: a simple name such as _T0 means an OU directly below the selected domain and is saved as its full distinguished name. For nested OUs, use the complete path, e.g. OU=Servers,OU=_T1,DC=example,DC=invalid. Several OUs per tier are allowed; unused tiers stay empty.",
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
  pilot: "Legacy",
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
  validation: {
    domain:
      "Domain DNS name: enter a complete name such as example.invalid, without a URL or path.",
    tier0:
      "Tier 0 OUs: use simple names such as _T0 or complete OU distinguished names within the selected domain. Maximum 32 OUs; simple names allow up to 64 letters, digits, spaces, underscores, dots or hyphens. Nested OUs require their full path.",
    tier1:
      "Tier 1 OUs: use simple names such as _T1 or complete OU distinguished names within the selected domain. Maximum 32 OUs; simple names allow up to 64 letters, digits, spaces, underscores, dots or hyphens. Nested OUs require their full path.",
    tier2:
      "Tier 2 OUs: use simple names such as _T2 or complete OU distinguished names within the selected domain. Maximum 32 OUs; simple names allow up to 64 letters, digits, spaces, underscores, dots or hyphens. Nested OUs require their full path.",
    overlap:
      "OU mappings: an OU may occur only once. Parent and child OUs cannot belong to different tiers.",
    template:
      "GPO naming template: use each token {tier}, {scope}, {target}, {purpose}, {version} exactly once. Use only letters, digits, spaces, dots, underscores or hyphens around the tokens; maximum 160 characters.",
    order:
      "Baseline order: include every available baseline exactly once. Reload the saved data if the catalog has changed.",
  },
  conflict:
    "The saved settings changed in another session. Your draft is retained. Reload the saved version before making another change.",
  uncertain:
    "The result could not be confirmed. Your draft is retained. Reload the saved version before trying again.",
  permission: "Your current tenant permissions do not allow this action.",
  sessionExpired: "Your session has expired. Sign in again to continue.",
  importsTitle: "Unlinked GPOs",
  importBoundary:
    "Prepare a separate GPO on a domain controller. An authorized administrator reviews and approves the exact import in Logs. The GPO remains unlinked with Computer and User settings disabled; this does not apply the baseline.",
  saveFirst: "Save the GPO configuration before requesting a GPO request.",
  importsUnavailable:
    "Eligible Agents and the request state could not be loaded.",
  importsRefresh: "Refresh Agents and request state",
  executor: "Domain controller Agent",
  noExecutor: "No eligible Agent in this domain",
  executorHint:
    "The selected Agent must run version 0.2.36 or later and report the expected domain identity. Requesting and approving require an explicit domain and Tier authorization.",
  baseline: "Baseline package",
  component: "GPO component",
  unavailableComponent: "Artifact unavailable",
  tier: "Target tier",
  target: "Target name token",
  version: "GPO version",
  importAction: "Request unlinked GPO request",
  requesting: "Requesting…",
  importReceived:
    "GPO request request recorded. Review and approve the exact import in Logs before the Agent can create the GPO.",
  importInvalid:
    "The GPO request was rejected. Check the saved domain revision, Agent and package selection.",
  importUncertain:
    "The request result is uncertain. Refresh the request state and check Logs before retrying. No new request will be created automatically.",
  noJobs: "No GPO requests have been requested for this domain.",
  jobs: "GPO request jobs",
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
    awaiting_approval: "Awaiting approval",
    running: "Running",
    staged: "Version prepared",
    inspected: "AD state checked",
    linked: "Linked, inactive",
    activated: "Activated",
    deactivated: "Deactivated",
    deleted: "Deleted",
    reconciled: "Directory reconciled; import not confirmed",
    blocked: "Blocked",
    failed: "Failed",
    expired: "Expired",
    reconciliation_required: "Directory reconciliation required",
  },
};

export type DomainSecurityCopy = typeof en;
const de: DomainSecurityCopy = {
  navigation: "Domänen & Tiers",
  title: "Domänen-Sicherheitseinstellungen",
  eyebrow: "Tenant-Administration / Security",
  description:
    "DNS-Namen der Domänen, Tier-OUs und GPO-Namensschema konfigurieren.",
  boundary:
    "Das Speichern hält die Planung fest. Es erstellt oder verschiebt keine OUs, ändert keine GPOs und wendet keine Richtlinien an.",
  domains: "Konfigurierte Domänen",
  policyTitle: "GPO-Konfiguration der Domäne",
  policyDomain: "Konfigurierte Domäne",
  policyDescription:
    "Namensschema für diese Domäne festlegen. Es wird gemeinsam mit den Tier-OUs gespeichert.",
  deploymentTitle: "GPO-Vorbereitung",
  deploymentDescription:
    "Konfigurierte Domäne für diese Baseline auswählen. GPO-Namen und OU-Zuordnung werden in der Tenant-Administration gepflegt.",
  deploymentUnavailable:
    "Die gespeicherte Domänenkonfiguration konnte nicht geladen werden. Bitte erneut laden.",
  deploymentEmpty:
    "Vor der GPO-Vorbereitung eine Domäne mit ihren Tier-OUs in der Tenant-Administration konfigurieren.",
  configureDomains: "Domänen & Tiers konfigurieren",
  scanLogs: "Scan-Protokolle öffnen",
  importLogs: "GPO-Importprotokolle öffnen",
  openImportLog: "Auftrag und Freigabe in Logs öffnen",
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
    "Pro Zeile eine vorhandene OU eintragen: Ein einfacher Name wie _T0 bezeichnet eine OU direkt unter der gewählten Domäne und wird als vollständiger Distinguished Name gespeichert. Für verschachtelte OUs den vollständigen Pfad verwenden, z. B. OU=Servers,OU=_T1,DC=example,DC=invalid. Mehrere OUs pro Tier sind möglich; nicht verwendete Tiers bleiben leer.",
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
  pilot: "Legacy",
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
  validation: {
    domain:
      "DNS-Name der Domäne: Einen vollständigen Namen wie example.invalid eintragen, ohne URL oder Pfad.",
    tier0:
      "Tier 0 OUs: Einfache Namen wie _T0 oder vollständige OU-Distinguished-Names innerhalb der gewählten Domäne verwenden. Maximal 32 OUs; einfache Namen erlauben bis zu 64 Buchstaben, Ziffern, Leerzeichen, Unterstriche, Punkte oder Bindestriche. Verschachtelte OUs benötigen den vollständigen Pfad.",
    tier1:
      "Tier 1 OUs: Einfache Namen wie _T1 oder vollständige OU-Distinguished-Names innerhalb der gewählten Domäne verwenden. Maximal 32 OUs; einfache Namen erlauben bis zu 64 Buchstaben, Ziffern, Leerzeichen, Unterstriche, Punkte oder Bindestriche. Verschachtelte OUs benötigen den vollständigen Pfad.",
    tier2:
      "Tier 2 OUs: Einfache Namen wie _T2 oder vollständige OU-Distinguished-Names innerhalb der gewählten Domäne verwenden. Maximal 32 OUs; einfache Namen erlauben bis zu 64 Buchstaben, Ziffern, Leerzeichen, Unterstriche, Punkte oder Bindestriche. Verschachtelte OUs benötigen den vollständigen Pfad.",
    overlap:
      "OU-Zuordnung: Eine OU darf nur einmal vorkommen. Über- und untergeordnete OUs dürfen nicht unterschiedlichen Tiers zugeordnet sein.",
    template:
      "GPO-Namensschema: Jeden Platzhalter {tier}, {scope}, {target}, {purpose}, {version} genau einmal verwenden. Dazwischen sind nur Buchstaben, Ziffern, Leerzeichen, Punkte, Unterstriche oder Bindestriche erlaubt; maximal 160 Zeichen.",
    order:
      "Baseline-Reihenfolge: Jede verfügbare Baseline genau einmal einordnen. Bei geändertem Katalog die gespeicherten Daten neu laden.",
  },
  conflict:
    "Die gespeicherten Einstellungen wurden zwischenzeitlich geändert. Der Entwurf bleibt erhalten. Vor einer weiteren Änderung die gespeicherte Version neu laden.",
  uncertain:
    "Das Ergebnis konnte nicht bestätigt werden. Der Entwurf bleibt erhalten. Vor einem weiteren Versuch die gespeicherte Version neu laden.",
  permission:
    "Die aktuellen Tenant-Berechtigungen erlauben diese Aktion nicht.",
  sessionExpired: "Die Sitzung ist abgelaufen. Bitte erneut anmelden.",
  importsTitle: "Unverknüpfte GPOs",
  importBoundary:
    "Eine separate GPO auf einem Domain Controller vorbereiten. Ein berechtigter Administrator prüft und genehmigt den konkreten Import unter Logs. Die GPO bleibt unverknüpft; Computer- und Benutzereinstellungen sind deaktiviert. Die Baseline wird dadurch nicht angewendet.",
  saveFirst: "Vor einem GPO-Auftrag die GPO-Konfiguration speichern.",
  importsUnavailable:
    "Geeignete Agents und der Auftragsstand konnten nicht geladen werden.",
  importsRefresh: "Agents und Auftragsstand aktualisieren",
  executor: "Domain-Controller-Agent",
  noExecutor: "Kein geeigneter Agent in dieser Domäne",
  executorHint:
    "Der ausgewählte Agent muss mindestens Version 0.2.36 ausführen und die erwartete Domänenidentität melden. Anfordern und Freigeben erfordern eine ausdrückliche Berechtigung für Domäne und Tier.",
  baseline: "Baseline-Paket",
  component: "GPO-Komponente",
  unavailableComponent: "Artefakt nicht verfügbar",
  tier: "Ziel-Tier",
  target: "Zielgruppen-Kürzel im Namen",
  version: "GPO-Version",
  importAction: "Unverknüpften GPO-Auftrag anfordern",
  requesting: "Wird angefordert…",
  importReceived:
    "GPO-Auftrag erfasst. Den konkreten Import unter Logs prüfen und freigeben, bevor der Agent die GPO erstellen kann.",
  importInvalid:
    "Der GPO-Auftrag wurde abgelehnt. Bitte gespeicherte Domänenrevision, Agent und Paket prüfen.",
  importUncertain:
    "Das Auftragsergebnis ist unklar. Vor einem erneuten Versuch den Auftragsstand aktualisieren und Logs prüfen. Es wird kein neuer Auftrag automatisch erstellt.",
  noJobs: "Für diese Domäne wurden noch keine GPO-Auftrage angefordert.",
  jobs: "GPO-Aufträge",
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
    awaiting_approval: "Freigabe ausstehend",
    running: "Wird ausgeführt",
    staged: "Version vorbereitet",
    inspected: "AD-Zustand geprüft",
    linked: "Verknüpft, inaktiv",
    activated: "Aktiviert",
    deactivated: "Deaktiviert",
    deleted: "Gelöscht",
    reconciled: "Verzeichnis abgeglichen; Import nicht bestätigt",
    blocked: "Blockiert",
    failed: "Fehlgeschlagen",
    expired: "Abgelaufen",
    reconciliation_required: "Abgleich mit Verzeichnis erforderlich",
  },
};

export function getDomainSecurityCopy(locale: Locale): DomainSecurityCopy {
  return locale === "de" ? de : en;
}
