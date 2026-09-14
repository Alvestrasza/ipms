/**
 * File Name: security-copy.ts
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Provide English and German security baseline console copy.
 */
import type { Locale } from "./config";

const en = {
  navigation: "Security",
  baselineNavigation: "Baseline",
  title: "Microsoft security baselines",
  description:
    "A shared view of Microsoft's Windows GPO baselines and compliance across this tenant's servers and clients.",
  readOnly: "Read-only catalog",
  reload: "Reload data",
  unavailable: "Baseline data is currently unavailable.",
  unavailableHint:
    "The security service could not be reached or returned an incomplete response. Reload to try again.",
  catalog: "Baseline catalog",
  catalogHint:
    "Select a baseline to see its package details and the systems that match its Windows release.",
  catalogEmpty: "No baselines are available for this selection.",
  hiddenCount: "Hidden baselines in this selection",
  hiddenHint:
    "A tenant administrator can show them again in Administration → Security → Baseline.",
  allHidden: "All baselines in this selection are hidden.",
  manageVisibility: "Manage baseline visibility",
  admin: {
    title: "Baseline visibility",
    eyebrow: "Administration / Security",
    description:
      "Choose which baselines appear in this tenant's Security overview.",
    boundary: "Hide from Security > Baseline; existing results are retained.",
    table: "Baseline visibility settings",
    overview: "Open Security overview",
    visible: "Visible",
    hidden: "Hidden",
    visibility: "Overview visibility",
    hide: "Hide",
    show: "Show",
    saving: "Saving…",
    action: "Action",
    updated: "Changed (UTC)",
    default: "Default visibility",
    empty: "No baseline visibility settings are available.",
    unavailable:
      "Baseline visibility settings could not be loaded. Reload to try again.",
    uncertain: "Not confirmed",
    actionFailed:
      "The change could not be confirmed. Reload the settings before trying again.",
    permission:
      "Your tenant role no longer permits this action. Reload to check your access.",
    sessionExpired: "Your session has expired. Sign in again to continue.",
    invalid:
      "The visibility setting was rejected. Reload the settings before trying again.",
    hiddenNotice: "{name} is now hidden from Security > Baseline.",
    shownNotice: "{name} is now visible in Security > Baseline.",
  },
  catalogRevision: "Catalog revision",
  generatedAt: "Data loaded (UTC)",
  inventoried: "Inventoried Windows systems",
  servers: "Servers",
  clients: "Clients",
  unclassified: "Unclassified system role",
  unmatched: "No matching baseline",
  mappingHint:
    "Windows systems with an unclassified role or no matching baseline need their inventory or catalog coverage reviewed.",
  targets: { all: "All Windows systems", server: "Servers", client: "Clients" },
  filterLabel: "Baseline target",
  baseline: "Baseline",
  targetRelease: "Target / release",
  compliance: "Compliance",
  coverage: "Assessment coverage",
  applicable: "Matching systems",
  assessed: "Assessed",
  notAssessed: "Not assessed",
  noMatching: "No matching systems",
  viewSystems: "View systems",
  selected: "Selected baseline",
  selectionMissing: "The selected baseline is not in this catalog selection.",
  selectBaseline: "Select a baseline from the catalog to continue.",
  scope:
    "Compliance is the share of all matching inventoried systems that fully meet this baseline. Missing, incomplete, failed and expired assessments remain in that total. Assessment coverage shows how many matching systems have a current, complete result.",
  assessmentPending:
    "Automatic baseline assessment through the Agent is not available yet. Systems without a current, complete result remain unknown.",
  modules: "Security modules",
  moduleCatalog: "Microsoft baseline catalog",
  moduleAssessment: "Agent assessments",
  moduleDeployment: "Deployment via collections",
  ready: "Available",
  planned: "Planned",
  moduleHint:
    "The modular structure prepares additional baseline providers and platforms, including CIS, Linux and network devices. Configuration and collection deployment follow in later modules.",
  details: "Baseline details",
  provider: "Provider",
  package: "GPO package",
  revision: "Package revision",
  verifiedAt: "Source verified",
  profiles: "Included profiles",
  source: "Microsoft source",
  openSource: "Open Microsoft source",
  lastAssessed: "Last assessment (UTC)",
  systems: "Matching systems",
  systemsHint:
    "This list includes physical and virtual Windows systems that match this baseline's target and release.",
  systemsUnavailable:
    "The system list could not be loaded. Reload to try again.",
  pageMissing: "This system page is no longer available.",
  firstPage: "Return to the first page",
  system: "System",
  operatingSystem: "Operating system",
  role: "System role",
  serverRole: "Server",
  status: "Assessment status",
  assessmentTime: "Assessed (UTC)",
  build: "Build",
  previous: "Previous",
  next: "Next",
  page: "Page",
  of: "of",
  systemTypes: { physical: "Physical", virtual: "Virtual" },
  roles: {
    server: "Member server",
    "domain-controller": "Domain controller",
    client: "Client",
    unknown: "Unclassified",
  },
  statuses: {
    compliant: "Compliant",
    non_compliant: "Non-compliant",
    unknown: "Unknown",
    error: "Assessment error",
    stale: "Expired result",
  },
  reasons: {
    not_assessed: "Not assessed",
    partial: "Incomplete assessment",
    assessment_error: "Assessment failed",
    expired: "Result expired",
    baseline_changed: "Baseline changed",
    system_changed: "System changed",
    agent_unavailable: "Agent unavailable",
    complete: "Complete assessment",
  },
};

export type SecurityCopy = typeof en;

const de: SecurityCopy = {
  navigation: "Security",
  baselineNavigation: "Baseline",
  title: "Microsoft-Sicherheitsbaselines",
  description:
    "Die Windows-GPO-Baselines von Microsoft und der Erfüllungsgrad der Server und Clients dieses Mandanten auf einen Blick.",
  readOnly: "Lesender Katalog",
  reload: "Daten neu laden",
  unavailable: "Baseline-Daten sind derzeit nicht verfügbar.",
  unavailableHint:
    "Der Security-Dienst ist nicht erreichbar oder hat eine unvollständige Antwort geliefert. Lade die Daten erneut.",
  catalog: "Baseline-Katalog",
  catalogHint:
    "Wähle eine Baseline aus, um Paketdetails und die Systeme mit passender Windows-Version zu sehen.",
  catalogEmpty: "Für diese Auswahl sind keine Baselines verfügbar.",
  hiddenCount: "Ausgeblendete Baselines in dieser Auswahl",
  hiddenHint:
    "Ein Mandantenadministrator kann sie unter Administration → Security → Baseline wieder einblenden.",
  allHidden: "Alle Baselines in dieser Auswahl sind ausgeblendet.",
  manageVisibility: "Baseline-Sichtbarkeit verwalten",
  admin: {
    title: "Baseline-Sichtbarkeit",
    eyebrow: "Administration / Security",
    description:
      "Lege fest, welche Baselines in der Security-Übersicht dieses Mandanten erscheinen.",
    boundary:
      "Aus Security > Baseline ausblenden; vorhandene Ergebnisse bleiben erhalten.",
    table: "Baseline-Sichtbarkeit verwalten",
    overview: "Security-Übersicht öffnen",
    visible: "Sichtbar",
    hidden: "Ausgeblendet",
    visibility: "Sichtbarkeit in der Übersicht",
    hide: "Ausblenden",
    show: "Einblenden",
    saving: "Wird gespeichert…",
    action: "Aktion",
    updated: "Geändert (UTC)",
    default: "Standardsichtbarkeit",
    empty: "Es sind keine Baseline-Sichtbarkeitseinstellungen verfügbar.",
    unavailable:
      "Die Baseline-Sichtbarkeit konnte nicht geladen werden. Lade die Daten erneut.",
    uncertain: "Nicht bestätigt",
    actionFailed:
      "Die Änderung konnte nicht bestätigt werden. Lade die Einstellungen vor einem weiteren Versuch erneut.",
    permission:
      "Deine Mandantenrolle erlaubt diese Aktion nicht mehr. Lade die Seite zur erneuten Zugriffsprüfung.",
    sessionExpired: "Deine Sitzung ist abgelaufen. Melde dich erneut an.",
    invalid:
      "Die Sichtbarkeitseinstellung wurde abgelehnt. Lade die Einstellungen vor einem weiteren Versuch erneut.",
    hiddenNotice: "{name} ist jetzt unter Security > Baseline ausgeblendet.",
    shownNotice: "{name} ist jetzt unter Security > Baseline sichtbar.",
  },
  catalogRevision: "Katalogrevision",
  generatedAt: "Datenstand (UTC)",
  inventoried: "Inventarisierte Windows-Systeme",
  servers: "Server",
  clients: "Clients",
  unclassified: "Systemrolle nicht zugeordnet",
  unmatched: "Keine passende Baseline",
  mappingHint:
    "Prüfe bei Windows-Systemen ohne zugeordnete Rolle oder passende Baseline die Inventardaten und die Abdeckung des Katalogs.",
  targets: { all: "Alle Windows-Systeme", server: "Server", client: "Clients" },
  filterLabel: "Baseline-Zielgruppe",
  baseline: "Baseline",
  targetRelease: "Zielgruppe / Version",
  compliance: "Erfüllungsgrad",
  coverage: "Prüfungsabdeckung",
  applicable: "Passende Systeme",
  assessed: "Geprüft",
  notAssessed: "Nicht geprüft",
  noMatching: "Keine passenden Systeme",
  viewSystems: "Systeme anzeigen",
  selected: "Ausgewählte Baseline",
  selectionMissing:
    "Die ausgewählte Baseline ist in dieser Katalogauswahl nicht enthalten.",
  selectBaseline: "Wähle eine Baseline aus dem Katalog aus.",
  scope:
    "Der Erfüllungsgrad ist der Anteil aller passenden inventarisierten Systeme, die diese Baseline vollständig erfüllen. Fehlende, unvollständige, fehlgeschlagene und abgelaufene Prüfungen bleiben in der Gesamtzahl enthalten. Die Prüfungsabdeckung zeigt den Anteil mit aktuellem, vollständigem Ergebnis.",
  assessmentPending:
    "Die automatische Baseline-Prüfung durch den Agent ist noch nicht verfügbar. Systeme ohne aktuelles, vollständiges Ergebnis bleiben unbekannt.",
  modules: "Security-Module",
  moduleCatalog: "Microsoft-Baseline-Katalog",
  moduleAssessment: "Prüfung durch den Agent",
  moduleDeployment: "Verteilung über Collections",
  ready: "Verfügbar",
  planned: "Geplant",
  moduleHint:
    "Der modulare Aufbau bereitet weitere Baseline-Anbieter und Plattformen vor, darunter CIS, Linux und Netzwerkgeräte. Konfiguration und Verteilung über Collections folgen in späteren Modulen.",
  details: "Baseline-Details",
  provider: "Anbieter",
  package: "GPO-Paket",
  revision: "Paketrevision",
  verifiedAt: "Quelle geprüft",
  profiles: "Enthaltene Profile",
  source: "Microsoft-Quelle",
  openSource: "Microsoft-Quelle öffnen",
  lastAssessed: "Letzte Prüfung (UTC)",
  systems: "Passende Systeme",
  systemsHint:
    "Diese Liste enthält physische und virtuelle Windows-Systeme mit passender Zielgruppe und Windows-Version für diese Baseline.",
  systemsUnavailable:
    "Die Systemliste konnte nicht geladen werden. Lade die Daten erneut.",
  pageMissing: "Diese Seite der Systemliste ist nicht mehr verfügbar.",
  firstPage: "Zur ersten Seite",
  system: "System",
  operatingSystem: "Betriebssystem",
  role: "Systemrolle",
  serverRole: "Server",
  status: "Prüfstatus",
  assessmentTime: "Geprüft (UTC)",
  build: "Build",
  previous: "Zurück",
  next: "Weiter",
  page: "Seite",
  of: "von",
  systemTypes: { physical: "Physisch", virtual: "Virtuell" },
  roles: {
    server: "Mitgliedsserver",
    "domain-controller": "Domänencontroller",
    client: "Client",
    unknown: "Nicht zugeordnet",
  },
  statuses: {
    compliant: "Erfüllt",
    non_compliant: "Nicht erfüllt",
    unknown: "Unbekannt",
    error: "Prüffehler",
    stale: "Ergebnis abgelaufen",
  },
  reasons: {
    not_assessed: "Nicht geprüft",
    partial: "Prüfung unvollständig",
    assessment_error: "Prüfung fehlgeschlagen",
    expired: "Ergebnis abgelaufen",
    baseline_changed: "Baseline geändert",
    system_changed: "System geändert",
    agent_unavailable: "Agent nicht verfügbar",
    complete: "Vollständige Prüfung",
  },
};

export function getSecurityCopy(locale: Locale): SecurityCopy {
  return locale === "de" ? de : en;
}
