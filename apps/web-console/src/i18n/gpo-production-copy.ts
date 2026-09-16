/**

 * File Name: gpo-production-copy.ts

 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15

 * Author: Alice Endelgard | Organization: Alvestrasza Corporation

 * Purpose: Explain independently approved production GPO lifecycle actions.

 */

import type { Locale } from "./config";

const en = {
  title: "GPO distribution",

  activeUnverified: "Active version not verified",

  description:
    "Import and linking use one request. The GPO and its links remain disabled until a separate activation is approved. Existing GPOs keep their GUID; preparing an update does not change active settings.",

  policy: "Managed GPO",

  create: "New GPO",

  operation: "Action",

  inspect: "Inspect AD state",

  refresh: "Refresh",

  executor: "Executing domain controller",

  baseline: "Baseline",

  component: "Component",

  target: "Target alias",

  version: "Version",

  tier: "Tier",

  exactOus: "Exact target OUs",

  exactOusHint:
    "Select one or more OUs configured for this tier. The managed GPO remains bound to this exact target set for later activation and lifecycle actions.",

  noConfiguredOus: "No OUs are configured for this tier.",

  adopt: "Use existing IPMS import",

  noAdopt: "Create a new managed GPO",

  selection: "Selection",

  preparing:
    "The Agent is checking GPO identity, OU identities and existing links. This check does not change AD.",

  prepare: "Submit action",

  retry: "Retry the same request",

  createHint:
    "The Agent checks AD first. Without four-eyes review, submission also authorizes this exact action when you have domain and tier approval rights. Otherwise, approval in Logs is required.",

  prepared: "Request created. Review and approve this exact action in Logs.",

  submitted:
    "Request approved and submitted. No additional approval in Logs is needed; execution status is shown there.",

  logs: "Review request in Logs",

  unavailable: "The GPO state could not be loaded. Reload before continuing.",

  rejected:
    "The request was rejected. Refresh and check domain permissions, configuration, Agent version and AD state.",

  uncertain:
    "The request result is uncertain. Reload to reconcile its existing request ID before trying again.",

  expiry: "Inspection is no longer current. Run a new AD inspection.",

  empty: "No managed GPOs for this domain yet.",

  inspection: "Verified AD state",

  unchanged:
    "Changes after inspection invalidate this request. The Agent checks the same state again immediately before execution.",

  unavailableName:
    "The requested GPO name is occupied. Resolve the name conflict before continuing.",

  proposedName: "Requested GPO name",

  existing: "Existing GPO",

  newIdentity: "New disabled, unlinked GPO",

  ou: "Target OUs",

  noOus: "No target OUs selected for this import.",

  links: "Existing direct links",

  enabled: "Enabled",

  disabled: "Disabled",

  enforced: "Enforced",

  blocked: "Inheritance blocked",

  technical: "Technical identity details",

  management:
    "I have checked that the proposed settings preserve IPMS and the required administrator access.",

  recovery:
    "I have verified an independent recovery access path for the affected domain and tier.",

  activation:
    "Activation applies the prepared settings to the stable GPO and enables the approved links. A protected backup is created first. A heartbeat alone is not proof of recovery access.",

  linkBoundary:
    "Link changes require disabled GPO settings. New links stay disabled until a separate activation is approved.",

  deactivateBoundary:
    "Deactivation disables both GPO halves. It does not delete the GPO or its links.",

  inspectOnly: "Read-only inspection; no change approval is required.",

  domainBoundary:
    "Domain-wide account policies target the domain root with explicit Tier 0 authorization. Confirm that target separately for each action; importing alone leaves the GPO disabled and unlinked.",

  domainRoot: "Domain root",

  confirmDomainRoot:
    "I confirm the domain root as the target for this domain-wide account policy. This confirmation does not approve its execution.",

  actionHint: "Approval authorizes only the action and targets shown below.",

  noExecutor: "No eligible Agent 0.2.36 or newer is currently available.",

  noLegacyExecutor: "No eligible Agent 0.2.35 or newer is currently available.",

  actions: {
    import_and_link_managed_gpo: "Import and link",

    import_managed_gpo: "Prepare version",

    link_managed_gpo: "Link targets",

    activate_managed_gpo: "Activate",

    deactivate_managed_gpo: "Deactivate",

    inspect_managed_gpo: "Inspect AD state",
  },

  states: {
    new: "Not imported",

    prepared: "Version prepared",

    linked: "Linked, inactive",

    active: "Active",

    inactive: "Inactive",

    reconciliation_required: "Reconciliation required",
  },
};

const de: typeof en = {
  title: "GPO-Verteilung",

  activeUnverified: "Aktiver Stand nicht bestätigt",

  description:
    "Import und Verknüpfung erfolgen in einem Auftrag. GPO und Verknüpfungen bleiben bis zur separaten Aktivierungsfreigabe deaktiviert. Bestehende GPOs behalten ihre GUID; die Vorbereitung eines Updates ändert keine aktiven Einstellungen.",

  policy: "Verwaltete GPO",

  create: "Neue GPO",

  operation: "Aktion",

  inspect: "AD-Zustand prüfen",

  refresh: "Aktualisieren",

  executor: "Ausführender Domain Controller",

  baseline: "Baseline",

  component: "Komponente",

  target: "Zielkürzel",

  version: "Version",

  tier: "Tier",

  exactOus: "Genaue Ziel-OUs",

  exactOusHint:
    "Wähle eine oder mehrere für dieses Tier konfigurierte OUs. Die verwaltete GPO bleibt für die spätere Aktivierung und weitere Aktionen genau an diese Zielmenge gebunden.",

  noConfiguredOus: "Für dieses Tier sind keine OUs konfiguriert.",

  adopt: "Vorhandenen IPMS-Import übernehmen",

  noAdopt: "Neue verwaltete GPO erstellen",

  selection: "Auswahl",

  preparing:
    "Der Agent prüft GPO-Identität, OU-Identitäten und vorhandene Verknüpfungen. Diese Prüfung ändert nichts im AD.",

  prepare: "Aktion beauftragen",

  retry: "Denselben Auftrag erneut versuchen",

  createHint:
    "Der Agent prüft zuerst das AD. Ohne Vier-Augen-Prinzip gibt die Beauftragung diese konkrete Aktion mit deinen Freigaberechten für Domäne und Tier frei. Andernfalls ist eine Freigabe unter Logs erforderlich.",

  prepared:
    "Auftrag erstellt. Diese konkrete Aktion unter Logs prüfen und freigeben.",

  submitted:
    "Auftrag freigegeben und übermittelt. Keine zusätzliche Freigabe unter Logs erforderlich; dort steht der Ausführungsstatus.",
  logs: "Auftrag unter Logs prüfen",

  unavailable:
    "Der GPO-Zustand konnte nicht geladen werden. Vor dem Fortfahren erneut laden.",

  rejected:
    "Der Auftrag wurde abgelehnt. Bitte aktualisieren und Domänenberechtigung, Konfiguration, Agent-Version und AD-Zustand prüfen.",

  uncertain:
    "Das Auftragsergebnis ist unklar. Vor einem erneuten Versuch aktualisieren und die vorhandene Auftrags-ID abgleichen.",

  expiry:
    "Die Prüfung ist nicht mehr aktuell. Bitte den AD-Zustand erneut prüfen.",

  empty: "Für diese Domäne gibt es noch keine verwalteten GPOs.",

  inspection: "Geprüfter AD-Zustand",

  unchanged:
    "Änderungen nach der Prüfung machen diesen Auftrag ungültig. Der Agent prüft denselben Zustand unmittelbar vor der Ausführung erneut.",

  unavailableName:
    "Der gewünschte GPO-Name ist bereits belegt. Vor dem Fortfahren den Namenskonflikt auflösen.",

  proposedName: "Gewünschter GPO-Name",

  existing: "Vorhandene GPO",

  newIdentity: "Neue deaktivierte, unverknüpfte GPO",

  ou: "Ziel-OUs",

  noOus: "Für diesen Import sind keine Ziel-OUs ausgewählt.",

  links: "Vorhandene direkte Verknüpfungen",

  enabled: "Aktiviert",

  disabled: "Deaktiviert",

  enforced: "Erzwungen",

  blocked: "Vererbung blockiert",

  technical: "Technische Identitätsdetails",

  management:
    "Ich habe geprüft, dass die vorgesehenen Einstellungen IPMS und die erforderlichen Administratorzugänge erhalten.",

  recovery:
    "Ich habe einen unabhängigen Wiederherstellungszugang für die betroffene Domäne und das Tier geprüft.",

  activation:
    "Die Aktivierung übernimmt die vorbereiteten Einstellungen in die stabile GPO und aktiviert die freigegebenen Verknüpfungen. Vorher wird eine geschützte Sicherung erstellt. Ein Heartbeat allein bestätigt keinen Wiederherstellungszugang.",

  linkBoundary:
    "Verknüpfungen können nur bei deaktivierten GPO-Einstellungen geändert werden. Neue Verknüpfungen bleiben bis zur separaten Aktivierungsfreigabe deaktiviert.",

  deactivateBoundary:
    "Die Deaktivierung schaltet beide GPO-Teile aus. Sie löscht weder die GPO noch deren Verknüpfungen.",

  inspectOnly:
    "Lesende Prüfung; dafür ist keine Änderungsfreigabe erforderlich.",

  domainBoundary:
    "Domänenweite Kontorichtlinien verwenden die Domänenwurzel und benötigen eine ausdrückliche Tier-0-Berechtigung. Bestätige dieses Ziel für jede Aktion gesondert; der Import allein lässt die GPO deaktiviert und unverknüpft.",

  domainRoot: "Domänenwurzel",

  confirmDomainRoot:
    "Ich bestätige die Domänenwurzel als Ziel dieser domänenweiten Kontorichtlinie. Diese Bestätigung gibt die Ausführung noch nicht frei.",

  actionHint:
    "Die Freigabe gilt ausschließlich für die unten angezeigte Aktion und ihre Ziele.",

  noExecutor: "Derzeit ist kein geeigneter Agent ab Version 0.2.36 verfügbar.",

  noLegacyExecutor:
    "Derzeit ist kein geeigneter Agent ab Version 0.2.35 verfügbar.",

  actions: {
    import_and_link_managed_gpo: "Importieren und verknüpfen",

    import_managed_gpo: "Version vorbereiten",

    link_managed_gpo: "Ziele verknüpfen",

    activate_managed_gpo: "Aktivieren",

    deactivate_managed_gpo: "Deaktivieren",

    inspect_managed_gpo: "AD-Zustand prüfen",
  },

  states: {
    new: "Noch nicht importiert",

    prepared: "Version vorbereitet",

    linked: "Verknüpft, inaktiv",

    active: "Aktiv",

    inactive: "Inaktiv",

    reconciliation_required: "Abgleich erforderlich",
  },
};

export const getGpoProductionCopy = (locale: Locale) =>
  locale === "de" ? de : en;
