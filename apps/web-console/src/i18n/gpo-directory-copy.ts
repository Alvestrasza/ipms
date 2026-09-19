/**
 * File Name: gpo-directory-copy.ts
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Label the read-only GPMC-style directory and managed GPO viewer.
 */
import type { Locale } from "./config";

const en = {
  title: "Directory and GPO overview",
  description:
    "Read-only view of configured directory targets and IPMS-managed GPOs from validated Agent observations.",
  boundary:
    "This first viewer stage covers configured targets and IPMS-managed GPOs. Unmanaged GPOs, all directory containers, delegation and modeling follow with the domain-wide inventory stage.",
  configuredTargets: "Configured targets",
  managedGpos: "Managed GPOs",
  observedTargets: "Targets with Agent evidence",
  noGpos: "No IPMS-managed GPO exists in this domain.",
  noEvidence: "No validated directory observation is available yet.",
  observed: "Observed",
  notObserved: "Not yet observed",
  inheritanceBlocked: "Inheritance blocked",
  inheritanceEnabled: "Inheritance enabled",
  directLinks: "Direct links",
  inheritedLinks: "Inherited links",
  state: "State",
  tier: "Tier",
  targets: "Targets",
  computer: "Computer configuration",
  user: "User configuration",
  enabled: "Enabled",
  disabled: "Disabled",
  unknown: "Not observed",
  owner: "Owner SID",
  wmi: "WMI filter",
  none: "None",
  versions: "Directory / SYSVOL version",
  links: "Links",
  technical: "Technical details",
  sources: { baseline: "Baseline", override: "Override", custom: "Custom GPO" },
};

const de: typeof en = {
  title: "Verzeichnis- und GPO-Übersicht",
  description:
    "Lesende Ansicht der konfigurierten Verzeichnisziele und IPMS-verwalteten GPOs aus geprüften Agent-Beobachtungen.",
  boundary:
    "Diese erste Viewer-Stufe umfasst konfigurierte Ziele und IPMS-verwaltete GPOs. Fremde GPOs, alle Verzeichniscontainer, Delegation und Modellierung folgen mit der domänenweiten Inventarisierung.",
  configuredTargets: "Konfigurierte Ziele",
  managedGpos: "Verwaltete GPOs",
  observedTargets: "Ziele mit Agent-Nachweis",
  noGpos: "In dieser Domäne ist noch keine IPMS-verwaltete GPO vorhanden.",
  noEvidence: "Es liegt noch keine geprüfte Verzeichnisbeobachtung vor.",
  observed: "Beobachtet",
  notObserved: "Noch nicht beobachtet",
  inheritanceBlocked: "Vererbung blockiert",
  inheritanceEnabled: "Vererbung aktiv",
  directLinks: "Direkte Verknüpfungen",
  inheritedLinks: "Geerbte Verknüpfungen",
  state: "Status",
  tier: "Tier",
  targets: "Ziele",
  computer: "Computerkonfiguration",
  user: "Benutzerkonfiguration",
  enabled: "Aktiviert",
  disabled: "Deaktiviert",
  unknown: "Nicht beobachtet",
  owner: "Besitzer-SID",
  wmi: "WMI-Filter",
  none: "Keiner",
  versions: "Verzeichnis-/SYSVOL-Version",
  links: "Verknüpfungen",
  technical: "Technische Details",
  sources: { baseline: "Baseline", override: "Override", custom: "Custom-GPO" },
};

export const getGpoDirectoryCopy = (locale: Locale) =>
  locale === "de" ? de : en;
