/**
 * File Name: windows-gpo-copy.ts
 * Version: v0.1.1 | Created: 2026-09-16 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Label the single managed Windows GPO deployment workspace.
 */
import type { Locale } from "./config";

const en = {
  navigation: "Windows GPOs",
  title: "Windows GPO deployment",
  description:
    "Import, link and activate managed baseline, override and custom GPOs from one workspace.",
  domain: "Domain",
  source: "Policy source",
  baseline: "Baseline",
  override: "Override",
  overrideSelection: "Saved override",
  customSelection: "Saved custom GPO",
  noDomains:
    "No domain configuration is available. Configure domains and tier OUs first.",
  noOverrides: "No override definition is available.",
  noCustomGpos: "No custom GPO definition is available.",
  unavailable: "The Windows GPO workspace could not be loaded.",
  configure: "Configure domains and tier OUs",
  baselines: "Baselines",
  overrides: "Overrides",
  custom: "Custom GPOs",
  customTitle: "Custom GPOs",
  customDescription:
    "Create tenant-authored custom GPO definitions from validated policy settings. Deployment remains centralized in Windows GPO deployment.",
  openDeployment: "Open Windows GPO deployment",
};

const de: typeof en = {
  navigation: "Windows GPOs",
  title: "Windows-GPO-Verteilung",
  description:
    "Importiere, verknüpfe und aktiviere verwaltete Baseline-, Override- und Custom-GPOs an einer zentralen Stelle.",
  domain: "Domäne",
  source: "Richtlinienquelle",
  baseline: "Baseline",
  override: "Override",
  overrideSelection: "Gespeicherter Override",
  customSelection: "Gespeicherte Custom-GPO",
  noDomains:
    "Es ist keine Domänenkonfiguration verfügbar. Konfiguriere zuerst Domänen und Tier-OUs.",
  noOverrides: "Es ist keine Override-Definition verfügbar.",
  noCustomGpos: "Es ist keine Custom-GPO-Definition verfügbar.",
  unavailable: "Der Windows-GPO-Arbeitsbereich konnte nicht geladen werden.",
  configure: "Domänen und Tier-OUs konfigurieren",
  baselines: "Baselines",
  overrides: "Overrides",
  custom: "Custom GPOs",
  customTitle: "Custom GPOs",
  customDescription:
    "Erstelle kundeneigene GPO-Definitionen aus geprüften Richtlinieneinstellungen. Die Verteilung bleibt zentral unter Windows-GPO-Verteilung.",
  openDeployment: "Windows-GPO-Verteilung öffnen",
};

export const getWindowsGpoCopy = (locale: Locale) =>
  locale === "de" ? de : en;
