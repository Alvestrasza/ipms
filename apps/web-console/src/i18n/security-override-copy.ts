/**
 * File Name: security-override-copy.ts
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Explain original-setting overrides and separate managed GPO deployment.
 */
import type { Locale } from "./config";

const en = {
  navigation: "Override",
  title: "Baseline overrides",
  description:
    "Change selected original baseline settings. Only deviations are stored; the Microsoft baseline stays unchanged.",
  select: "Override",
  create: "New override",
  name: "Name",
  baseline: "Baseline",
  component: "Component",
  enabled: "Available for deployment",
  save: "Save override",
  discard: "Discard changes",
  saved: "Override saved. Saving does not change AD.",
  load: "The override configuration could not be loaded. Reload before continuing.",
  rejected:
    "The override was not saved. Check the values and reload if the baseline or revision changed.",
  uncertain:
    "The save result is uncertain. Reload and check the existing overrides before retrying.",
  reload: "Reload",
  loading: "Loading original settings…",
  search: "Search settings",
  changedOnly: "Only changes",
  setting: "Original setting",
  original: "Baseline value",
  override: "Override value",
  apply: "Use override",
  cancelSetting: "Cancel",
  edit: "Override this setting",
  editExisting: "Edit override",
  remove: "Remove override",
  baselineSelected: "Choose a value that differs from the baseline.",
  readonly: "This original setting cannot currently be edited safely.",
  structural:
    "This entry controls policy structure or removal. Changing it as an individual value is not supported.",
  structured:
    "This value contains structured policy data, such as AppLocker XML. It needs a dedicated editor and cannot be changed as plain text here.",
  invalid: "Check value type, permitted options and limits.",
  empty: "No settings match this selection.",
  count: "Changed settings",
  sparse:
    "Choose a value, then accept it with Use override. Remove override restores the baseline value; it does not create a Not Configured setting. Save override persists all accepted deviations. At most 128 deviations can be saved.",
  listHint: "One entry per line; an empty field means an empty list.",
  deployment: "Deploy saved override",
  domain: "Domain",
  priority:
    "IPMS deploys the selected deviations in a separate GPO with higher priority than the baseline at the same target. The Agent checks the actual links before execution. Other inheritance and filtering rules still apply.",
  saveFirst: "Save or discard changes before deployment.",
  disabled:
    "This override is unavailable for new deployments. Existing managed GPOs can still be deactivated.",
  agent: "Overrides require a domain controller Agent version 0.2.43 or newer.",
  noDomains: "No domain configuration is available for deployment.",
  noChanges: "No deviations selected.",
  previous: "Previous",
  next: "Next",
  unsupported: "Unsupported setting",
  mismatch:
    "This override belongs to a different baseline package. Reload and review the baseline before editing.",
};
const de: typeof en = {
  navigation: "Override",
  title: "Baseline-Overrides",
  description:
    "Ändere ausgewählte Originaleinstellungen einer Baseline. Gespeichert werden nur Abweichungen; die Microsoft-Baseline bleibt unverändert.",
  select: "Override",
  create: "Neuer Override",
  name: "Name",
  baseline: "Baseline",
  component: "Komponente",
  enabled: "Für Verteilung verfügbar",
  save: "Override speichern",
  discard: "Änderungen verwerfen",
  saved: "Override gespeichert. Das Speichern ändert nichts im AD.",
  load: "Die Override-Konfiguration konnte nicht geladen werden. Lade die Seite erneut, bevor du fortfährst.",
  rejected:
    "Der Override wurde nicht gespeichert. Prüfe die Werte und lade bei geänderter Baseline oder Revision erneut.",
  uncertain:
    "Das Speicherergebnis ist unklar. Lade erneut und prüfe die vorhandenen Overrides vor einem neuen Versuch.",
  reload: "Neu laden",
  loading: "Originaleinstellungen werden geladen…",
  search: "Einstellungen suchen",
  changedOnly: "Nur Änderungen",
  setting: "Originaleinstellung",
  original: "Baseline-Wert",
  override: "Override-Wert",
  apply: "Override übernehmen",
  cancelSetting: "Abbrechen",
  edit: "Diese Einstellung überschreiben",
  editExisting: "Override bearbeiten",
  remove: "Override entfernen",
  baselineSelected: "Wähle einen Wert, der von der Baseline abweicht.",
  readonly:
    "Diese Originaleinstellung kann derzeit nicht sicher bearbeitet werden.",
  structural:
    "Dieser Eintrag steuert die Richtlinienstruktur oder das Entfernen von Einstellungen. Er kann nicht als einzelner Wert geändert werden.",
  structured:
    "Dieser Wert enthält strukturierte Richtliniendaten, beispielsweise AppLocker-XML. Dafür ist ein eigener Editor erforderlich; hier kann er nicht als einfacher Text geändert werden.",
  invalid: "Prüfe Datentyp, erlaubte Werte und Grenzen.",
  empty: "Keine Einstellungen entsprechen dieser Auswahl.",
  count: "Geänderte Einstellungen",
  sparse:
    "Wähle einen Wert und bestätige ihn mit Override übernehmen. Override entfernen stellt den Baseline-Wert wieder her; es entsteht keine Einstellung Nicht konfiguriert. Override speichern speichert alle übernommenen Abweichungen. Maximal 128 Abweichungen können gespeichert werden.",
  listHint: "Ein Eintrag pro Zeile; ein leeres Feld bedeutet eine leere Liste.",
  deployment: "Gespeicherten Override verteilen",
  domain: "Domäne",
  priority:
    "IPMS verteilt die ausgewählten Abweichungen in einer separaten GPO mit höherer Priorität als die Baseline am selben Ziel. Der Agent prüft die tatsächlichen Verknüpfungen vor der Ausführung. Weitere Vererbungs- und Filterregeln gelten weiterhin.",
  saveFirst: "Speichere oder verwirf Änderungen vor der Verteilung.",
  disabled:
    "Dieser Override ist für neue Verteilungen gesperrt. Bestehende verwaltete GPOs können weiterhin deaktiviert werden.",
  agent: "Overrides benötigen einen Domain-Controller-Agent ab Version 0.2.43.",
  noDomains: "Keine Domänenkonfiguration für die Verteilung verfügbar.",
  noChanges: "Keine Abweichungen ausgewählt.",
  previous: "Zurück",
  next: "Weiter",
  unsupported: "Nicht unterstützte Einstellung",
  mismatch:
    "Dieser Override gehört zu einem anderen Baseline-Paket. Lade erneut und prüfe die Baseline vor der Bearbeitung.",
};
export const getSecurityOverrideCopy = (locale: Locale) =>
  locale === "de" ? de : en;
export function overrideReadonlyReason(reason: string, locale: Locale) {
  const copy = getSecurityOverrideCopy(locale);
  return reason === "structured_registry_value"
    ? copy.structured
    : reason === "structural_instruction"
      ? copy.structural
      : copy.readonly;
}
