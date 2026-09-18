/**
 * File Name: security-custom-gpo-copy.ts
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Explain bounded sparse custom GPO authoring.
 */
import type { Locale } from "./config";
import { getSecurityOverrideCopy } from "./security-override-copy";

export function getSecurityCustomGpoCopy(locale: Locale) {
  const base = getSecurityOverrideCopy(locale);
  return locale === "de"
    ? {
        ...base,
        navigation: "Custom GPOs",
        title: "Custom-GPOs",
        description:
          "Erstelle eigene GPOs aus geprüften Windows-Richtlinieneinstellungen. Nur ausdrücklich ausgewählte Einstellungen werden konfiguriert.",
        select: "Custom-GPO",
        create: "Neue Custom-GPO",
        enabled: "Für Verteilung verfügbar",
        save: "Custom-GPO speichern",
        delete: "Custom-GPO löschen",
        deleted:
          "Custom-GPO-Definition gelöscht. Vorhandene AD-GPOs müssen zuvor unter Windows-GPO-Verteilung gelöscht werden.",
        deleteInUse:
          "Zu dieser Custom-GPO existiert noch eine verwaltete GPO. Lösche diese zuerst unter Windows-GPO-Verteilung.",
        saved: "Custom-GPO gespeichert. Das Speichern ändert nichts im AD.",
        load: "Die Custom-GPO-Konfiguration konnte nicht geladen werden. Lade die Seite erneut.",
        rejected:
          "Die Custom-GPO wurde nicht gespeichert. Prüfe Name, Einstellungen und Revision.",
        changedOnly: "Nur ausgewählte Einstellungen",
        override: "Konfigurierter Wert",
        apply: "Einstellung übernehmen",
        edit: "Einstellung konfigurieren",
        editExisting: "Einstellung bearbeiten",
        remove: "Auf Nicht konfiguriert setzen",
        baselineSelected:
          "Der angezeigte Quellwert darf in einer Custom-GPO ausdrücklich übernommen werden.",
        count: "Konfigurierte Einstellungen",
        sparse:
          "Wähle eine Einstellung und bestätige sie mit Einstellung übernehmen. Die Custom-GPO enthält ausschließlich diese Auswahl; alle übrigen Einstellungen bleiben Nicht konfiguriert. Maximal 128 Einstellungen können gespeichert werden.",
        noChanges: "Wähle mindestens eine Einstellung aus.",
        agent:
          "Custom-GPOs benötigen einen Domain-Controller-Agent ab Version 0.2.48.",
      }
    : {
        ...base,
        navigation: "Custom GPOs",
        title: "Custom GPOs",
        description:
          "Build custom GPOs from validated Windows policy settings. Only explicitly selected settings are configured.",
        select: "Custom GPO",
        create: "New custom GPO",
        enabled: "Available for deployment",
        save: "Save custom GPO",
        delete: "Delete custom GPO",
        deleted:
          "Custom GPO definition deleted. Existing AD GPOs must first be deleted in Windows GPO deployment.",
        deleteInUse:
          "This custom GPO still has a managed GPO. Delete it in Windows GPO deployment first.",
        saved: "Custom GPO saved. Saving does not change AD.",
        load: "The custom GPO configuration could not be loaded. Reload the page.",
        rejected:
          "The custom GPO was not saved. Check its name, settings and revision.",
        changedOnly: "Selected settings only",
        override: "Configured value",
        apply: "Use setting",
        edit: "Configure setting",
        editExisting: "Edit setting",
        remove: "Set to Not Configured",
        baselineSelected:
          "The displayed source value may be selected explicitly in a custom GPO.",
        count: "Configured settings",
        sparse:
          "Choose a setting and accept it with Use setting. The custom GPO contains only that selection; every other setting remains Not Configured. At most 128 settings can be saved.",
        noChanges: "Select at least one setting.",
        agent:
          "Custom GPOs require a domain controller Agent version 0.2.48 or newer.",
      };
}
