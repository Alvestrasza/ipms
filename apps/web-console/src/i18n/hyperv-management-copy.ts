import type { Locale } from "./config";

const english = {
  title: "Virtual machine management",
  sections: {
    settings: "Settings",
    checkpoints: "Checkpoints",
    migration: "Move virtual machine",
    cluster: "Failover cluster",
  },
  actions: "More virtual machine actions",
  hint: "Use the action button, right-click, or Shift+F10 to manage a virtual machine.",
  close: "Close",
  cancel: "Cancel",
  host: "Host",
  powerState: "Virtual machine power state",
  poweredOn: "VM is powered on",
  lastPoweredOn: "Last observed: VM powered on",
  currentSection: "Current section",
  otherActions: "VM actions",
  unsaved: "Unsaved changes in this section",
  applyHint: "Only the selected section is applied.",
  refresh: "Refresh from host",
  reload: "Reload status",
  loading: "Loading management data…",
  empty:
    "No management snapshot has been collected. Refresh from the host to inspect this virtual machine.",
  refreshHint:
    "Refreshing requests a new read-only inspection from the Agent. Opening this window does not contact the host.",
  stale:
    "This snapshot is no longer current. Refresh from the host before making changes.",
  fresh: "Current snapshot",
  observed: "Collected (UTC)",
  unknown: "Not reported",
  yes: "Yes",
  no: "No",
  readonly:
    "Only General, processor count and memory can be changed in this release. Each section is applied separately while the VM is stopped. Other settings remain read-only.",
  applySettings: "Apply this section",
  settingsStopped:
    "Settings changes require a stopped VM and a current, complete inspection. IPMS does not stop the VM automatically.",
  settingsRunning:
    "This section is read-only while the VM is powered on. Live changes are not yet supported by the current IPMS Agent. IPMS does not stop the VM automatically.",
  settingsMissing:
    "This section contains unreported values and cannot be edited. Unknown values will not be replaced with defaults.",
  settingsInvalid:
    "Check the values. Names must be non-empty and at most 100 characters; CPU and memory values must be positive whole numbers. Memory must satisfy minimum ≤ startup ≤ maximum.",
  permission: "Your tenant role does not permit this change.",
  unsupported:
    "The host Agent has not enabled this operation. No command will be sent.",
  uncertainSubmission:
    "The request outcome could not be confirmed. Status is being read without resubmitting the operation. A new successful host inspection is required before another change.",
  productionUnsupported:
    "Production checkpoint creation is not yet qualified for this host interface. IPMS does not silently change the VM policy or fall back to a standard checkpoint.",
  checkpointsDisabled:
    "Checkpoint creation is disabled by this VM's configured policy.",
  unavailable:
    "This section could not be collected. Missing information is not an empty configuration.",
  settings: {
    groups: {
      identity: "Identity",
      hardware: "Hardware configuration",
      management: "Management",
    },
    additional: "Additional properties",
    readOnlyLabel: "Read-only",
    general: "General",
    processor: "Processor",
    memory: "Memory",
    automatic: "Automatic actions",
    devices: "Devices",
    name: "Name",
    notes: "Notes",
    version: "Configuration version",
    generation: "Generation",
    count: "Virtual processors",
    reservation: "Processor reservation",
    limit: "Processor limit",
    weight: "Relative weight",
    compatibility: "Processor migration compatibility",
    startup: "Startup memory",
    minimum: "Minimum memory",
    maximum: "Maximum memory",
    dynamic: "Dynamic memory",
    buffer: "Memory buffer",
    startAction: "Start action (provider value)",
    startDelay: "Start delay (provider duration)",
    stopAction: "Stop action (provider value)",
    policy: "Checkpoint policy",
    devicesHint:
      "Network adapter and storage settings have not yet been collected by this inspector.",
  },
  policies: {
    2: "Disabled",
    3: "Production with standard fallback",
    4: "Production only",
    5: "Standard",
  },
  checkpoints: {
    create: "Create checkpoint",
    remove: "Delete checkpoint subtree",
    apply: "Apply checkpoint",
    empty: "No checkpoints exist in this collected snapshot.",
    select: "Select a checkpoint to inspect it.",
    name: "Checkpoint name",
    created: "Created (UTC)",
    type: "Type",
    current: "Current checkpoint",
    id: "Checkpoint ID",
    parent: "Parent checkpoint ID",
    createHint:
      "Uses the VM's configured checkpoint policy only when the host Agent explicitly supports it. IPMS does not change the policy or silently choose another checkpoint type.",
    deleteTitle: "Delete checkpoint subtree",
    deleteWarning:
      "The selected checkpoint and every listed descendant will be removed. Disk merges may take time. This cannot be undone and does not delete the virtual machine.",
    acknowledge:
      "I acknowledge deletion of exactly the checkpoints listed below, including their IDs.",
    applyTitle: "Apply checkpoint",
    applyWarning:
      "Applying this checkpoint replaces the VM's current state. Changes since the checkpoint may be lost. This is not a backup or a rollback guarantee.",
    confirmVm: "Type the exact virtual machine name",
    confirmCheckpoint: "Type the exact checkpoint name",
    types: {
      standard: "Standard",
      production: "Production",
      recovery: "Recovery",
      unknown: "Unknown",
    },
  },
  pending: "Preflight not yet implemented",
  migration:
    "Host and storage migration are not executable in this release. Destination host, storage paths, connectivity, migration identity, compatibility and free space must be validated before a migration can be offered. No destination or storage path has been selected.",
  cluster:
    "Adding or removing a VM's clustered role is not executable in this release. Cluster membership, exact VM identity, storage ownership and dependencies must be validated first. Removing a role must never silently delete the VM or its storage.",
  job: "Management operation",
  jobId: "Job ID",
  result: "Result code",
  continuing:
    "The operation continues when this window is closed. Reopen it to see the current status.",
  reconciliation:
    "The outcome is uncertain and requires reconciliation. Do not repeat the operation. It is intentionally blocked until its actual host state has been verified.",
  statuses: {
    queued: "Queued",
    delivered: "Delivered",
    running: "Running",
    requires_reconciliation: "Requires reconciliation",
    succeeded: "Succeeded",
    failed: "Failed",
    cancelled: "Cancelled",
  },
  operations: {
    inspect: "Inspect virtual machine",
    checkpoint_create: "Create checkpoint",
    checkpoint_delete: "Delete checkpoint subtree",
    checkpoint_apply: "Apply checkpoint",
    settings_update: "Update settings",
  },
  errors: {
    checkpoint_policy_unsupported:
      "The configured checkpoint policy is not supported by this Agent operation. No automatic fallback to a standard checkpoint is permitted.",
    invalid_vm_state:
      "The VM is not in a state that permits this operation. Refresh its state before continuing.",
    settings_property_unsupported:
      "The host does not expose all required settings. No missing value will be replaced with a default.",
    settings_method_unavailable:
      "The host does not provide the required settings update method.",
    provider_acceptance_unknown:
      "It is unclear whether the host accepted the operation. Reconciliation is required before another attempt.",
    provider_job_missing:
      "The host operation can no longer be located. Its outcome must be reconciled before retrying.",
    provider_job_ownership_unconfirmed:
      "The host operation could not be safely bound to this VM. Reconciliation is required.",
    operation_postcondition_unconfirmed:
      "The expected VM state after the operation could not be verified. Reconciliation is required.",
    execution_authority_unavailable:
      "The Agent could not verify current execution authorization. No new change is permitted.",
    unknown:
      "The request could not be completed. Reload status before trying again; a submitted operation may already have been accepted.",
    management_agent_upgrade_required:
      "Update the host Agent to a version supporting VM management first.",
    management_agent_unavailable:
      "The host Agent is unavailable. Check its connection before requesting an inspection.",
    management_operation_conflict:
      "Another operation is active for this VM. Reload status and wait for it to finish.",
    management_console_active:
      "Close the VM console before making this change.",
    management_snapshot_stale:
      "The snapshot has expired. Refresh from the host before making changes.",
    management_revision_changed:
      "The VM configuration has changed. Refresh and review it again.",
    management_operation_unsupported:
      "This operation is not supported by the current management contract or host Agent.",
    management_snapshot_unavailable:
      "A complete host inspection is required before this operation.",
    management_checkpoint_not_found:
      "The checkpoint is no longer present. Refresh from the host.",
    management_confirmation_mismatch:
      "The confirmation does not match the current VM and checkpoint names.",
    management_checkpoint_tree_changed:
      "The checkpoint tree has changed. Refresh and review every affected checkpoint again.",
    management_request_conflict:
      "This request identifier is already bound to another operation. Reload status.",
    management_authority_withdrawn:
      "Authorization for this operation has been withdrawn.",
    forbidden:
      "Your account is not permitted to perform this operation in this tenant.",
    invalid_request:
      "The request does not match the supported management contract.",
  },
};
type CopyShape<T> = {
  [Key in keyof T]: T[Key] extends string ? string : CopyShape<T[Key]>;
};
export type HyperVManagementCopy = CopyShape<typeof english>;
const german: HyperVManagementCopy = {
  title: "Verwaltung der virtuellen Maschine",
  sections: {
    settings: "Einstellungen",
    checkpoints: "Prüfpunkte",
    migration: "Virtuelle Maschine verschieben",
    cluster: "Failovercluster",
  },
  actions: "Weitere VM-Aktionen",
  hint: "Verwalte eine VM über den Aktionsbutton, per Rechtsklick oder mit Umschalt+F10.",
  close: "Schließen",
  cancel: "Abbrechen",
  host: "Host",
  powerState: "Betriebszustand der VM",
  poweredOn: "VM ist eingeschaltet",
  lastPoweredOn: "Zuletzt erfasst: VM eingeschaltet",
  currentSection: "Aktueller Bereich",
  otherActions: "VM-Aktionen",
  unsaved: "Ungespeicherte Änderungen in diesem Bereich",
  applyHint: "Nur der ausgewählte Bereich wird angewendet.",
  refresh: "Vom Host aktualisieren",
  reload: "Status neu laden",
  loading: "Verwaltungsdaten werden geladen…",
  empty:
    "Es wurden noch keine Verwaltungsdaten erfasst. Aktualisiere vom Host, um diese VM zu prüfen.",
  refreshHint:
    "Die Aktualisierung fordert eine neue, rein lesende Prüfung durch den Agent an. Das Öffnen dieses Fensters kontaktiert den Host nicht.",
  stale:
    "Dieser Datenstand ist nicht mehr aktuell. Aktualisiere vom Host, bevor du Änderungen ausführst.",
  fresh: "Aktueller Datenstand",
  observed: "Erfasst (UTC)",
  unknown: "Nicht gemeldet",
  yes: "Ja",
  no: "Nein",
  readonly:
    "In dieser Version können nur Allgemein, Prozessoranzahl und Arbeitsspeicher geändert werden. Jeder Bereich wird einzeln bei ausgeschalteter VM angewendet. Die übrigen Einstellungen bleiben schreibgeschützt.",
  applySettings: "Diesen Bereich anwenden",
  settingsStopped:
    "Änderungen erfordern eine ausgeschaltete VM und eine aktuelle, vollständige Prüfung. IPMS schaltet die VM nicht automatisch aus.",
  settingsRunning:
    "Dieser Bereich ist bei eingeschalteter VM schreibgeschützt. Live-Änderungen werden vom aktuellen IPMS-Agent noch nicht unterstützt. IPMS schaltet die VM nicht automatisch aus.",
  settingsMissing:
    "Dieser Bereich enthält nicht gemeldete Werte und kann nicht bearbeitet werden. Unbekannte Werte werden nicht durch Standardwerte ersetzt.",
  settingsInvalid:
    "Prüfe die Werte. Namen dürfen nicht leer sein und höchstens 100 Zeichen enthalten; CPU- und Speicherwerte müssen positive ganze Zahlen sein. Es muss Minimum ≤ Startwert ≤ Maximum gelten.",
  permission: "Deine Tenant-Rolle erlaubt diese Änderung nicht.",
  unsupported:
    "Der Host-Agent hat diese Aktion nicht freigegeben. Es wird kein Befehl gesendet.",
  uncertainSubmission:
    "Das Ergebnis der Anfrage konnte nicht bestätigt werden. Der Status wird ohne erneutes Senden der Aktion gelesen. Vor einer weiteren Änderung ist eine neue erfolgreiche Host-Prüfung erforderlich.",
  productionUnsupported:
    "Das Erstellen von Produktionsprüfpunkten ist für diese Host-Schnittstelle noch nicht qualifiziert. IPMS ändert weder unbemerkt die VM-Richtlinie noch weicht es auf einen Standardprüfpunkt aus.",
  checkpointsDisabled:
    "Das Erstellen von Prüfpunkten ist durch die konfigurierte VM-Richtlinie deaktiviert.",
  unavailable:
    "Dieser Bereich konnte nicht erfasst werden. Fehlende Informationen bedeuten keine leere Konfiguration.",
  settings: {
    groups: {
      identity: "Identität",
      hardware: "Hardwarekonfiguration",
      management: "Verwaltung",
    },
    additional: "Weitere Eigenschaften",
    readOnlyLabel: "Schreibgeschützt",
    general: "Allgemein",
    processor: "Prozessor",
    memory: "Arbeitsspeicher",
    automatic: "Automatische Aktionen",
    devices: "Geräte",
    name: "Name",
    notes: "Notizen",
    version: "Konfigurationsversion",
    generation: "Generation",
    count: "Virtuelle Prozessoren",
    reservation: "Prozessorreservierung",
    limit: "Prozessorlimit",
    weight: "Relative Gewichtung",
    compatibility: "Prozessorkompatibilität für Migration",
    startup: "Startarbeitsspeicher",
    minimum: "Minimaler Arbeitsspeicher",
    maximum: "Maximaler Arbeitsspeicher",
    dynamic: "Dynamischer Arbeitsspeicher",
    buffer: "Arbeitsspeicherpuffer",
    startAction: "Startaktion (Providerwert)",
    startDelay: "Startverzögerung (Providerdauer)",
    stopAction: "Beendigungsaktion (Providerwert)",
    policy: "Prüfpunktrichtlinie",
    devicesHint:
      "Netzwerkkarten- und Speichereinstellungen werden von dieser Prüfung noch nicht erfasst.",
  },
  policies: {
    2: "Deaktiviert",
    3: "Produktion mit Standard-Fallback",
    4: "Nur Produktion",
    5: "Standard",
  },
  checkpoints: {
    create: "Prüfpunkt erstellen",
    remove: "Prüfpunkt-Unterstruktur löschen",
    apply: "Prüfpunkt anwenden",
    empty: "In diesem erfassten Datenstand sind keine Prüfpunkte vorhanden.",
    select: "Wähle einen Prüfpunkt aus, um seine Details anzuzeigen.",
    name: "Prüfpunktname",
    created: "Erstellt (UTC)",
    type: "Typ",
    current: "Aktueller Prüfpunkt",
    id: "Prüfpunkt-ID",
    parent: "Übergeordnete Prüfpunkt-ID",
    createHint:
      "Verwendet die konfigurierte Prüfpunktrichtlinie nur, wenn der Host-Agent sie ausdrücklich unterstützt. IPMS ändert weder die Richtlinie noch wählt es unbemerkt einen anderen Prüfpunkt-Typ.",
    deleteTitle: "Prüfpunkt-Unterstruktur löschen",
    deleteWarning:
      "Der ausgewählte Prüfpunkt und alle aufgeführten Nachfolger werden entfernt. Das Zusammenführen der Datenträger kann dauern. Dies lässt sich nicht rückgängig machen und löscht nicht die virtuelle Maschine.",
    acknowledge:
      "Ich bestätige das Löschen genau der nachfolgend aufgeführten Prüfpunkte einschließlich ihrer IDs.",
    applyTitle: "Prüfpunkt anwenden",
    applyWarning:
      "Das Anwenden dieses Prüfpunkts ersetzt den aktuellen VM-Zustand. Änderungen seit dem Prüfpunkt können verloren gehen. Dies ist kein Backup und keine Wiederherstellungsgarantie.",
    confirmVm: "Gib den exakten Namen der virtuellen Maschine ein",
    confirmCheckpoint: "Gib den exakten Prüfpunktnamen ein",
    types: {
      standard: "Standard",
      production: "Produktion",
      recovery: "Wiederherstellung",
      unknown: "Unbekannt",
    },
  },
  pending: "Vorabprüfung noch nicht implementiert",
  migration:
    "Host- und Speichermigrationen sind in dieser Version noch nicht ausführbar. Zielhost, Speicherpfade, Verbindung, Migrationsidentität, Kompatibilität und freier Speicher müssen zuvor geprüft werden. Es wurden weder Zielhost noch Speicherpfad ausgewählt.",
  cluster:
    "Das Hinzufügen oder Entfernen einer VM-Clusterrolle ist in dieser Version noch nicht ausführbar. Zuerst müssen Clustermitgliedschaft, exakte VM-Identität, Speicherzuordnung und Abhängigkeiten geprüft werden. Das Entfernen einer Rolle darf niemals unbemerkt die VM oder ihre Datenträger löschen.",
  job: "Verwaltungsaktion",
  jobId: "Auftrags-ID",
  result: "Ergebniscode",
  continuing:
    "Der Auftrag läuft auch nach dem Schließen dieses Fensters weiter. Öffne es erneut, um den aktuellen Status zu sehen.",
  reconciliation:
    "Das Ergebnis ist unklar und erfordert einen Abgleich. Wiederhole die Aktion nicht. Sie bleibt bewusst gesperrt, bis der tatsächliche Zustand auf dem Host geprüft wurde.",
  statuses: {
    queued: "Eingereiht",
    delivered: "Zugestellt",
    running: "Wird ausgeführt",
    requires_reconciliation: "Abgleich erforderlich",
    succeeded: "Erfolgreich",
    failed: "Fehlgeschlagen",
    cancelled: "Abgebrochen",
  },
  operations: {
    inspect: "Virtuelle Maschine prüfen",
    checkpoint_create: "Prüfpunkt erstellen",
    checkpoint_delete: "Prüfpunkt-Unterstruktur löschen",
    checkpoint_apply: "Prüfpunkt anwenden",
    settings_update: "Einstellungen ändern",
  },
  errors: {
    checkpoint_policy_unsupported:
      "Die konfigurierte Prüfpunktrichtlinie wird von dieser Agent-Aktion nicht unterstützt. Ein automatischer Fallback auf Standardprüfpunkte ist nicht erlaubt.",
    invalid_vm_state:
      "Die VM befindet sich nicht in einem für diese Aktion zulässigen Zustand. Aktualisiere ihren Zustand vor dem Fortfahren.",
    settings_property_unsupported:
      "Der Host stellt nicht alle erforderlichen Einstellungen bereit. Fehlende Werte werden nicht durch Standardwerte ersetzt.",
    settings_method_unavailable:
      "Der Host stellt die erforderliche Methode zur Einstellungsänderung nicht bereit.",
    provider_acceptance_unknown:
      "Es ist unklar, ob der Host die Aktion angenommen hat. Vor einem neuen Versuch ist ein Abgleich erforderlich.",
    provider_job_missing:
      "Der Host-Auftrag ist nicht mehr auffindbar. Vor einem neuen Versuch muss sein Ergebnis abgeglichen werden.",
    provider_job_ownership_unconfirmed:
      "Der Host-Auftrag konnte dieser VM nicht sicher zugeordnet werden. Ein Abgleich ist erforderlich.",
    operation_postcondition_unconfirmed:
      "Der erwartete VM-Zustand nach der Aktion konnte nicht bestätigt werden. Ein Abgleich ist erforderlich.",
    execution_authority_unavailable:
      "Der Agent konnte die aktuelle Ausführungsberechtigung nicht bestätigen. Eine neue Änderung ist nicht erlaubt.",
    unknown:
      "Die Anfrage konnte nicht abgeschlossen werden. Lade vor einem neuen Versuch den Status neu; ein gesendeter Auftrag könnte bereits angenommen worden sein.",
    management_agent_upgrade_required:
      "Aktualisiere den Host-Agent zuerst auf eine Version mit VM-Verwaltung.",
    management_agent_unavailable:
      "Der Host-Agent ist nicht verfügbar. Prüfe vor einer erneuten Prüfung seine Verbindung.",
    management_operation_conflict:
      "Für diese VM läuft bereits ein Auftrag. Lade den Status neu und warte auf den Abschluss.",
    management_console_active: "Schließe die VM-Konsole vor dieser Änderung.",
    management_snapshot_stale:
      "Der Datenstand ist abgelaufen. Aktualisiere vor Änderungen vom Host.",
    management_revision_changed:
      "Die VM-Konfiguration wurde geändert. Aktualisiere und prüfe sie erneut.",
    management_operation_unsupported:
      "Diese Aktion wird vom aktuellen Verwaltungsablauf oder Host-Agent nicht unterstützt.",
    management_snapshot_unavailable:
      "Für diese Aktion ist eine vollständige Prüfung durch den Host erforderlich.",
    management_checkpoint_not_found:
      "Der Prüfpunkt ist nicht mehr vorhanden. Aktualisiere vom Host.",
    management_confirmation_mismatch:
      "Die Bestätigung stimmt nicht mit den aktuellen VM- und Prüfpunktnamen überein.",
    management_checkpoint_tree_changed:
      "Die Prüfpunktstruktur wurde geändert. Aktualisiere und prüfe alle betroffenen Prüfpunkte erneut.",
    management_request_conflict:
      "Diese Anfrage-ID gehört bereits zu einem anderen Auftrag. Lade den Status neu.",
    management_authority_withdrawn:
      "Die Berechtigung für diesen Auftrag wurde entzogen.",
    forbidden: "Dein Konto darf diese Aktion in diesem Tenant nicht ausführen.",
    invalid_request:
      "Die Anfrage entspricht nicht dem unterstützten Verwaltungsformat.",
  },
};
export function getHyperVManagementCopy(locale: Locale): HyperVManagementCopy {
  return locale === "de" ? german : english;
}
