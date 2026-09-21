/**
 * File Name: hgs-copy.ts
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Localize the HGS deployment workflow and explicit protection boundaries.
 */
import type { Locale } from "./config";

const en = {
  navigation: "Host Guardian Service",
  security: "Security",
  title: "Host Guardian Service",
  description:
    "Plan and provision HGS on existing Windows VMs enrolled in a dedicated tenant.",
  singleAppliance:
    "One IPMS Appliance supports HGS and infrastructure tenants.",
  boundary:
    "HGS runs on the Windows nodes. After provisioning, Hyper-V contacts HGS directly for attestation and key release. Privileged Appliance administrators remain trusted across both tenants.",
  tenantRequired:
    "Use a separate tenant with the purpose ‘Host Guardian Service only’. Select that tenant above. A platform administrator can create it on this Appliance; a second Appliance is not required.",
  unavailable:
    "HGS data is unavailable or did not match this tenant. Refresh before taking an action.",
  refresh: "Refresh",
  newPlan: "New deployment plan",
  deployments: "Deployment plans",
  empty: "No HGS deployment plans yet.",
  create: "Create plan",
  created:
    "The plan was created. Inspect the nodes before reviewing execution.",
  name: "Deployment name",
  profile: "VM protection profile",
  profiles: { vtpm: "Simple: vTPM", shielded: "Secure: Shielded VMs" },
  profileHelp:
    "This provisions HGS for the selected profile. Host admission, VM shielding and guest disk encryption are separate operations; existing VMs are not changed.",
  attestation: "Host attestation",
  modes: { host_key: "Host-key attestation", tpm: "TPM-trusted attestation" },
  attestationHelp:
    "Shielded VMs require TPM-trusted attestation. A TPM-attested HGS can serve both profiles. An existing deployment never changes mode automatically.",
  domain: "New HGS forest DNS name",
  service: "HGS service name",
  featureSource: "Local Windows feature source",
  sourceHelp:
    "Use the approved feature source already present on each node. Installation must remain within the air gap.",
  sourceInvalid:
    "Use an absolute local Windows path of at most 240 characters. Network paths, parent-directory navigation, alternate streams and script characters are not accepted.",
  signing: "Signing certificate thumbprint",
  encryption: "Encryption certificate thumbprint",
  certificatesHelp:
    "The corresponding certificates and usable private keys must already be available on every selected node.",
  dsrm: "Local DSRM secret reference",
  join: "Local domain-join secret reference",
  secretHelp:
    "Enter reference names for locally protected secrets, never passwords or private keys.",
  primaryServer: "Primary HGS node IP address",
  primaryHelp:
    "Required when adding nodes. Enter the primary Windows node's IP address, not the Appliance address.",
  nodes: "HGS nodes",
  nodesHelp:
    "Select existing enrolled Windows VMs. The first selected node creates the new forest; subsequent nodes join it. Start with one lab node; production availability should use at least three nodes.",
  noSystems:
    "No enrolled Windows nodes are available in this tenant. Install and enroll their Agents first.",
  agent: "Agent",
  primary: "Primary node",
  additional: "Additional node",
  selection: "Selected order",
  allowReboot: "Authorize the planned Windows reboots as part of execution",
  readOnly:
    "Your account can view HGS plans. A tenant administrator must create and execute them.",
  plan: "Plan review",
  digest: "Plan digest",
  expires: "Plan expires",
  approvalExpires: "Execution authority expires",
  noApproval: "Not authorized",
  observed: "Last node inspection",
  noObservation: "Not inspected",
  status: "Status",
  operation: "Operation",
  target: "Target node",
  change: "Changes system",
  reboot: "Planned reboot",
  yes: "Yes",
  no: "No",
  steps: "Planned steps",
  jobs: "Jobs",
  noJobs: "No jobs have been dispatched.",
  result: "Result",
  inspect: "Inspect nodes",
  inspectionQueued:
    "Node inspection was requested. Waiting for Agent evidence.",
  execute: "Authorize and execute plan",
  executionQueued:
    "Execution was authorized for this exact plan. Follow the recorded job outcomes.",
  review:
    "I have reviewed these targets, actions, certificate and secret references, and planned reboots.",
  cancel: "Stop new work",
  cancelHelp:
    "Stopping prevents new work. It cannot undo a Windows operation that has already started.",
  stopped: "The request to stop new work was recorded.",
  reconcile: "Inspect for reconciliation",
  resolve: "Accept verified state and resume",
  recoveryReview:
    "I have reviewed the current evidence. Accept the verified state of the interrupted step and authorize only the following steps.",
  recoveryEvidence: "Verified observation digest",
  resolved:
    "The verified state was accepted. Subsequent steps can continue; the interrupted write was not replayed.",
  reconciliation:
    "The previous outcome needs reconciliation. Fresh inspection does not authorize replay. When its evidence proves the interrupted step completed, review and accept that state before continuing with subsequent steps.",
  reconciled:
    "Fresh read-only inspection was requested. No write operation was replayed.",
  expired:
    "This plan has expired. Create a new plan and review fresh node evidence.",
  stale:
    "Execution requires fresh successful inspection of every node within the last 30 minutes.",
  blocked: "Resolve the reported prerequisites before execution.",
  uncertain:
    "The request outcome is uncertain. Refresh the plans and inspect the recorded state before any further action. The request will not be repeated automatically.",
  failed:
    "The request could not be completed. Refresh and check the current plan.",
  invalid: "Check the entered values and selected nodes.",
  forbidden: "You are not authorized for this HGS operation.",
  changed:
    "The plan or observed state changed. Inspect it again and review the current plan.",
  unknown: "Unknown",
  states: {
    draft: "Draft",
    inspecting: "Inspecting nodes",
    blocked: "Blocked",
    ready: "Ready for review",
    running: "Running",
    waiting_for_reboot: "Waiting for reboot",
    succeeded: "Completed",
    failed: "Failed",
    cancelled: "Stopped",
    reconciliation_required: "Reconciliation required",
    pending: "Pending",
    queued: "Queued",
    claimed: "Claimed",
    offered: "Offered to Agent",
    dispatched: "Dispatched",
    completed: "Completed",
    unavailable: "Unavailable",
    not_started: "Not started",
    inspected: "Inspected",
    verified: "Verified",
  },
  operations: {
    inspect: "Inspect readiness",
    readiness: "Inspect readiness",
    install_role: "Install HGS role",
    create_forest: "Create dedicated HGS forest",
    join_node: "Join HGS forest",
    initialize: "Initialize HGS",
    initialize_hgs: "Initialize HGS",
    verify: "Verify HGS health",
    reboot: "Restart Windows",
  },
  reasons: {
    fresh_workgroup_node_required:
      "Initial provisioning requires a fresh workgroup VM. Existing domain membership will not be adopted or removed.",
    hgs_configuration_mismatch:
      "The existing HGS service name or certificate bindings differ from this plan.",
    fresh_inspection_required:
      "Run a fresh read-only inspection before reviewing recovery.",
    interrupted_step_not_proven:
      "The current evidence does not prove that the interrupted step completed. Writes remain blocked.",
    active_windows_agent_required:
      "An active enrolled Windows Agent is required.",
    unsupported_windows_version:
      "Windows Server 2022 or 2025 is required for this provider.",
    agent_update_required:
      "Update the Windows Agent to a version supporting HGS.",
    agent_unavailable: "The Agent has not sent a current heartbeat.",
    node_identity_changed:
      "The observed node identity differs from the reviewed target.",
    different_domain_membership:
      "This node belongs to a different domain. It will not be removed automatically.",
    attestation_mode_mismatch:
      "The existing HGS uses a different attestation mode.",
    certificate_private_key_unavailable:
      "The selected certificates and usable private keys must be present on this node.",
    offline_feature_source_unavailable:
      "The approved local feature source or offline installation policy is unavailable.",
    dsrm_secret_unavailable: "The local DSRM secret reference is unavailable.",
    join_secret_unavailable:
      "The local domain-join secret reference is unavailable.",
    provider_unavailable: "The required HGS provider is unavailable.",
    planned_reboot_not_authorized:
      "This installation requires planned reboots. Create a plan that explicitly authorizes them.",
    agent_version_unsupported: "Update this Agent to a version supporting HGS.",
    hgs_capability_missing: "This Agent does not advertise the HGS provider.",
    agent_offline: "The Agent is offline.",
    windows_required: "A supported Windows Server node is required.",
    domain_joined:
      "The new-forest workflow requires a node outside an existing domain.",
    secret_missing: "A required local secret reference is unavailable.",
    certificate_missing:
      "A required certificate or usable private key is unavailable.",
    reboot_required: "Complete the pending Windows reboot before proceeding.",
  },
};
const de: typeof en = {
  navigation: "Host Guardian Service",
  security: "Sicherheit",
  title: "Host Guardian Service",
  description:
    "Plane und installiere HGS auf vorhandenen Windows-VMs mit Agent in einem eigenen Mandanten.",
  singleAppliance:
    "Eine IPMS-Appliance unterstützt HGS- und Infrastruktur-Mandanten.",
  boundary:
    "HGS läuft auf den Windows-Knoten. Nach der Einrichtung kontaktiert Hyper-V HGS direkt zur Attestierung und Schlüsselfreigabe. Privilegierte Appliance-Administratoren bleiben für beide Mandanten vertrauenswürdig.",
  tenantRequired:
    "Verwende einen separaten Mandanten mit dem Zweck „Nur Host Guardian Service“. Wähle diesen Mandanten oben aus. Ein Plattformadministrator kann ihn auf dieser Appliance anlegen; eine zweite Appliance ist nicht erforderlich.",
  unavailable:
    "HGS-Daten sind nicht verfügbar oder passen nicht zu diesem Mandanten. Aktualisiere sie vor einer Aktion.",
  refresh: "Aktualisieren",
  newPlan: "Neuer Bereitstellungsplan",
  deployments: "Bereitstellungspläne",
  empty: "Noch keine HGS-Bereitstellungspläne vorhanden.",
  create: "Plan erstellen",
  created:
    "Der Plan wurde erstellt. Prüfe die Knoten vor der Ausführungsfreigabe.",
  name: "Name der Bereitstellung",
  profile: "VM-Schutzprofil",
  profiles: { vtpm: "Einfach: vTPM", shielded: "Sicher: Shielded VMs" },
  profileHelp:
    "Dies richtet HGS für das gewählte Profil ein. Host-Zulassung, VM-Shielding und Gastverschlüsselung sind separate Vorgänge; bestehende VMs werden nicht geändert.",
  attestation: "Host-Attestierung",
  modes: {
    host_key: "Host-Key-Attestierung",
    tpm: "TPM-basierte Attestierung",
  },
  attestationHelp:
    "Shielded VMs benötigen TPM-basierte Attestierung. Ein TPM-attestierter HGS kann beide Profile bedienen. Ein bestehender Verbund wechselt seinen Modus niemals automatisch.",
  domain: "DNS-Name des neuen HGS-Forests",
  service: "HGS-Dienstname",
  featureSource: "Lokale Quelle der Windows-Features",
  sourceHelp:
    "Verwende die freigegebene Feature-Quelle, die bereits auf jedem Knoten liegt. Die Installation bleibt innerhalb der Air-Gap-Umgebung.",
  sourceInvalid:
    "Verwende einen absoluten lokalen Windows-Pfad mit höchstens 240 Zeichen. Netzwerkpfade, übergeordnete Verzeichnisse, alternative Datenströme und Skriptzeichen sind nicht zulässig.",
  signing: "Fingerabdruck des Signaturzertifikats",
  encryption: "Fingerabdruck des Verschlüsselungszertifikats",
  certificatesHelp:
    "Die zugehörigen Zertifikate und nutzbaren privaten Schlüssel müssen bereits auf jedem ausgewählten Knoten verfügbar sein.",
  dsrm: "Lokale DSRM-Geheimnisreferenz",
  join: "Lokale Geheimnisreferenz für den Domänenbeitritt",
  secretHelp:
    "Gib Referenznamen lokal geschützter Geheimnisse ein, niemals Passwörter oder private Schlüssel.",
  primaryServer: "IP-Adresse des primären HGS-Knotens",
  primaryHelp:
    "Bei zusätzlichen Knoten erforderlich. Gib die IP-Adresse des primären Windows-Knotens ein, nicht die Appliance-Adresse.",
  nodes: "HGS-Knoten",
  nodesHelp:
    "Wähle vorhandene Windows-VMs mit eingebundenem Agent. Der zuerst gewählte Knoten erstellt den neuen Forest; weitere Knoten treten ihm bei. Beginne mit einem Laborknoten; für produktive Verfügbarkeit sollten mindestens drei Knoten eingesetzt werden.",
  noSystems:
    "In diesem Mandanten sind keine Windows-Knoten eingebunden. Installiere und registriere zunächst ihre Agents.",
  agent: "Agent",
  primary: "Primärer Knoten",
  additional: "Zusätzlicher Knoten",
  selection: "Gewählte Reihenfolge",
  allowReboot: "Geplante Windows-Neustarts als Teil der Ausführung freigeben",
  readOnly:
    "Dein Konto kann HGS-Pläne anzeigen. Ein Mandantenadministrator muss sie erstellen und ausführen.",
  plan: "Planprüfung",
  digest: "Plan-Prüfsumme",
  expires: "Plan läuft ab",
  approvalExpires: "Ausführungsfreigabe läuft ab",
  noApproval: "Nicht freigegeben",
  observed: "Letzte Knotenprüfung",
  noObservation: "Noch nicht geprüft",
  status: "Status",
  operation: "Vorgang",
  target: "Zielknoten",
  change: "Ändert das System",
  reboot: "Geplanter Neustart",
  yes: "Ja",
  no: "Nein",
  steps: "Geplante Schritte",
  jobs: "Aufträge",
  noJobs: "Es wurden noch keine Aufträge übermittelt.",
  result: "Ergebnis",
  inspect: "Knoten prüfen",
  inspectionQueued:
    "Die Knotenprüfung wurde angefordert. Agent-Nachweise stehen noch aus.",
  execute: "Plan freigeben und ausführen",
  executionQueued:
    "Die Ausführung dieses konkreten Plans wurde freigegeben. Verfolge die protokollierten Auftragsergebnisse.",
  review:
    "Ich habe diese Ziele, Aktionen, Zertifikats- und Geheimnisreferenzen sowie die geplanten Neustarts geprüft.",
  cancel: "Neue Arbeit stoppen",
  cancelHelp:
    "Das Stoppen verhindert neue Arbeit. Ein bereits gestarteter Windows-Vorgang wird dadurch nicht rückgängig gemacht.",
  stopped: "Die Anforderung zum Stoppen neuer Arbeit wurde erfasst.",
  reconcile: "Bestand zur Klärung prüfen",
  resolve: "Bestätigten Zustand übernehmen und fortsetzen",
  recoveryReview:
    "Ich habe die aktuellen Nachweise geprüft. Den bestätigten Zustand des unterbrochenen Schritts übernehmen und ausschließlich nachfolgende Schritte freigeben.",
  recoveryEvidence: "Prüfsumme des bestätigten Nachweises",
  resolved:
    "Der bestätigte Zustand wurde übernommen. Nachfolgende Schritte können fortgesetzt werden; die unterbrochene Änderung wurde nicht wiederholt.",
  reconciliation:
    "Das bisherige Ergebnis muss geklärt werden. Eine neue Bestandsprüfung erlaubt keine Wiederholung von Änderungen. Wenn sie den Abschluss des unterbrochenen Schritts belegt, prüfe und übernimm diesen Zustand vor der Fortsetzung nachfolgender Schritte.",
  reconciled:
    "Eine neue lesende Bestandsprüfung wurde angefordert. Es wurde keine Änderung wiederholt.",
  expired:
    "Dieser Plan ist abgelaufen. Erstelle einen neuen Plan und prüfe aktuelle Knotennachweise.",
  stale:
    "Die Ausführung benötigt für jeden Knoten eine erfolgreiche Prüfung der letzten 30 Minuten.",
  blocked: "Behebe die gemeldeten Voraussetzungen vor der Ausführung.",
  uncertain:
    "Das Anfrageergebnis ist unklar. Aktualisiere die Pläne und prüfe den erfassten Zustand vor weiteren Aktionen. Die Anfrage wird nicht automatisch wiederholt.",
  failed:
    "Die Anfrage konnte nicht abgeschlossen werden. Aktualisiere und prüfe den aktuellen Plan.",
  invalid: "Prüfe die eingegebenen Werte und ausgewählten Knoten.",
  forbidden: "Du bist für diesen HGS-Vorgang nicht berechtigt.",
  changed:
    "Der Plan oder der beobachtete Zustand hat sich geändert. Prüfe die Knoten und den aktuellen Plan erneut.",
  unknown: "Unbekannt",
  states: {
    draft: "Entwurf",
    inspecting: "Knoten werden geprüft",
    blocked: "Blockiert",
    ready: "Bereit zur Prüfung",
    running: "Wird ausgeführt",
    waiting_for_reboot: "Wartet auf Neustart",
    succeeded: "Abgeschlossen",
    failed: "Fehlgeschlagen",
    cancelled: "Gestoppt",
    reconciliation_required: "Klärung erforderlich",
    pending: "Ausstehend",
    queued: "Eingereiht",
    claimed: "Übernommen",
    offered: "Dem Agent angeboten",
    dispatched: "Übermittelt",
    completed: "Abgeschlossen",
    unavailable: "Nicht verfügbar",
    not_started: "Nicht begonnen",
    inspected: "Geprüft",
    verified: "Verifiziert",
  },
  operations: {
    inspect: "Bereitschaft prüfen",
    readiness: "Bereitschaft prüfen",
    install_role: "HGS-Rolle installieren",
    create_forest: "Eigenen HGS-Forest erstellen",
    join_node: "HGS-Forest beitreten",
    initialize: "HGS initialisieren",
    initialize_hgs: "HGS initialisieren",
    verify: "HGS-Funktion prüfen",
    reboot: "Windows neu starten",
  },
  reasons: {
    fresh_workgroup_node_required:
      "Die Ersteinrichtung benötigt eine frische VM in einer Arbeitsgruppe. Eine bestehende Domänenmitgliedschaft wird weder übernommen noch entfernt.",
    hgs_configuration_mismatch:
      "Der vorhandene HGS-Dienstname oder seine Zertifikatsbindungen weichen von diesem Plan ab.",
    fresh_inspection_required:
      "Führe vor der Wiederaufnahme eine neue lesende Bestandsprüfung durch.",
    interrupted_step_not_proven:
      "Die aktuellen Nachweise belegen den Abschluss des unterbrochenen Schritts nicht. Änderungen bleiben blockiert.",
    active_windows_agent_required:
      "Ein aktiver eingebundener Windows-Agent ist erforderlich.",
    unsupported_windows_version:
      "Dieser Provider benötigt Windows Server 2022 oder 2025.",
    agent_update_required:
      "Aktualisiere den Windows-Agent auf eine Version mit HGS-Unterstützung.",
    agent_unavailable: "Der Agent hat kein aktuelles Lebenszeichen gesendet.",
    node_identity_changed:
      "Die beobachtete Knotenidentität weicht vom geprüften Ziel ab.",
    different_domain_membership:
      "Dieser Knoten gehört zu einer anderen Domäne. Er wird nicht automatisch daraus entfernt.",
    attestation_mode_mismatch:
      "Der vorhandene HGS verwendet einen anderen Attestierungsmodus.",
    certificate_private_key_unavailable:
      "Die gewählten Zertifikate und nutzbaren privaten Schlüssel müssen auf diesem Knoten vorhanden sein.",
    offline_feature_source_unavailable:
      "Die freigegebene lokale Feature-Quelle oder die Richtlinie für Offline-Installation ist nicht verfügbar.",
    dsrm_secret_unavailable:
      "Die lokale DSRM-Geheimnisreferenz ist nicht verfügbar.",
    join_secret_unavailable:
      "Die lokale Geheimnisreferenz für den Domänenbeitritt ist nicht verfügbar.",
    provider_unavailable: "Der benötigte HGS-Provider ist nicht verfügbar.",
    planned_reboot_not_authorized:
      "Diese Installation benötigt geplante Neustarts. Erstelle einen Plan, der sie ausdrücklich freigibt.",
    agent_version_unsupported:
      "Aktualisiere diesen Agent auf eine Version mit HGS-Unterstützung.",
    hgs_capability_missing: "Dieser Agent meldet keinen HGS-Provider.",
    agent_offline: "Der Agent ist offline.",
    windows_required:
      "Ein unterstützter Windows-Server-Knoten ist erforderlich.",
    domain_joined:
      "Der Ablauf für einen neuen Forest benötigt einen Knoten außerhalb einer bestehenden Domäne.",
    secret_missing:
      "Eine erforderliche lokale Geheimnisreferenz ist nicht verfügbar.",
    certificate_missing:
      "Ein erforderliches Zertifikat oder ein nutzbarer privater Schlüssel ist nicht verfügbar.",
    reboot_required:
      "Führe den ausstehenden Windows-Neustart vor dem Fortfahren durch.",
  },
};
export type HgsCopy = typeof en;
export const getHgsCopy = (locale: Locale): HgsCopy =>
  locale === "de" ? de : en;
export const hgsLabel = (values: Record<string, string>, code: string) =>
  values[code] ?? code;
