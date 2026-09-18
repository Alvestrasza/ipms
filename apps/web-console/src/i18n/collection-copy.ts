/**
 * File Name: collection-copy.ts
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Localize Device and Policy Collection workflows.
 */
import type { Locale } from "./config";

const en = {
  navigation: "Collections",
  deviceNavigation: "Device Collections",
  policyNavigation: "Policy Collections",
  deviceTitle: "Device Collections",
  deviceDescription:
    "Group managed Windows systems through direct membership and inventory rules.",
  policyTitle: "Policy Collections",
  policyDescription:
    "Combine ordered GPO policies and deploy them to configured targets in multiple domains.",
  newDevice: "New Device Collection",
  newPolicy: "New Policy Collection",
  name: "Name",
  description: "Description",
  save: "Save collection",
  update: "Update collection",
  cancel: "Cancel editing",
  edit: "Edit",
  delete: "Delete",
  memberCount: "Members",
  directMembers: "Direct members",
  rules: "Inventory rules",
  addRule: "Add rule",
  remove: "Remove",
  hostnameContains: "Hostname contains",
  anyDomain: "Domain name",
  serverType: "Server type",
  role: "Operating system role",
  family: "Operating system family",
  orderedPolicies: "Ordered policies",
  addPolicy: "Add policy",
  moveUp: "Move up",
  moveDown: "Move down",
  source: "Source",
  baseline: "Baseline",
  override: "Override",
  component: "GPO component",
  targetAlias: "Target alias",
  version: "Version",
  domainBindings: "Domain targets",
  addDomain: "Add domain",
  tier: "Tier",
  targetOus: "Link targets",
  preview: "Deployment preview",
  refreshPreview: "Refresh preview",
  deploy: "Deploy collection",
  ready: "Ready",
  blocked: "Blocked",
  executor: "Domain controller",
  deployments: "Recent deployments",
  noCollections: "No collection has been created yet.",
  noDomains: "Configure at least one domain and its tier targets first.",
  unavailable: "Collection data could not be loaded.",
  saved: "Collection saved.",
  deleted: "Collection deleted.",
  submitted:
    "Deployment started. Each domain progresses independently in the configured policy order.",
  uncertain:
    "The request result is uncertain. Reload the collection before repeating the action.",
  rootHint:
    "The domain root is available only for Tier 0 and must be selected alone.",
  activationHint:
    "This rollout imports and links each GPO with disabled settings. Activation remains a separate approved action in Windows GPOs.",
  errors: {
    invalid_request:
      "Check the collection name, policy entries, domains, tiers and link targets.",
    forbidden:
      "Your account is not permitted to manage Collections in this tenant.",
    security_collection_device_unavailable:
      "At least one selected device no longer belongs to this tenant. Reload the page and select the members again.",
    security_collection_policy_unavailable:
      "At least one selected baseline or override is no longer available. Reload the page and select it again.",
    security_collection_domain_unavailable:
      "At least one selected domain is no longer available in this tenant. Reload the page and select it again.",
    security_collection_target_unavailable:
      "At least one link target is no longer configured for the selected domain and tier. Update the Collection target.",
    security_collection_domain_root_required:
      "A domain-wide policy must target the Tier 0 domain root exclusively.",
    security_collection_name_exists:
      "A Collection with this name already exists.",
    security_collection_limit: "The tenant Collection limit has been reached.",
    security_collection_revision_changed:
      "The Collection changed after it was loaded. Reload it before saving or deploying.",
    security_collection_has_deployments:
      "This Policy Collection has deployment history and cannot be deleted.",
    security_collection_request_conflict:
      "This request identifier was already used for a different deployment.",
    security_collection_not_ready:
      "The deployment preview is blocked. Resolve the displayed domain, override or Agent condition first.",
    domain_revision_changed:
      "The domain configuration changed. Edit and save the Collection to confirm its current targets.",
    override_revision_changed:
      "The override changed. Edit and save the Collection to pin its current revision.",
    executor_unavailable:
      "No eligible current Windows Agent is available on a domain controller in this domain.",
    previous_policy_failed:
      "A preceding policy failed in this domain. Fix that item before retrying the domain.",
  },
  statuses: {
    queued: "Queued",
    preparing: "Preparing",
    running: "Running",
    awaiting_approval: "Awaiting approval",
    succeeded: "Succeeded",
    partial: "Partially succeeded",
    failed: "Failed",
    blocked: "Blocked",
    reconciliation_required: "Directory reconciliation required",
  },
};

const de: typeof en = {
  navigation: "Collections",
  deviceNavigation: "Device Collections",
  policyNavigation: "Policy Collections",
  deviceTitle: "Device Collections",
  deviceDescription:
    "Gruppiere verwaltete Windows-Systeme über direkte Mitgliedschaften und Inventarregeln.",
  policyTitle: "Policy Collections",
  policyDescription:
    "Kombiniere geordnete GPO-Richtlinien und verteile sie an konfigurierte Ziele in mehreren Domänen.",
  newDevice: "Neue Device Collection",
  newPolicy: "Neue Policy Collection",
  name: "Name",
  description: "Beschreibung",
  save: "Collection speichern",
  update: "Collection aktualisieren",
  cancel: "Bearbeitung abbrechen",
  edit: "Bearbeiten",
  delete: "Löschen",
  memberCount: "Mitglieder",
  directMembers: "Direkte Mitglieder",
  rules: "Inventarregeln",
  addRule: "Regel hinzufügen",
  remove: "Entfernen",
  hostnameContains: "Hostname enthält",
  anyDomain: "Domänenname",
  serverType: "Systemtyp",
  role: "Betriebssystemrolle",
  family: "Betriebssystemfamilie",
  orderedPolicies: "Geordnete Richtlinien",
  addPolicy: "Richtlinie hinzufügen",
  moveUp: "Nach oben",
  moveDown: "Nach unten",
  source: "Quelle",
  baseline: "Baseline",
  override: "Override",
  component: "GPO-Komponente",
  targetAlias: "Zielkürzel",
  version: "Version",
  domainBindings: "Domänenziele",
  addDomain: "Domäne hinzufügen",
  tier: "Tier",
  targetOus: "Verknüpfungsziele",
  preview: "Bereitstellungsvorschau",
  refreshPreview: "Vorschau aktualisieren",
  deploy: "Collection bereitstellen",
  ready: "Bereit",
  blocked: "Blockiert",
  executor: "Domain Controller",
  deployments: "Letzte Bereitstellungen",
  noCollections: "Es wurde noch keine Collection erstellt.",
  noDomains:
    "Konfiguriere zuerst mindestens eine Domäne mit ihren Tier-Zielen.",
  unavailable: "Die Collection-Daten konnten nicht geladen werden.",
  saved: "Collection gespeichert.",
  deleted: "Collection gelöscht.",
  submitted:
    "Die Bereitstellung wurde gestartet. Jede Domäne arbeitet die konfigurierte Richtlinienreihenfolge unabhängig ab.",
  uncertain:
    "Das Ergebnis der Anfrage ist unklar. Lade die Collection vor einer Wiederholung neu.",
  rootHint:
    "Die Domänenwurzel ist ausschließlich in Tier 0 und nur als alleiniges Ziel zulässig.",
  activationHint:
    "Diese Bereitstellung importiert und verknüpft jede GPO mit deaktivierten Einstellungen. Die Aktivierung bleibt eine getrennt freizugebende Aktion unter Windows GPOs.",
  errors: {
    invalid_request:
      "Prüfe den Namen, die Richtlinien, Domänen, Tiers und Verknüpfungsziele der Collection.",
    forbidden:
      "Dein Konto darf Collections in diesem Mandanten nicht verwalten.",
    security_collection_device_unavailable:
      "Mindestens ein gewähltes System gehört nicht mehr zu diesem Mandanten. Lade die Seite neu und wähle die Mitglieder erneut.",
    security_collection_policy_unavailable:
      "Mindestens eine gewählte Baseline oder ein Override ist nicht mehr verfügbar. Lade die Seite neu und wähle den Eintrag erneut.",
    security_collection_domain_unavailable:
      "Mindestens eine gewählte Domäne ist in diesem Mandanten nicht mehr verfügbar. Lade die Seite neu und wähle sie erneut.",
    security_collection_target_unavailable:
      "Mindestens ein Verknüpfungsziel ist für die gewählte Domäne und das Tier nicht mehr konfiguriert. Passe das Ziel der Collection an.",
    security_collection_domain_root_required:
      "Eine domänenweite Richtlinie muss ausschließlich mit der Tier-0-Domänenwurzel verknüpft werden.",
    security_collection_name_exists:
      "Eine Collection mit diesem Namen existiert bereits.",
    security_collection_limit:
      "Das Collection-Limit des Mandanten ist erreicht.",
    security_collection_revision_changed:
      "Die Collection wurde nach dem Laden geändert. Lade sie vor dem Speichern oder Bereitstellen neu.",
    security_collection_has_deployments:
      "Diese Policy Collection besitzt eine Bereitstellungshistorie und kann deshalb nicht gelöscht werden.",
    security_collection_request_conflict:
      "Diese Auftragskennung wurde bereits für eine andere Bereitstellung verwendet.",
    security_collection_not_ready:
      "Die Bereitstellungsvorschau ist blockiert. Behebe zuerst die angezeigte Domänen-, Override- oder Agent-Bedingung.",
    domain_revision_changed:
      "Die Domänenkonfiguration wurde geändert. Bearbeite und speichere die Collection, um die aktuellen Ziele zu bestätigen.",
    override_revision_changed:
      "Der Override wurde geändert. Bearbeite und speichere die Collection, um seine aktuelle Revision zu übernehmen.",
    executor_unavailable:
      "In dieser Domäne ist kein berechtigter Domain Controller mit aktuellem Windows Agent verfügbar.",
    previous_policy_failed:
      "Eine vorherige Richtlinie ist in dieser Domäne fehlgeschlagen. Behebe diesen Eintrag vor einer erneuten Bereitstellung.",
  },
  statuses: {
    queued: "Wartet",
    preparing: "Wird vorbereitet",
    running: "Läuft",
    awaiting_approval: "Wartet auf Freigabe",
    succeeded: "Erfolgreich",
    partial: "Teilweise erfolgreich",
    failed: "Fehlgeschlagen",
    blocked: "Blockiert",
    reconciliation_required: "Verzeichnisabgleich erforderlich",
  },
};

export type CollectionCopy = typeof en;
export const getCollectionCopy = (locale: Locale): CollectionCopy =>
  locale === "de" ? de : en;

export function collectionApiError(
  payload: unknown,
  copy: CollectionCopy,
): string {
  if (
    typeof payload === "object" &&
    payload !== null &&
    "error" in payload &&
    typeof payload.error === "object" &&
    payload.error !== null &&
    "code" in payload.error &&
    typeof payload.error.code === "string"
  ) {
    return (
      copy.errors[payload.error.code as keyof typeof copy.errors] ??
      copy.uncertain
    );
  }
  return copy.uncertain;
}

export function collectionStatus(value: string, copy: CollectionCopy): string {
  return copy.statuses[value as keyof typeof copy.statuses] ?? value;
}

export function collectionCondition(
  value: string | null,
  copy: CollectionCopy,
): string {
  return value ? (copy.errors[value as keyof typeof copy.errors] ?? value) : "";
}
