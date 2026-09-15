/**
 * File Name: gpo-approval-copy.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Explain explicit central approval, its scopes and the immutable import review.
 */
import type { Locale } from "./config";

const en = {
  policyTitle: "GPO approval policy",
  policyDescription:
    "These approval rules apply to every configured domain in the selected tenant.",
  fourEyes: "Require a second administrator",
  fourEyesHint:
    "When enabled, the requester cannot approve his own import. Both administrators need an explicit authorization for the domain and Tier. There is no exception for a single administrator.",
  selfApprovalHint:
    "When disabled, an authorized tenant administrator may request and approve his own import. Domain and Tier authorization is still required.",
  invalidationHint:
    "Saving changed approval rules or authorizations invalidates pending imports. Review and request them again under the new rules.",
  savePolicy: "Save approval policy",
  savedPolicy:
    "Approval policy saved. Pending imports affected by the change must be requested again.",
  authorizationTitle: "GPO authorization by domain and Tier",
  authorizationHint:
    "Select each administrator and Tier explicitly. Tenant administrators may request and approve; approvers may only approve. Empty selections authorize nobody.",
  saveAuthorization: "Save GPO authorizations",
  savedAuthorization:
    "GPO authorizations saved. Pending imports affected by the change must be requested again.",
  noMembers: "No eligible tenant administrators or approvers are available.",
  inactiveMember: "Unavailable member",
  tenantAdmin: "Tenant administrator: request and approve",
  approver: "Approver: approve only",
  loading: "Loading approval settings…",
  unavailable: "Approval settings could not be loaded. Reload before editing.",
  invalid:
    "The approval settings were rejected. Reload and check the selected administrators and Tiers.",
  conflict:
    "Approval settings changed in another session. Your draft is retained. Reload before saving again.",
  uncertain:
    "The result could not be confirmed. Reload the saved settings before another attempt.",
  permission: "Your current tenant permissions do not allow this action.",
  sessionExpired: "Your session has expired. Sign in again.",
  reload: "Reload approval settings",
  discard: "Discard authorization changes",
  saving: "Saving…",
  revision: "Approval revision",
  centralTitle: "Review and approve GPO import",
  legacyTitle: "Legacy local approval",
  legacyHint:
    "This older request uses local approval and cannot be approved centrally. A new centrally approved request is required to use the Portal workflow.",
  centralHint:
    "Approval permits only the displayed import: one separate GPO, unlinked and with Computer and User settings disabled. It does not link, activate or apply the baseline.",
  approved:
    "Action approved. The Agent can collect this exact request; its execution result will appear in Logs.",
  approve: "Approve this GPO action",
  approving: "Approving…",
  refreshReview: "Reload action review",
  reviewUnavailable:
    "The authorized import review is unavailable. Reload before approving.",
  reviewInvalidated:
    "The import or your authorization changed. The previous preview has been cleared. Reload and review the current request.",
  approvalUncertain:
    "The approval result could not be confirmed. The previous preview has been cleared. Reload the request before another attempt.",
  reviewReport: "Exact GPO settings report (XML)",
  reviewDocument: "Immutable import document",
  files: "Verified import files",
  file: "File",
  bytes: "Bytes",
  hash: "SHA-256",
  inputDigest: "Import digest",
  expires: "Expires (UTC)",
  requestedBy: "Requested by",
  approvedBy: "Approved by",
  approvedAt: "Approved (UTC)",
  dc: "Target domain controller",
  component: "GPO component",
  fourEyesRequired: "Second administrator required",
  selfApprovalAllowed: "Self-approval allowed with authorization",
  awaitingPortal: "Awaiting Portal approval",
  approvedWaiting: "Approved; awaiting Agent",
  awaitingLocal: "Awaiting local approval",
  blockers: {
    four_eyes_required:
      "A different authorized administrator must approve this request.",
    authorization_required:
      "You need an explicit authorization for this domain and Tier.",
    policy_changed:
      "The approval policy changed. Request a new import under the current rules.",
    expired: "This request expired. A new import request is required.",
    legacy_local: "Legacy local requests cannot be approved in the Portal.",
    unavailable:
      "This request is not available for approval. Reload its current status.",
  },
};
export type GpoApprovalCopy = typeof en;
const de: GpoApprovalCopy = {
  policyTitle: "GPO-Freigaberichtlinie",
  policyDescription:
    "Diese Freigaberegeln gelten für alle konfigurierten Domänen des ausgewählten Tenants.",
  fourEyes: "Zweiten Administrator für die Freigabe verlangen",
  fourEyesHint:
    "Wenn aktiviert, darf der Antragsteller seinen Import nicht selbst freigeben. Beide Administratoren benötigen eine ausdrückliche Berechtigung für Domäne und Tier. Für einen einzelnen Administrator gibt es keine Ausnahme.",
  selfApprovalHint:
    "Wenn deaktiviert, darf ein berechtigter Tenant-Administrator seinen eigenen Import anfordern und freigeben. Die Berechtigung für Domäne und Tier bleibt erforderlich.",
  invalidationHint:
    "Geänderte Freigaberegeln oder Berechtigungen machen ausstehende Importe ungültig. Diese müssen unter den neuen Regeln erneut geprüft und angefordert werden.",
  savePolicy: "Freigaberichtlinie speichern",
  savedPolicy:
    "Freigaberichtlinie gespeichert. Betroffene ausstehende Importe müssen erneut angefordert werden.",
  authorizationTitle: "GPO-Berechtigung je Domäne und Tier",
  authorizationHint:
    "Jeden Administrator und Tier ausdrücklich auswählen. Tenant-Administratoren dürfen anfordern und freigeben; Freigeber dürfen nur freigeben. Eine leere Auswahl berechtigt niemanden.",
  saveAuthorization: "GPO-Berechtigungen speichern",
  savedAuthorization:
    "GPO-Berechtigungen gespeichert. Betroffene ausstehende Importe müssen erneut angefordert werden.",
  noMembers:
    "Es stehen keine geeigneten Tenant-Administratoren oder Freigeber zur Verfügung.",
  inactiveMember: "Nicht verfügbarer Benutzer",
  tenantAdmin: "Tenant-Administrator: anfordern und freigeben",
  approver: "Freigeber: nur freigeben",
  loading: "Freigabeeinstellungen werden geladen…",
  unavailable:
    "Die Freigabeeinstellungen konnten nicht geladen werden. Vor dem Bearbeiten erneut laden.",
  invalid:
    "Die Freigabeeinstellungen wurden abgelehnt. Bitte erneut laden und Administratoren sowie Tiers prüfen.",
  conflict:
    "Die Freigabeeinstellungen wurden zwischenzeitlich geändert. Der Entwurf bleibt erhalten. Vor dem Speichern erneut laden.",
  uncertain:
    "Das Ergebnis konnte nicht bestätigt werden. Vor einem weiteren Versuch die gespeicherten Einstellungen neu laden.",
  permission:
    "Die aktuellen Tenant-Berechtigungen erlauben diese Aktion nicht.",
  sessionExpired: "Die Sitzung ist abgelaufen. Bitte erneut anmelden.",
  reload: "Freigabeeinstellungen neu laden",
  discard: "Berechtigungsänderungen verwerfen",
  saving: "Wird gespeichert…",
  revision: "Freigaberevision",
  centralTitle: "GPO-Import prüfen und freigeben",
  legacyTitle: "Bestehende lokale Freigabe",
  legacyHint:
    "Dieser ältere Auftrag verwendet die lokale Freigabe und kann nicht zentral freigegeben werden. Für den Portal-Ablauf muss ein neuer Auftrag mit zentraler Freigabe erstellt werden.",
  centralHint:
    "Die Freigabe erlaubt ausschließlich den angezeigten Import: eine separate GPO ohne Verknüpfung und mit deaktivierten Computer- und Benutzereinstellungen. Sie verknüpft, aktiviert oder wendet die Baseline nicht an.",
  approved:
    "Aktion freigegeben. Der Agent kann genau diesen Auftrag übernehmen; das Ausführungsergebnis erscheint in Logs.",
  approve: "Diese GPO-Aktion freigeben",
  approving: "Wird freigegeben…",
  refreshReview: "Auftragsprüfung neu laden",
  reviewUnavailable:
    "Die berechtigte Importvorschau ist nicht verfügbar. Vor einer Freigabe erneut laden.",
  reviewInvalidated:
    "Der Import oder die Berechtigung wurde geändert. Die vorherige Vorschau wurde entfernt. Bitte erneut laden und den aktuellen Auftrag prüfen.",
  approvalUncertain:
    "Das Freigabeergebnis konnte nicht bestätigt werden. Die vorherige Vorschau wurde entfernt. Vor einem weiteren Versuch den Auftrag neu laden.",
  reviewReport: "Exakter GPO-Einstellungsbericht (XML)",
  reviewDocument: "Unveränderliches Importdokument",
  files: "Geprüfte Importdateien",
  file: "Datei",
  bytes: "Bytes",
  hash: "SHA-256",
  inputDigest: "Import-Prüfsumme",
  expires: "Läuft ab (UTC)",
  requestedBy: "Angefordert von",
  approvedBy: "Freigegeben von",
  approvedAt: "Freigegeben (UTC)",
  dc: "Ziel-Domain-Controller",
  component: "GPO-Komponente",
  fourEyesRequired: "Zweiter Administrator erforderlich",
  selfApprovalAllowed: "Eigene Freigabe mit Berechtigung erlaubt",
  awaitingPortal: "Portal-Freigabe ausstehend",
  approvedWaiting: "Freigegeben; wartet auf Agent",
  awaitingLocal: "Lokale Freigabe ausstehend",
  blockers: {
    four_eyes_required:
      "Ein anderer berechtigter Administrator muss diesen Auftrag freigeben.",
    authorization_required:
      "Für diese Domäne und diesen Tier ist eine ausdrückliche Berechtigung erforderlich.",
    policy_changed:
      "Die Freigaberichtlinie wurde geändert. Einen neuen Import unter den aktuellen Regeln anfordern.",
    expired:
      "Dieser Auftrag ist abgelaufen. Ein neuer Importauftrag ist erforderlich.",
    legacy_local:
      "Bestehende lokale Aufträge können nicht im Portal freigegeben werden.",
    unavailable:
      "Dieser Auftrag steht nicht zur Freigabe bereit. Bitte den aktuellen Stand neu laden.",
  },
};
export function getGpoApprovalCopy(locale: Locale): GpoApprovalCopy {
  return locale === "de" ? de : en;
}
