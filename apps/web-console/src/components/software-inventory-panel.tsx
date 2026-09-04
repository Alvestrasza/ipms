import { PackageSearch, RotateCw } from "lucide-react";

import type { SoftwarePackage, SoftwareSnapshot } from "@/lib/server-software";

export type SoftwareInventoryCopy = {
  eyebrow: string;
  heading: string;
  packages: string;
  updates: string;
  rebootRequired: string;
  rebootNotRequired: string;
  scanCurrent: string;
  scanUpdates: string;
  scanUnknown: string;
  scanUnavailable: string;
  name: string;
  installedVersion: string;
  availableVersion: string;
  publisher: string;
  type: string;
  state: string;
  current: string;
  updateAvailable: string;
  unknown: string;
  lastUpdateScan: string;
  lastUpdateInstall: string;
  never: string;
  noInventory: string;
};

export function SoftwareInventoryPanel({
  copy,
  locale,
  snapshot,
  packages,
}: {
  copy: SoftwareInventoryCopy;
  locale: "de" | "en";
  snapshot: SoftwareSnapshot | null;
  packages: SoftwarePackage[];
}) {
  if (!snapshot) {
    return (
      <section className="panel empty-state">
        <PackageSearch aria-hidden="true" size={25} />
        <strong>{copy.heading}</strong>
        <span>{copy.noInventory}</span>
      </section>
    );
  }
  const stateLabels = {
    current: copy.current,
    "update-available": copy.updateAvailable,
    unknown: copy.unknown,
  };
  const scanLabels = {
    current: copy.scanCurrent,
    "updates-available": copy.scanUpdates,
    unknown: copy.scanUnknown,
    unavailable: copy.scanUnavailable,
  };
  return (
    <section
      className="panel inventory-panel"
      aria-labelledby="software-inventory-heading"
    >
      <div className="panel__header">
        <div>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h2 id="software-inventory-heading">{copy.heading}</h2>
        </div>
        <span className="panel__metric">
          <strong>{snapshot.package_count}</strong> {copy.packages} ·{" "}
          {snapshot.updates_available} {copy.updates}
        </span>
      </div>
      <div className="security-note">
        <RotateCw aria-hidden="true" size={18} />
        <span>
          {scanLabels[snapshot.update_scan_status]} ·{" "}
          {snapshot.reboot_required
            ? copy.rebootRequired
            : copy.rebootNotRequired}
        </span>
      </div>
      <dl className="detail-list detail-list--compact">
        <div>
          <dt>{copy.lastUpdateScan}</dt>
          <dd>
            {snapshot.last_update_scan_at
              ? new Intl.DateTimeFormat(locale, {
                  dateStyle: "medium",
                  timeStyle: "medium",
                }).format(new Date(snapshot.last_update_scan_at))
              : copy.never}
          </dd>
        </div>
        <div>
          <dt>{copy.lastUpdateInstall}</dt>
          <dd>
            {snapshot.last_update_install_at
              ? new Intl.DateTimeFormat(locale, {
                  dateStyle: "medium",
                  timeStyle: "medium",
                }).format(new Date(snapshot.last_update_install_at))
              : copy.never}
          </dd>
        </div>
      </dl>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>{copy.name}</th>
              <th>{copy.installedVersion}</th>
              <th>{copy.availableVersion}</th>
              <th>{copy.publisher}</th>
              <th>{copy.type}</th>
              <th>{copy.state}</th>
            </tr>
          </thead>
          <tbody>
            {packages.map((item) => (
              <tr key={item.id}>
                <td>
                  <strong>{item.name}</strong>
                </td>
                <td>{item.installed_version || "—"}</td>
                <td>{item.available_version || "—"}</td>
                <td>{item.publisher || "—"}</td>
                <td>{item.package_type}</td>
                <td>{stateLabels[item.update_state]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
