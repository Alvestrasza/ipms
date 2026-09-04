import { HardDrive } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import type { LinuxSystem } from "@/lib/server-linux";

export function LinuxSystemInventory({
  systems,
  systemType,
  locale,
  copy,
}: {
  systems: LinuxSystem[];
  systemType: "physical" | "virtual";
  locale: "de" | "en";
  copy: {
    inventory: string;
    fqdn: string;
    operatingSystem: string;
    kernel: string;
    cpu: string;
    memory: string;
    agentVersion: string;
    lastSeen: string;
    noSystems: string;
  };
}) {
  const date = new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  });
  return (
    <section className="panel inventory-panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Linux</p>
          <h2>{copy.inventory}</h2>
        </div>
        <span className="panel__metric">
          <strong>{systems.length}</strong>
        </span>
      </div>
      {systems.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>{copy.fqdn}</th>
                <th>{copy.operatingSystem}</th>
                <th>{copy.kernel}</th>
                <th>{copy.cpu}</th>
                <th>{copy.memory}</th>
                <th>{copy.agentVersion}</th>
                <th>{copy.lastSeen}</th>
              </tr>
            </thead>
            <tbody>
              {systems.map((system) => (
                <tr key={system.id}>
                  <td>
                    <Link
                      className="connector-detail-link"
                      href={
                        `/${locale}/${systemType === "physical" ? "physical/linux" : "virtual/linux"}/${system.id}` as Route
                      }
                    >
                      <strong>{system.fqdn || system.hostname}</strong>
                    </Link>
                  </td>
                  <td>
                    {system.distribution} {system.distribution_version}
                  </td>
                  <td>{system.kernel_version}</td>
                  <td>{system.logical_processors}</td>
                  <td>{(system.memory_bytes / 1024 ** 3).toFixed(1)} GiB</td>
                  <td>v{system.agent_version}</td>
                  <td>{date.format(new Date(system.last_seen_at))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <HardDrive aria-hidden="true" size={25} />
          <strong>{copy.noSystems}</strong>
        </div>
      )}
    </section>
  );
}
