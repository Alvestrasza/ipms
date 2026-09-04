import { ArrowLeft, Cpu, HardDrive, Network } from "lucide-react";
import type { Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getLinuxSystem } from "@/lib/server-linux";
import { getSoftwareInventory } from "@/lib/server-software";
import { selectedTenant } from "@/lib/tenant-selection";
import { ConsoleShell } from "./console-shell";
import { SoftwareInventoryPanel } from "./software-inventory-panel";

export async function LinuxSystemPage({
  id,
  expectedType,
}: {
  id: string;
  expectedType: "physical" | "virtual";
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  const inventory = await getLinuxSystem(tenant.id, id);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);
  if (inventory.notFound || !inventory.system) notFound();
  if (inventory.system.system_type !== expectedType)
    redirect(
      `/${locale}/${inventory.system.system_type === "physical" ? "physical/linux" : "virtual/linux"}/${id}` as Route,
    );
  const system = inventory.system;
  const software = await getSoftwareInventory(tenant.id, system.source_id);
  const copy = dictionary.linuxSystems;
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection={
        expectedType === "physical" ? "physical-linux" : "virtual-linux"
      }
    >
      <Link
        className="detail-back-link"
        href={
          `/${locale}/${expectedType === "physical" ? "physical/linux" : "virtual/linux"}` as Route
        }
      >
        <ArrowLeft aria-hidden="true" size={16} />
        {copy.back}
      </Link>
      <section className="page-heading">
        <div>
          <p className="eyebrow">Linux</p>
          <h1>{system.fqdn || system.hostname}</h1>
          <p>
            {system.distribution} {system.distribution_version} ·{" "}
            {system.architecture}
          </p>
        </div>
        <span className="read-only-badge">Agent v{system.agent_version}</span>
      </section>
      <section className="summary-grid">
        <article className="summary-card">
          <div className="summary-card__icon">
            <Cpu size={21} />
          </div>
          <div>
            <p>{copy.cpu}</p>
            <strong>{system.logical_processors}</strong>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <HardDrive size={21} />
          </div>
          <div>
            <p>{copy.memory}</p>
            <strong>{(system.memory_bytes / 1024 ** 3).toFixed(1)} GiB</strong>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <Network size={21} />
          </div>
          <div>
            <p>{copy.interfaces}</p>
            <strong>{system.network_interfaces.length}</strong>
          </div>
        </article>
      </section>
      <section className="detail-grid">
        <article className="panel detail-card">
          <div className="panel__header">
            <h2>{copy.identity}</h2>
          </div>
          <dl className="detail-list">
            <div>
              <dt>{copy.manufacturer}</dt>
              <dd>{system.manufacturer || "—"}</dd>
            </div>
            <div>
              <dt>{copy.model}</dt>
              <dd>{system.model || "—"}</dd>
            </div>
            <div>
              <dt>{copy.serialNumber}</dt>
              <dd>{system.serial_number || "—"}</dd>
            </div>
            <div>
              <dt>{copy.kernel}</dt>
              <dd>{system.kernel_version || "—"}</dd>
            </div>
          </dl>
        </article>
        <article className="panel detail-card">
          <div className="panel__header">
            <h2>{copy.storage}</h2>
          </div>
          {system.fixed_volumes.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>{copy.volume}</th>
                    <th>{copy.filesystem}</th>
                    <th>{copy.capacity}</th>
                    <th>{copy.used}</th>
                  </tr>
                </thead>
                <tbody>
                  {system.fixed_volumes.map((volume) => (
                    <tr key={volume.name}>
                      <td>{volume.name}</td>
                      <td>{volume.filesystem || "—"}</td>
                      <td>{(volume.total_bytes / 1024 ** 3).toFixed(1)} GiB</td>
                      <td>{volume.used_percent.toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="connector-footnote">{copy.noVolumes}</p>
          )}
        </article>
      </section>
      <section className="panel inventory-panel">
        <div className="panel__header">
          <h2>{copy.network}</h2>
        </div>
        {system.network_interfaces.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>{copy.interfaceName}</th>
                  <th>{copy.status}</th>
                  <th>{copy.macAddress}</th>
                  <th>{copy.addresses}</th>
                </tr>
              </thead>
              <tbody>
                {system.network_interfaces.map((networkInterface) => (
                  <tr key={networkInterface.interface_id}>
                    <td>{networkInterface.name}</td>
                    <td>{networkInterface.status || "—"}</td>
                    <td>{networkInterface.mac_address || "—"}</td>
                    <td>
                      {networkInterface.addresses.length
                        ? networkInterface.addresses
                            .map(
                              (address) =>
                                `${address.address}/${address.prefix_length}`,
                            )
                            .join(", ")
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="connector-footnote">{copy.noInterfaces}</p>
        )}
      </section>
      <SoftwareInventoryPanel
        copy={dictionary.softwareInventory}
        locale={locale}
        snapshot={software.snapshot}
        packages={software.packages}
      />
    </ConsoleShell>
  );
}
