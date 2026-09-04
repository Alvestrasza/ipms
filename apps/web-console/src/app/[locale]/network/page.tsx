import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { ManagedDeviceActions } from "@/components/managed-device-actions";
import { ManagedDeviceWizard } from "@/components/managed-device-wizard";
import { StatusPill } from "@/components/status-pill";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getManagedDevices } from "@/lib/server-devices";
import { selectedTenant } from "@/lib/tenant-selection";

function interfaceValue(item: Record<string, unknown>, ...keys: string[]) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === "string" || typeof value === "number") {
      return String(value);
    }
  }
  return "—";
}

export default async function NetworkPage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  const inventory = await getManagedDevices(tenant.id);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);
  const copy = dictionary.networkDevices;
  const canManage = hasPermission(tenant, "connectors.manage");
  const devicesByConnector = new Map(
    inventory.devices.map((device) => [device.connector_id, device]),
  );

  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="network">
      <section className="page-heading">
        <div>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h1>{copy.heading}</h1>
          <p>{copy.description}</p>
        </div>
        {canManage ? (
          <ManagedDeviceWizard
            csrfToken={session.csrf_token}
            tenantId={tenant.id}
            copy={copy}
          />
        ) : null}
      </section>
      <section className="panel inventory-panel">
        <div className="panel__header">
          <h2>{copy.inventory}</h2>
          <span className="panel__metric">
            <strong>{inventory.connectors.length}</strong>
          </span>
        </div>
        {inventory.connectors.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>{copy.name}</th>
                  <th>{copy.category}</th>
                  <th>{copy.product}</th>
                  <th>{copy.version}</th>
                  <th>{copy.uptime}</th>
                  <th>{copy.status}</th>
                  {canManage ? <th>{copy.actions}</th> : null}
                </tr>
              </thead>
              <tbody>
                {inventory.connectors.map((connector) => {
                  const device = devicesByConnector.get(connector.id);
                  return (
                    <tr key={connector.id}>
                      <td>
                        <strong>
                          {device?.name || connector.display_name}
                        </strong>
                        <small className="connector-detail">
                          {connector.base_url}
                        </small>
                      </td>
                      <td>{device?.category || connector.connector_type}</td>
                      <td>
                        {device
                          ? `${device.vendor} ${device.model || device.product}`
                          : copy.awaitingDiscovery}
                        {device?.interfaces.length ? (
                          <details className="connector-interface-details">
                            <summary>
                              {device.interfaces.length} {copy.interfaces}
                            </summary>
                            <div className="table-scroll">
                              <table>
                                <thead>
                                  <tr>
                                    <th>{copy.interfaceName}</th>
                                    <th>{copy.interfaceState}</th>
                                    <th>{copy.interfaceAddress}</th>
                                    <th>{copy.interfaceDescription}</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {device.interfaces.map((item) => (
                                    <tr
                                      key={`${connector.id}-${JSON.stringify(item)}`}
                                    >
                                      <td>
                                        {interfaceValue(
                                          item,
                                          "name",
                                          "interface_name",
                                          "id",
                                          "index",
                                        )}
                                      </td>
                                      <td>
                                        {interfaceValue(
                                          item,
                                          "status",
                                          "oper_status",
                                          "state",
                                        )}
                                      </td>
                                      <td>
                                        {interfaceValue(
                                          item,
                                          "ip_address",
                                          "address",
                                          "speed_mbps",
                                        )}
                                      </td>
                                      <td>
                                        {interfaceValue(
                                          item,
                                          "description",
                                          "zone",
                                          "admin_status",
                                        )}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </details>
                        ) : null}
                      </td>
                      <td>{device?.software_version || "—"}</td>
                      <td>
                        {device?.uptime_seconds === null ||
                        device?.uptime_seconds === undefined
                          ? "—"
                          : `${Math.floor(device.uptime_seconds / 86400)}d`}
                      </td>
                      <td>
                        <StatusPill
                          status={connector.health}
                          label={dictionary.status[connector.health]}
                        />
                        {connector.last_error_code ? (
                          <small className="connector-detail">
                            {connector.last_error_code}
                          </small>
                        ) : null}
                      </td>
                      {canManage ? (
                        <td>
                          <ManagedDeviceActions
                            connector={connector}
                            csrfToken={session.csrf_token}
                            tenantId={tenant.id}
                            copy={copy}
                          />
                        </td>
                      ) : null}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state empty-state--compact">
            <strong>{copy.noDevices}</strong>
          </div>
        )}
      </section>
    </ConsoleShell>
  );
}
