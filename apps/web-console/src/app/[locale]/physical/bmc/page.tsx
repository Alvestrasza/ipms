import { RadioTower } from "lucide-react";
import type { Metadata, Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { BmcActions } from "@/components/bmc-actions";
import { BmcWizard } from "@/components/bmc-wizard";
import { ConnectorOperations } from "@/components/connector-operations";
import { ConsoleShell } from "@/components/console-shell";
import { StatusPill } from "@/components/status-pill";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getPhysicalInfrastructure } from "@/lib/server-physical";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.bmc.title };
}

export default async function BareMetalControllerPage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);

  const infrastructure = await getPhysicalInfrastructure(tenant.id);
  if (!infrastructure.sessionValid) redirect(`/${locale}/login`);
  const connectors = infrastructure.connectors.filter(
    (connector) => connector.connector_type === "bmc-api",
  );
  const canManage = hasPermission(tenant, "connectors.manage");
  const familyLabels = {
    "hpe-ilo4": dictionary.bmc.familyIlo4,
    "hpe-ilo-modern": dictionary.bmc.familyIloModern,
    "dell-idrac": dictionary.bmc.familyIdrac,
    "generic-bmc-api": dictionary.bmc.familyGenericApi,
  };

  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="bmc">
      <div
        className={`preview-notice ${infrastructure.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {infrastructure.available
          ? dictionary.bmc.liveData
          : dictionary.bmc.unavailableData}
      </div>

      <section className="page-heading" aria-labelledby="bmc-heading">
        <div>
          <p className="eyebrow">{dictionary.bmc.eyebrow}</p>
          <h1 id="bmc-heading">{dictionary.bmc.heading}</h1>
          <p>
            {dictionary.bmc.descriptionPrefix} {tenant.display_name}.
          </p>
        </div>
        <span className="read-only-badge">BMC API</span>
      </section>

      <section
        className="panel connector-card"
        aria-labelledby="bmc-list-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">{dictionary.physical.connectors}</p>
            <h2 id="bmc-list-heading">{dictionary.bmc.endpoints}</h2>
          </div>
          <span className="panel__metric">
            <strong>{connectors.length}</strong>
          </span>
        </div>
        {canManage ? (
          <BmcWizard
            csrfToken={session.csrf_token}
            tenantId={tenant.id}
            locale={locale}
            copy={dictionary.bmc}
          />
        ) : null}
        {connectors.length ? (
          connectors.map((connector) => (
            <div className="connector-entry" key={connector.id}>
              <div className="connector-row">
                <span>
                  <i className="connector-mark connector-mark--ilo">
                    <RadioTower aria-hidden="true" size={16} />
                  </i>
                  <span>
                    <Link
                      className="connector-detail-link"
                      href={`/${locale}/physical/bmc/${connector.id}` as Route}
                    >
                      <strong>{connector.display_name}</strong>
                    </Link>
                    <small className="connector-detail">
                      {familyLabels[connector.bmc_family]} ·{" "}
                      {connector.base_url}
                    </small>
                  </span>
                </span>
                <div className="connector-row__status-actions">
                  <StatusPill
                    status={connector.health}
                    label={dictionary.status[connector.health]}
                  />
                  {canManage ? (
                    <BmcActions
                      connector={connector}
                      csrfToken={session.csrf_token}
                      tenantId={tenant.id}
                      copy={dictionary.bmc}
                      discoveryCopy={dictionary.physical}
                    />
                  ) : null}
                </div>
              </div>
              <ConnectorOperations
                connector={connector}
                locale={locale}
                copy={dictionary.physical}
              />
            </div>
          ))
        ) : (
          <div className="empty-state empty-state--compact">
            <RadioTower aria-hidden="true" size={24} />
            <strong>{dictionary.bmc.noEndpoints}</strong>
            <span>{dictionary.bmc.noEndpointsHint}</span>
          </div>
        )}
      </section>
    </ConsoleShell>
  );
}
