import { ArrowLeft, RadioTower } from "lucide-react";
import type { Metadata, Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { BmcDetailTabs } from "@/components/bmc-detail-tabs";
import { ConsoleShell } from "@/components/console-shell";
import { StatusPill } from "@/components/status-pill";
import { documentLocale } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getPhysicalInfrastructure } from "@/lib/server-physical";
import { selectedTenant } from "@/lib/tenant-selection";

type BmcDetailPageProps = {
  params: Promise<{ id: string }>;
};

function formatDate(value: string, locale: "de" | "en") {
  return new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function formatMemory(bytes: number | null) {
  if (bytes === null) return "—";
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.bmcDetail.title };
}

export default async function BmcDetailPage({ params }: BmcDetailPageProps) {
  const [locale, { id }] = await Promise.all([resolveLocale(), params]);
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);

  const infrastructure = await getPhysicalInfrastructure(tenant.id);
  if (!infrastructure.sessionValid) redirect(`/${locale}/login`);
  const connector = infrastructure.connectors.find(
    (candidate) =>
      candidate.id === id && candidate.connector_type === "ilo-redfish",
  );
  if (!connector) notFound();
  const system = infrastructure.systems.find(
    (candidate) => candidate.connector_id === connector.id,
  );

  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="bmc">
      <Link
        className="detail-back-link"
        href={`/${locale}/physical/bmc` as Route}
      >
        <ArrowLeft aria-hidden="true" size={16} />
        {dictionary.bmcDetail.back}
      </Link>

      <section className="page-heading" aria-labelledby="bmc-detail-heading">
        <div>
          <p className="eyebrow">{dictionary.bmcDetail.snapshot}</p>
          <h1 id="bmc-detail-heading">
            {dictionary.bmcDetail.eyebrow} -{" "}
            {dictionary.bmcDetail.headingSuffix}
          </h1>
          <p>{connector.display_name}</p>
        </div>
        <StatusPill
          status={connector.health}
          label={dictionary.status[connector.health]}
        />
      </section>

      {system ? (
        <>
          <section className="panel bmc-identity" aria-label={system.name}>
            <div className="bmc-identity__title">
              <span className="connector-mark connector-mark--ilo">
                <RadioTower aria-hidden="true" size={18} />
              </span>
              <div>
                <strong>{system.name}</strong>
                <small>{system.manufacturer}</small>
              </div>
            </div>
            <dl className="bmc-identity__grid">
              <div>
                <dt>{dictionary.bmcDetail.systemModel}</dt>
                <dd>{system.model || "—"}</dd>
              </div>
              <div>
                <dt>{dictionary.bmcDetail.serialNumber}</dt>
                <dd>{system.serial_number || "—"}</dd>
              </div>
              <div>
                <dt>{dictionary.bmcDetail.powerState}</dt>
                <dd>{system.power_state || "—"}</dd>
              </div>
              <div>
                <dt>{dictionary.bmcDetail.memory}</dt>
                <dd>{formatMemory(system.memory_bytes)}</dd>
              </div>
              <div>
                <dt>{dictionary.bmcDetail.biosVersion}</dt>
                <dd>{system.bios_version || "—"}</dd>
              </div>
              <div>
                <dt>{dictionary.bmcDetail.bmcFirmware}</dt>
                <dd>{system.bmc_firmware_version || "—"}</dd>
              </div>
              <div>
                <dt>{dictionary.bmcDetail.lastDiscovery}</dt>
                <dd>{formatDate(system.discovered_at, locale)}</dd>
              </div>
            </dl>
          </section>

          <BmcDetailTabs
            snapshot={system.detail_snapshot ?? {}}
            copy={dictionary.bmcDetail}
            locale={locale}
          />
        </>
      ) : (
        <section className="panel empty-state">
          <RadioTower aria-hidden="true" size={28} />
          <strong>{dictionary.bmcDetail.noSystem}</strong>
          <span>{dictionary.bmcDetail.noSystemHint}</span>
        </section>
      )}
    </ConsoleShell>
  );
}
