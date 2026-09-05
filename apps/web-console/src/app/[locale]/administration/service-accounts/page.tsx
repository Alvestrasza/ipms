import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { ServiceAccountAdministration } from "@/components/service-account-administration";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getServiceAccounts } from "@/lib/server-service-accounts";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  return { title: getDictionary(await resolveLocale()).serviceAccounts.title };
}

export default async function ServiceAccountsPage({
  searchParams,
}: {
  searchParams: Promise<{ tenant?: string }>;
}) {
  const locale = await resolveLocale();
  const copy = getDictionary(locale).serviceAccounts;
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const query = await searchParams;
  const tenant = query.tenant
    ? session.tenants.find((item) => item.id === query.tenant)
    : selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  if (!hasPermission(tenant, "service_accounts.manage")) redirect(`/${locale}`);
  const result = await getServiceAccounts(tenant.id);
  if (!result.sessionValid) redirect(`/${locale}/login`);
  if (!result.authorized) redirect(`/${locale}`);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="admin-service-accounts"
    >
      <section
        className="page-heading"
        aria-labelledby="service-accounts-heading"
      >
        <div>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h1 id="service-accounts-heading">{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
        <span className="read-only-badge">{tenant.display_name}</span>
      </section>
      <ServiceAccountAdministration
        key={tenant.id}
        initialAccounts={result.accounts}
        initialHosts={result.hosts}
        available={result.available}
        csrfToken={session.csrf_token}
        tenantId={tenant.id}
        locale={locale}
        copy={copy}
      />
    </ConsoleShell>
  );
}
