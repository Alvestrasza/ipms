import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { UserAdministrationTable } from "@/components/user-administration-table";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { getManagedTenantUsers } from "@/lib/server-users";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.userAdministration.title };
}

export default async function UserAdministrationPage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  if (!hasPermission(tenant, "users.view")) redirect(`/${locale}`);
  const result = await getManagedTenantUsers(tenant.id);
  if (!result.sessionValid) redirect(`/${locale}/login`);

  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="admin-users">
      <div
        className={`preview-notice ${result.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {result.available
          ? dictionary.userAdministration.liveData
          : dictionary.userAdministration.unavailableData}
      </div>
      <section
        className="page-heading"
        aria-labelledby="user-administration-heading"
      >
        <div>
          <p className="eyebrow">{dictionary.userAdministration.eyebrow}</p>
          <h1 id="user-administration-heading">
            {dictionary.userAdministration.heading}
          </h1>
          <p>{dictionary.userAdministration.description}</p>
        </div>
        <span className="read-only-badge">{tenant.display_name}</span>
      </section>
      <UserAdministrationTable
        initialUsers={result.users}
        canManage={hasPermission(tenant, "users.manage")}
        csrfToken={session.csrf_token}
        tenantId={tenant.id}
        locale={locale}
        copy={dictionary.userAdministration}
      />
    </ConsoleShell>
  );
}
