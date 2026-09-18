/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Render tenant Device Collection management.
 */
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { DeviceCollections } from "@/components/device-collections";
import { getCollectionCopy } from "@/i18n/collection-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getDeviceCollections } from "@/lib/server-collections";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata() {
  return { title: getCollectionCopy(await resolveLocale()).deviceTitle };
}
export default async function DeviceCollectionsPage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant || !hasPermission(tenant, "security.collections.view"))
    redirect(`/${locale}/access-unavailable`);
  const collections = await getDeviceCollections(tenant.id);
  if (!collections.sessionValid) redirect(`/${locale}/login`);
  if (collections.forbidden) redirect(`/${locale}/access-unavailable`);
  const copy = getCollectionCopy(locale);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="collections-device"
    >
      <section className="page-heading">
        <div>
          <p className="eyebrow">
            {copy.navigation} / {copy.deviceNavigation}
          </p>
          <h1>{copy.deviceTitle}</h1>
          <p>{copy.deviceDescription}</p>
        </div>
      </section>
      {collections.data ? (
        <DeviceCollections
          initial={collections.data}
          tenantId={tenant.id}
          csrfToken={session.csrf_token}
          canManage={hasPermission(tenant, "security.collections.manage")}
          copy={copy}
        />
      ) : (
        <p role="alert">{copy.unavailable}</p>
      )}
    </ConsoleShell>
  );
}
