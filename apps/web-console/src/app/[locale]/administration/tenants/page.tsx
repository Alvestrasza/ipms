import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { PlatformShell } from "@/components/platform-shell";
import { TenantAdministration } from "@/components/tenant-administration";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { hasPlatformPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getPlatformTenants } from "@/lib/server-platform-tenants";

export async function generateMetadata(): Promise<Metadata> {
  return { title: getDictionary(await resolveLocale()).platform.title };
}
export default async function TenantAdministrationPage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  if (!hasPlatformPermission(session, "tenants.manage"))
    redirect(`/${locale}/access-unavailable`);
  const result = await getPlatformTenants();
  if (!result.sessionValid) redirect(`/${locale}/login`);
  const copy = getDictionary(locale).platform;
  return (
    <PlatformShell session={session}>
      <section className="page-heading">
        <div>
          <p className="eyebrow">{copy.scope}</p>
          <h1>{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
      </section>
      <p className="preview-notice" role="note">
        {copy.setupBoundary}
      </p>
      <TenantAdministration
        initialTenants={result.tenants}
        available={result.available}
        csrfToken={session.csrf_token}
        locale={locale}
        copy={copy}
      />
    </PlatformShell>
  );
}
