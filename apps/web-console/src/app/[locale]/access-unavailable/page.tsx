import { redirect } from "next/navigation";
import { PlatformShell } from "@/components/platform-shell";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";

export default async function AccessUnavailablePage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const copy = getDictionary(locale).platform;
  return (
    <PlatformShell session={session}>
      <section className="page-heading">
        <div>
          <p className="eyebrow">{copy.account}</p>
          <h1>{copy.noAccessTitle}</h1>
          <p>{copy.noAccessDescription}</p>
        </div>
      </section>
    </PlatformShell>
  );
}
