import Link from "next/link";
import { redirect } from "next/navigation";
import { AccountSettings } from "@/components/account-settings";
import { PlatformShell } from "@/components/platform-shell";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getAccountIdentity } from "@/lib/server-account";
import { getServerSession } from "@/lib/server-auth";

/** Account ownership is independent of tenant membership and operational scope. */
export default async function AccountPage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const result = await getAccountIdentity();
  if (!result.sessionValid) redirect(`/${locale}/login`);
  const copy = getDictionary(locale).account;
  return (
    <PlatformShell session={session} activeSection="account">
      <section className="page-heading">
        <div>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h1>{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
        <Link className="outline-button" href={`/${locale}`}>
          {copy.back}
        </Link>
      </section>
      {result.account ? (
        <AccountSettings
          account={result.account}
          csrfToken={session.csrf_token}
          locale={locale}
          copy={copy}
        />
      ) : (
        <p role="alert" className="form-error">
          {copy.unavailable}
        </p>
      )}
    </PlatformShell>
  );
}
