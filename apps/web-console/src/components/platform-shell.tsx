import { Building2, CircleUserRound } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import {
  type AuthenticatedSession,
  hasPlatformPermission,
} from "@/lib/auth-types";
import { Brand } from "./brand";
import { LanguageSwitcher } from "./language-switcher";
import { LogoutButton } from "./logout-button";
import { ThemeToggle } from "./theme-toggle";

/** Account-level chrome: deliberately contains no tenant inventory providers. */
export async function PlatformShell({
  session,
  children,
  activeSection = "tenants",
}: {
  session: AuthenticatedSession;
  children: React.ReactNode;
  activeSection?: "tenants" | "account";
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const canManage = hasPlatformPermission(session, "tenants.manage");
  return (
    <div className="console-shell">
      <aside className="sidebar" aria-label={dictionary.navigation.primary}>
        <div className="sidebar__brand">
          <Brand />
        </div>
        <nav className="sidebar__nav">
          <p className="sidebar__section-label">{dictionary.platform.scope}</p>
          {canManage ? (
            <Link
              className={`nav-item ${activeSection === "tenants" ? "nav-item--active" : ""}`}
              aria-current={activeSection === "tenants" ? "page" : undefined}
              href={`/${locale}/administration/tenants` as Route}
            >
              <Building2 size={18} aria-hidden="true" />
              {dictionary.platform.title}
            </Link>
          ) : null}
        </nav>
        <div className="sidebar__footer">
          <div className="sidebar__version">
            <span className="sidebar__version-dot" aria-hidden="true" />
            {dictionary.navigation.version}
          </div>
        </div>
      </aside>
      <div className="console-workspace">
        <header className="topbar">
          <strong>
            {session.user.is_platform_admin
              ? dictionary.platform.scope
              : dictionary.platform.account}
          </strong>
          <div className="topbar__tools">
            <LanguageSwitcher />
            <ThemeToggle />
            <Link
              className="user-summary user-summary--link"
              href={`/${locale}/account`}
              aria-label={dictionary.account.title}
              title={dictionary.account.title}
              aria-current={activeSection === "account" ? "page" : undefined}
            >
              <CircleUserRound size={21} aria-hidden="true" />
              <span>
                <strong>
                  {session.user.is_platform_admin
                    ? dictionary.shell.platformAdmin
                    : dictionary.platform.account}
                </strong>
                <small>{session.user.display_name}</small>
              </span>
            </Link>
            <LogoutButton csrfToken={session.csrf_token} />
          </div>
        </header>
        <main className="console-main">{children}</main>
      </div>
    </div>
  );
}
