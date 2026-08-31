import { Bell, CircleUserRound, Search } from "lucide-react";

import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import type { AuthenticatedSession, TenantSummary } from "@/lib/auth-types";

import { LanguageSwitcher } from "./language-switcher";
import { LogoutButton } from "./logout-button";
import { type ActiveSection, Sidebar } from "./sidebar";
import { TenantSwitcher } from "./tenant-switcher";
import { ThemeToggle } from "./theme-toggle";

export async function ConsoleShell({
  children,
  session,
  tenant,
  activeSection = "overview",
}: {
  children: React.ReactNode;
  session: AuthenticatedSession;
  tenant: TenantSummary;
  activeSection?: ActiveSection;
}) {
  const dictionary = getDictionary(await resolveLocale());
  const roleLabels = {
    platform_admin: dictionary.shell.platformAdmin,
    tenant_admin: dictionary.shell.tenantAdmin,
    operator: dictionary.shell.operator,
    reader: dictionary.shell.reader,
  };
  return (
    <div className="console-shell">
      <Sidebar activeSection={activeSection} />
      <div className="console-workspace">
        <header className="topbar">
          <TenantSwitcher
            key={tenant.id}
            tenants={session.tenants}
            selectedTenantId={tenant.id}
          />
          <div className="topbar__tools">
            <button
              className="search-trigger"
              type="button"
              disabled
              aria-label={dictionary.shell.searchFuture}
            >
              <Search aria-hidden="true" size={17} />
              <span>{dictionary.shell.search}</span>
              <kbd>Ctrl K</kbd>
            </button>
            <LanguageSwitcher />
            <ThemeToggle />
            <button
              className="icon-button"
              type="button"
              disabled
              aria-label={dictionary.shell.notificationsFuture}
            >
              <Bell aria-hidden="true" size={18} />
            </button>
            <div className="user-summary">
              <CircleUserRound aria-hidden="true" size={24} strokeWidth={1.6} />
              <span>
                <strong>{roleLabels[tenant.role]}</strong>
                <small>{session.user.display_name}</small>
              </span>
            </div>
            <LogoutButton csrfToken={session.csrf_token} />
          </div>
        </header>
        <main className="console-main">{children}</main>
      </div>
    </div>
  );
}
