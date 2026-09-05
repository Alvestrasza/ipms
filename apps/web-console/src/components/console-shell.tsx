import { Bell, CircleUserRound, Search } from "lucide-react";

import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import {
  type AuthenticatedSession,
  hasPermission,
  type TenantSummary,
} from "@/lib/auth-types";
import { requireTenantScope } from "@/lib/server-portal-scope";
import {
  getWindowsClientFamilies,
  getWindowsServerRoles,
} from "@/lib/server-windows";
import { AddSystemDialog } from "./add-system-dialog";
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
  activeWindowsRole,
  activeWindowsClientFamily,
}: {
  children: React.ReactNode;
  session: AuthenticatedSession;
  tenant: TenantSummary;
  activeSection?: ActiveSection;
  activeWindowsRole?: string;
  activeWindowsClientFamily?: string;
}) {
  const locale = await resolveLocale();
  requireTenantScope(session, locale);
  const [windowsRoles, windowsClientFamilies] = await Promise.all([
    getWindowsServerRoles(tenant.id),
    getWindowsClientFamilies(tenant.id),
  ]);
  const dictionary = getDictionary(locale);
  const roleLabels = {
    tenant_admin: dictionary.shell.tenantAdmin,
    operator: dictionary.shell.operator,
    approver: dictionary.shell.approver,
    auditor: dictionary.shell.auditor,
    reader: dictionary.shell.reader,
  };
  return (
    <div className="console-shell">
      <Sidebar
        activeSection={activeSection}
        activeWindowsRole={activeWindowsRole}
        activeWindowsClientFamily={activeWindowsClientFamily}
        canManageAgents={hasPermission(tenant, "agents.manage")}
        canViewUsers={hasPermission(tenant, "users.view")}
        canManageServiceAccounts={hasPermission(
          tenant,
          "service_accounts.manage",
        )}
        windowsRoles={windowsRoles}
        windowsClientFamilies={windowsClientFamilies}
      />
      <div className="console-workspace">
        <header className="topbar">
          <TenantSwitcher
            key={tenant.id}
            tenants={session.tenants}
            selectedTenantId={tenant.id}
          />
          <div className="topbar__tools">
            <AddSystemDialog
              csrfToken={session.csrf_token}
              tenantId={tenant.id}
              locale={locale}
              canManage={
                hasPermission(tenant, "agents.manage") ||
                hasPermission(tenant, "connectors.manage")
              }
              copy={dictionary.addSystem}
              bmcCopy={dictionary.bmc}
            />
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
