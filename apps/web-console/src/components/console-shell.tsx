import { Bell, CircleUserRound, Search } from "lucide-react";

import type { AuthenticatedSession, TenantSummary } from "@/lib/auth-types";

import { LogoutButton } from "./logout-button";
import { Sidebar } from "./sidebar";
import { TenantSwitcher } from "./tenant-switcher";
import { ThemeToggle } from "./theme-toggle";

const roleLabels = {
  platform_admin: "Platform administrator",
  tenant_admin: "Tenant administrator",
  operator: "Operator",
  reader: "Reader",
};

export function ConsoleShell({
  children,
  session,
  tenant,
}: {
  children: React.ReactNode;
  session: AuthenticatedSession;
  tenant: TenantSummary;
}) {
  return (
    <div className="console-shell">
      <Sidebar />
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
              aria-label="Search will be available in a future release"
            >
              <Search aria-hidden="true" size={17} />
              <span>Search infrastructure</span>
              <kbd>Ctrl K</kbd>
            </button>
            <ThemeToggle />
            <button
              className="icon-button"
              type="button"
              disabled
              aria-label="Notifications are not available yet"
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
