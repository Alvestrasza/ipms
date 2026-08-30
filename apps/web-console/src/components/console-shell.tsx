import { Bell, CircleUserRound, Search } from "lucide-react";

import { Sidebar } from "./sidebar";
import { TenantSwitcher } from "./tenant-switcher";
import { ThemeToggle } from "./theme-toggle";

export function ConsoleShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="console-shell">
      <Sidebar />
      <div className="console-workspace">
        <header className="topbar">
          <TenantSwitcher />
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
                <strong>Platform Admin</strong>
                <small>Development preview</small>
              </span>
            </div>
          </div>
        </header>
        <main className="console-main">{children}</main>
      </div>
    </div>
  );
}
