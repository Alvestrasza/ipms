import {
  Activity,
  ArchiveRestore,
  Boxes,
  Building2,
  Database,
  LayoutDashboard,
  Network,
  ServerCog,
  Settings,
} from "lucide-react";

import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";

import { Brand } from "./brand";

export async function Sidebar() {
  const dictionary = getDictionary(await resolveLocale());
  const navigation = [
    {
      label: dictionary.navigation.overview,
      icon: LayoutDashboard,
      active: true,
    },
    { label: dictionary.navigation.physical, icon: ServerCog },
    { label: dictionary.navigation.virtual, icon: Boxes },
    { label: dictionary.navigation.monitoring, icon: Activity },
    { label: dictionary.navigation.network, icon: Network },
    { label: dictionary.navigation.storage, icon: Database },
    { label: dictionary.navigation.backup, icon: ArchiveRestore },
  ];
  return (
    <aside className="sidebar" aria-label={dictionary.navigation.primary}>
      <div className="sidebar__brand">
        <Brand />
      </div>

      <nav className="sidebar__nav">
        <p className="sidebar__section-label">
          {dictionary.navigation.workspace}
        </p>
        <ul>
          {navigation.map(({ label, icon: Icon, active }) => (
            <li key={label}>
              <span
                className={
                  active
                    ? "nav-item nav-item--active"
                    : "nav-item nav-item--disabled"
                }
                aria-current={active ? "page" : undefined}
                aria-disabled={!active}
              >
                <Icon aria-hidden="true" size={18} strokeWidth={1.8} />
                <span>{label}</span>
                {!active && (
                  <span className="nav-item__soon">
                    {dictionary.navigation.soon}
                  </span>
                )}
              </span>
            </li>
          ))}
        </ul>
      </nav>

      <div className="sidebar__footer">
        <span className="nav-item nav-item--disabled" aria-disabled="true">
          <Building2 aria-hidden="true" size={18} />
          <span>{dictionary.navigation.tenants}</span>
          <span className="nav-item__soon">{dictionary.navigation.soon}</span>
        </span>
        <span className="nav-item nav-item--disabled" aria-disabled="true">
          <Settings aria-hidden="true" size={18} />
          <span>{dictionary.navigation.administration}</span>
          <span className="nav-item__soon">{dictionary.navigation.soon}</span>
        </span>
        <div className="sidebar__version">
          <span className="sidebar__version-dot" aria-hidden="true" />
          {dictionary.navigation.version}
        </div>
      </div>
    </aside>
  );
}
