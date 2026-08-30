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

import { Brand } from "./brand";

const navigation = [
  { label: "Overview", icon: LayoutDashboard, active: true },
  { label: "Physical infrastructure", icon: ServerCog },
  { label: "Virtual infrastructure", icon: Boxes },
  { label: "Monitoring", icon: Activity },
  { label: "Network", icon: Network },
  { label: "Storage", icon: Database },
  { label: "Backup & restore", icon: ArchiveRestore },
];

export function Sidebar() {
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="sidebar__brand">
        <Brand />
      </div>

      <nav className="sidebar__nav">
        <p className="sidebar__section-label">Workspace</p>
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
                {!active && <span className="nav-item__soon">Soon</span>}
              </span>
            </li>
          ))}
        </ul>
      </nav>

      <div className="sidebar__footer">
        <span className="nav-item nav-item--disabled" aria-disabled="true">
          <Building2 aria-hidden="true" size={18} />
          <span>Tenants</span>
          <span className="nav-item__soon">Soon</span>
        </span>
        <span className="nav-item nav-item--disabled" aria-disabled="true">
          <Settings aria-hidden="true" size={18} />
          <span>Administration</span>
          <span className="nav-item__soon">Soon</span>
        </span>
        <div className="sidebar__version">
          <span className="sidebar__version-dot" aria-hidden="true" />
          IPMS v0.1.0 development
        </div>
      </div>
    </aside>
  );
}
