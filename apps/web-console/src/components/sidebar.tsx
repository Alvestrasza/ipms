import {
  Activity,
  ArchiveRestore,
  Boxes,
  Building2,
  Database,
  LayoutDashboard,
  ListTree,
  MonitorCog,
  Network,
  ScrollText,
  ServerCog,
  Settings,
} from "lucide-react";
import type { Route } from "next";
import Link from "next/link";

import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";

import { Brand } from "./brand";

export type ActiveSection =
  | "overview"
  | "physical"
  | "physical-servers"
  | "bmc"
  | "bmc-logs"
  | "bmc-events"
  | "virtual";

export async function Sidebar({
  activeSection,
}: {
  activeSection: ActiveSection;
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const physicalExpanded = [
    "physical",
    "physical-servers",
    "bmc",
    "bmc-logs",
    "bmc-events",
  ].includes(activeSection);
  const virtualExpanded = activeSection === "virtual";
  const navigation = [
    {
      label: dictionary.navigation.overview,
      icon: LayoutDashboard,
      href: `/${locale}`,
      section: "overview" as const,
      enabled: true as const,
    },
    {
      label: dictionary.navigation.physical,
      icon: ServerCog,
      href: `/${locale}/physical`,
      section: "physical" as const,
      enabled: true as const,
    },
    {
      label: dictionary.navigation.virtual,
      icon: Boxes,
      href: `/${locale}/virtual`,
      section: "virtual" as const,
      enabled: true as const,
    },
    {
      label: dictionary.navigation.monitoring,
      icon: Activity,
      enabled: false as const,
    },
    {
      label: dictionary.navigation.network,
      icon: Network,
      enabled: false as const,
    },
    {
      label: dictionary.navigation.storage,
      icon: Database,
      enabled: false as const,
    },
    {
      label: dictionary.navigation.backup,
      icon: ArchiveRestore,
      enabled: false as const,
    },
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
          {navigation.map(({ label, icon: Icon, ...item }) => (
            <li key={label}>
              {item.enabled ? (
                <Link
                  className={`nav-item ${item.section === activeSection || (item.section === "physical" && physicalExpanded) ? "nav-item--active" : ""}`}
                  href={item.href as Route}
                  aria-current={
                    item.section === activeSection ? "page" : undefined
                  }
                >
                  <Icon aria-hidden="true" size={18} strokeWidth={1.8} />
                  <span>{label}</span>
                </Link>
              ) : (
                <span
                  className="nav-item nav-item--disabled"
                  aria-disabled="true"
                >
                  <Icon aria-hidden="true" size={18} strokeWidth={1.8} />
                  <span>{label}</span>
                  <span className="nav-item__soon">
                    {dictionary.navigation.soon}
                  </span>
                </span>
              )}
              {item.section === "physical" && physicalExpanded ? (
                <ul className="nav-tree">
                  <li>
                    <Link
                      className={`nav-subitem ${activeSection === "physical-servers" ? "nav-subitem--active" : ""}`}
                      href={`/${locale}/physical/servers` as Route}
                      aria-current={
                        activeSection === "physical-servers"
                          ? "page"
                          : undefined
                      }
                    >
                      <MonitorCog aria-hidden="true" size={15} />
                      <span>{dictionary.navigation.physicalServers}</span>
                    </Link>
                  </li>
                  <li>
                    <Link
                      className={`nav-subitem ${activeSection === "bmc" ? "nav-subitem--active" : ""}`}
                      href={`/${locale}/physical/bmc` as Route}
                      aria-current={
                        activeSection === "bmc" ? "page" : undefined
                      }
                    >
                      <ServerCog aria-hidden="true" size={15} />
                      <span>{dictionary.navigation.bmc}</span>
                    </Link>
                    {["bmc", "bmc-logs", "bmc-events"].includes(
                      activeSection,
                    ) ? (
                      <ul className="nav-tree nav-tree--nested">
                        <li>
                          <Link
                            className={`nav-subitem ${activeSection === "bmc-logs" ? "nav-subitem--active" : ""}`}
                            href={`/${locale}/physical/bmc/logs` as Route}
                            aria-current={
                              activeSection === "bmc-logs" ? "page" : undefined
                            }
                          >
                            <ScrollText aria-hidden="true" size={14} />
                            <span>{dictionary.navigation.bmcLogs}</span>
                          </Link>
                        </li>
                        <li>
                          <Link
                            className={`nav-subitem ${activeSection === "bmc-events" ? "nav-subitem--active" : ""}`}
                            href={`/${locale}/physical/bmc/events` as Route}
                            aria-current={
                              activeSection === "bmc-events"
                                ? "page"
                                : undefined
                            }
                          >
                            <ListTree aria-hidden="true" size={14} />
                            <span>{dictionary.navigation.bmcEvents}</span>
                          </Link>
                        </li>
                      </ul>
                    ) : null}
                  </li>
                </ul>
              ) : null}
              {item.section === "virtual" && virtualExpanded ? (
                <ul className="nav-tree">
                  <li>
                    <Link
                      className="nav-subitem nav-subitem--active"
                      href={`/${locale}/virtual` as Route}
                      aria-current="page"
                    >
                      <MonitorCog aria-hidden="true" size={15} />
                      <span>{dictionary.navigation.virtualServers}</span>
                    </Link>
                  </li>
                </ul>
              ) : null}
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
