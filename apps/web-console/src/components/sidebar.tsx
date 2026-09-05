import {
  Activity,
  ArchiveRestore,
  Boxes,
  Database,
  KeyRound,
  LayoutDashboard,
  ListTree,
  MonitorCog,
  Network,
  ScrollText,
  ServerCog,
  Settings,
  UsersRound,
} from "lucide-react";
import type { Route } from "next";
import Link from "next/link";

import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import type {
  WindowsClientFamilySummary,
  WindowsServerRoleSummary,
} from "@/lib/windows-server-types";

import { Brand } from "./brand";
import { WindowsClientNavigation } from "./windows-client-navigation";
import { WindowsRoleNavigation } from "./windows-role-navigation";

export type ActiveSection =
  | "overview"
  | "physical"
  | "physical-servers"
  | "physical-clients"
  | "physical-linux"
  | "bmc"
  | "bmc-logs"
  | "bmc-events"
  | "virtual"
  | "virtual-clients"
  | "virtual-linux"
  | "hyper-v-vms"
  | "network"
  | "admin-users"
  | "admin-service-accounts"
  | "admin-agents";

export async function Sidebar({
  activeSection,
  activeWindowsRole,
  activeWindowsClientFamily,
  canManageAgents,
  canViewUsers,
  canManageServiceAccounts,
  windowsRoles,
  windowsClientFamilies,
}: {
  activeSection: ActiveSection;
  activeWindowsRole?: string;
  activeWindowsClientFamily?: string;
  canManageAgents: boolean;
  canViewUsers: boolean;
  canManageServiceAccounts: boolean;
  windowsRoles: WindowsServerRoleSummary[];
  windowsClientFamilies: WindowsClientFamilySummary[];
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const physicalExpanded = [
    "physical",
    "physical-servers",
    "physical-clients",
    "physical-linux",
    "bmc",
    "bmc-logs",
    "bmc-events",
  ].includes(activeSection);
  const virtualExpanded = [
    "virtual",
    "virtual-clients",
    "virtual-linux",
    "hyper-v-vms",
  ].includes(activeSection);
  const hasHyperVHosts = windowsRoles.some(
    (role) =>
      ["hyper-v", "win32-server-feature-20"].includes(
        role.name.toLowerCase(),
      ) && role.physical_count + role.virtual_count > 0,
  );
  const administrationExpanded = [
    "admin-users",
    "admin-agents",
    "admin-service-accounts",
  ].includes(activeSection);
  const canAdmin = canManageAgents || canViewUsers || canManageServiceAccounts;
  const administrationHref = canViewUsers
    ? `/${locale}/administration/users`
    : canManageAgents
      ? `/${locale}/administration/infrastructure/agents`
      : `/${locale}/administration/service-accounts`;
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
      href: `/${locale}/network`,
      section: "network" as const,
      enabled: true as const,
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
                  className={`nav-item ${item.section === activeSection || (item.section === "physical" && physicalExpanded) || (item.section === "virtual" && virtualExpanded) ? "nav-item--active" : ""}`}
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
                    <WindowsRoleNavigation
                      active={activeSection === "physical-servers"}
                      activeRole={activeWindowsRole}
                      collapseLabel={dictionary.navigation.collapse}
                      expandLabel={dictionary.navigation.expand}
                      href={`/${locale}/physical/servers` as Route}
                      label={dictionary.navigation.physicalServers}
                      roles={windowsRoles}
                      serverType="physical"
                    />
                  </li>
                  <li>
                    <WindowsClientNavigation
                      active={activeSection === "physical-clients"}
                      activeFamily={activeWindowsClientFamily}
                      collapseLabel={dictionary.navigation.collapse}
                      expandLabel={dictionary.navigation.expand}
                      familyLabels={dictionary.windowsClientFamilies}
                      families={windowsClientFamilies}
                      href={`/${locale}/physical/clients` as Route}
                      label={dictionary.navigation.physicalClients}
                      serverType="physical"
                    />
                  </li>
                  <li>
                    <Link
                      className={`nav-subitem ${activeSection === "physical-linux" ? "nav-subitem--active" : ""}`}
                      href={`/${locale}/physical/linux` as Route}
                      aria-current={
                        activeSection === "physical-linux" ? "page" : undefined
                      }
                    >
                      <ServerCog aria-hidden="true" size={15} />
                      <span>{dictionary.navigation.physicalLinux}</span>
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
                    <WindowsRoleNavigation
                      active={activeSection === "virtual"}
                      activeRole={activeWindowsRole}
                      collapseLabel={dictionary.navigation.collapse}
                      expandLabel={dictionary.navigation.expand}
                      href={`/${locale}/virtual` as Route}
                      label={dictionary.navigation.virtualServers}
                      roles={windowsRoles}
                      serverType="virtual"
                    />
                  </li>
                  {hasHyperVHosts ? (
                    <li>
                      <Link
                        className={`nav-subitem ${activeSection === "hyper-v-vms" ? "nav-subitem--active" : ""}`}
                        href={`/${locale}/virtual/hyper-v` as Route}
                        aria-current={
                          activeSection === "hyper-v-vms" ? "page" : undefined
                        }
                      >
                        <Boxes aria-hidden="true" size={15} />
                        <span>
                          {dictionary.navigation.hyperVVirtualMachines}
                        </span>
                      </Link>
                    </li>
                  ) : null}
                  <li>
                    <WindowsClientNavigation
                      active={activeSection === "virtual-clients"}
                      activeFamily={activeWindowsClientFamily}
                      collapseLabel={dictionary.navigation.collapse}
                      expandLabel={dictionary.navigation.expand}
                      familyLabels={dictionary.windowsClientFamilies}
                      families={windowsClientFamilies}
                      href={`/${locale}/virtual/clients` as Route}
                      label={dictionary.navigation.virtualClients}
                      serverType="virtual"
                    />
                  </li>
                  <li>
                    <Link
                      className={`nav-subitem ${activeSection === "virtual-linux" ? "nav-subitem--active" : ""}`}
                      href={`/${locale}/virtual/linux` as Route}
                      aria-current={
                        activeSection === "virtual-linux" ? "page" : undefined
                      }
                    >
                      <ServerCog aria-hidden="true" size={15} />
                      <span>{dictionary.navigation.virtualLinux}</span>
                    </Link>
                  </li>
                </ul>
              ) : null}
            </li>
          ))}
        </ul>
      </nav>

      <div className="sidebar__footer">
        {canAdmin ? (
          <Link
            className={`nav-item ${administrationExpanded ? "nav-item--active" : ""}`}
            href={administrationHref as Route}
            aria-current={administrationExpanded ? "page" : undefined}
          >
            <Settings aria-hidden="true" size={18} />
            <span>{dictionary.navigation.administration}</span>
          </Link>
        ) : (
          <span className="nav-item nav-item--disabled" aria-disabled="true">
            <Settings aria-hidden="true" size={18} />
            <span>{dictionary.navigation.administration}</span>
          </span>
        )}
        {canAdmin && administrationExpanded ? (
          <ul className="nav-tree">
            {canViewUsers ? (
              <li>
                <Link
                  className={`nav-subitem ${activeSection === "admin-users" ? "nav-subitem--active" : ""}`}
                  href={`/${locale}/administration/users` as Route}
                  aria-current={
                    activeSection === "admin-users" ? "page" : undefined
                  }
                >
                  <UsersRound aria-hidden="true" size={15} />
                  <span>{dictionary.navigation.users}</span>
                </Link>
              </li>
            ) : null}
            {canManageServiceAccounts ? (
              <li>
                <Link
                  className={`nav-subitem ${activeSection === "admin-service-accounts" ? "nav-subitem--active" : ""}`}
                  href={`/${locale}/administration/service-accounts` as Route}
                  aria-current={
                    activeSection === "admin-service-accounts"
                      ? "page"
                      : undefined
                  }
                >
                  <KeyRound aria-hidden="true" size={15} />
                  <span>{dictionary.navigation.serviceAccounts}</span>
                </Link>
              </li>
            ) : null}
            {canManageAgents ? (
              <li>
                <span className="nav-subitem nav-subitem--branch">
                  <ServerCog aria-hidden="true" size={15} />
                  <span>{dictionary.navigation.infrastructure}</span>
                </span>
                <ul className="nav-tree nav-tree--nested">
                  <li>
                    <Link
                      className={`nav-subitem ${activeSection === "admin-agents" ? "nav-subitem--active" : ""}`}
                      href={
                        `/${locale}/administration/infrastructure/agents` as Route
                      }
                      aria-current={
                        activeSection === "admin-agents" ? "page" : undefined
                      }
                    >
                      <MonitorCog aria-hidden="true" size={14} />
                      <span>{dictionary.navigation.agents}</span>
                    </Link>
                  </li>
                </ul>
              </li>
            ) : null}
          </ul>
        ) : null}
        <div className="sidebar__version">
          <span className="sidebar__version-dot" aria-hidden="true" />
          {dictionary.navigation.version}
        </div>
      </div>
    </aside>
  );
}
