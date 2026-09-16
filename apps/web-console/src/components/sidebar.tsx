/**
 * File Name: sidebar.tsx
 * Version: v0.1.0
 * Created: 2026-08-30 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Present tenant inventory, security, administration and read-only log navigation.
 */
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
  Server,
  ServerCog,
  Settings,
  Shield,
  ShieldCheck,
  UsersRound,
} from "lucide-react";
import type { Route } from "next";
import Link from "next/link";

import { getDictionary } from "@/i18n/dictionaries";
import { getDomainSecurityCopy } from "@/i18n/domain-security-copy";
import { getJobLogsCopy } from "@/i18n/job-logs-copy";
import { getSecurityCopy } from "@/i18n/security-copy";
import { getSecurityOverrideCopy } from "@/i18n/security-override-copy";
import { resolveLocale } from "@/i18n/server";
import { getWsusCopy } from "@/i18n/wsus-copy";
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
  | "logs-agents"
  | "logs-baselines"
  | "logs-bmc-communication"
  | "logs-bmc-events"
  | "virtual"
  | "virtual-clients"
  | "virtual-linux"
  | "hyper-v-vms"
  | "network"
  | "updates-wsus"
  | "security-baseline"
  | "security-override"
  | "admin-users"
  | "admin-service-accounts"
  | "admin-wsus"
  | "admin-security-baselines"
  | "admin-security-domains"
  | "admin-agents";

export async function Sidebar({
  activeSection,
  activeWindowsRole,
  activeWindowsClientFamily,
  canManageAgents,
  canManageConnectors,
  canViewUsers,
  canManageServiceAccounts,
  canManageSecurityBaselines,
  canManageSecurityDomains,
  canViewLogs,
  windowsRoles,
  windowsClientFamilies,
}: {
  activeSection: ActiveSection;
  activeWindowsRole?: string;
  activeWindowsClientFamily?: string;
  canManageAgents: boolean;
  canManageConnectors: boolean;
  canViewUsers: boolean;
  canManageServiceAccounts: boolean;
  canManageSecurityBaselines: boolean;
  canManageSecurityDomains: boolean;
  canViewLogs: boolean;
  windowsRoles: WindowsServerRoleSummary[];
  windowsClientFamilies: WindowsClientFamilySummary[];
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const securityCopy = getSecurityCopy(locale);
  const logsCopy = getJobLogsCopy(locale);
  const securityExpanded =
    activeSection === "security-baseline" ||
    activeSection === "security-override";
  const overrideCopy = getSecurityOverrideCopy(locale);
  const logsExpanded = activeSection.startsWith("logs-");
  const physicalExpanded = [
    "physical",
    "physical-servers",
    "physical-clients",
    "physical-linux",
    "bmc",
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
    "admin-wsus",
    "admin-security-baselines",
    "admin-security-domains",
  ].includes(activeSection);
  const canAdmin =
    canManageAgents ||
    canViewUsers ||
    canManageServiceAccounts ||
    canManageConnectors ||
    canManageSecurityBaselines ||
    canManageSecurityDomains;
  const administrationHref = canViewUsers
    ? `/${locale}/administration/users`
    : canManageAgents
      ? `/${locale}/administration/infrastructure/agents`
      : canManageServiceAccounts
        ? `/${locale}/administration/service-accounts`
        : canManageConnectors
          ? `/${locale}/administration/updates/wsus`
          : canManageSecurityDomains
            ? `/${locale}/administration/security/domains`
            : `/${locale}/administration/security/baselines`;
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
      label: getWsusCopy(locale).navigation,
      icon: Server,
      href: `/${locale}/updates/wsus`,
      section: "updates-wsus" as const,
      enabled: true as const,
    },
    {
      label: securityCopy.navigation,
      icon: Shield,
      href: `/${locale}/security/baseline`,
      section: "security-baseline" as const,
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
                  className={`nav-item ${item.section === activeSection || (item.section === "security-baseline" && securityExpanded) || (item.section === "physical" && physicalExpanded) || (item.section === "virtual" && virtualExpanded) ? "nav-item--active" : ""}`}
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
              {item.section === "security-baseline" && securityExpanded ? (
                <ul className="nav-tree">
                  <li>
                    <Link
                      className={`nav-subitem ${activeSection === "security-baseline" ? "nav-subitem--active" : ""}`}
                      href={`/${locale}/security/baseline` as Route}
                      aria-current={
                        activeSection === "security-baseline"
                          ? "page"
                          : undefined
                      }
                    >
                      <ShieldCheck aria-hidden="true" size={15} />
                      <span>{securityCopy.baselineNavigation}</span>
                    </Link>
                  </li>
                  {canManageSecurityBaselines ? (
                    <li>
                      <Link
                        className={`nav-subitem ${activeSection === "security-override" ? "nav-subitem--active" : ""}`}
                        href={`/${locale}/security/override` as Route}
                        aria-current={
                          activeSection === "security-override"
                            ? "page"
                            : undefined
                        }
                      >
                        <ShieldCheck aria-hidden="true" size={15} />
                        <span>{overrideCopy.navigation}</span>
                      </Link>
                    </li>
                  ) : null}
                </ul>
              ) : null}
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
        {canViewLogs ? (
          <>
            <Link
              className={`nav-item ${logsExpanded ? "nav-item--active" : ""}`}
              href={`/${locale}/logs/agents` as Route}
            >
              <ScrollText aria-hidden="true" size={18} />
              <span>{logsCopy.navigation}</span>
            </Link>
            {logsExpanded ? (
              <ul className="nav-tree">
                {[
                  {
                    section: "logs-agents",
                    path: "agents",
                    label: logsCopy.agents,
                    icon: MonitorCog,
                  },
                  {
                    section: "logs-baselines",
                    path: "baselines",
                    label: logsCopy.baselines,
                    icon: ShieldCheck,
                  },
                  {
                    section: "logs-bmc-communication",
                    path: "bmc/communication",
                    label: logsCopy.bmcCommunication,
                    icon: ScrollText,
                  },
                  {
                    section: "logs-bmc-events",
                    path: "bmc/events",
                    label: logsCopy.bmcEvents,
                    icon: ListTree,
                  },
                ].map(({ section, path, label, icon: Icon }) => (
                  <li key={section}>
                    <Link
                      className={`nav-subitem ${activeSection === section ? "nav-subitem--active" : ""}`}
                      href={`/${locale}/logs/${path}` as Route}
                      aria-current={
                        activeSection === section ? "page" : undefined
                      }
                    >
                      <Icon aria-hidden="true" size={15} />
                      <span>{label}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : null}
          </>
        ) : null}
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
            {canManageSecurityBaselines || canManageSecurityDomains ? (
              <li>
                <span className="nav-subitem nav-subitem--branch">
                  <Shield aria-hidden="true" size={15} />
                  <span>{securityCopy.navigation}</span>
                </span>
                <ul className="nav-tree nav-tree--nested">
                  {canManageSecurityDomains ? (
                    <li>
                      <Link
                        className={`nav-subitem ${activeSection === "admin-security-domains" ? "nav-subitem--active" : ""}`}
                        href={
                          `/${locale}/administration/security/domains` as Route
                        }
                        aria-current={
                          activeSection === "admin-security-domains"
                            ? "page"
                            : undefined
                        }
                      >
                        <ListTree aria-hidden="true" size={14} />
                        <span>{getDomainSecurityCopy(locale).navigation}</span>
                      </Link>
                    </li>
                  ) : null}
                  {canManageSecurityBaselines ? (
                    <li>
                      <Link
                        className={`nav-subitem ${activeSection === "admin-security-baselines" ? "nav-subitem--active" : ""}`}
                        href={
                          `/${locale}/administration/security/baselines` as Route
                        }
                        aria-current={
                          activeSection === "admin-security-baselines"
                            ? "page"
                            : undefined
                        }
                      >
                        <ShieldCheck aria-hidden="true" size={14} />
                        <span>{securityCopy.baselineNavigation}</span>
                      </Link>
                    </li>
                  ) : null}
                </ul>
              </li>
            ) : null}
            {canManageConnectors ? (
              <li>
                <Link
                  className={`nav-subitem ${activeSection === "admin-wsus" ? "nav-subitem--active" : ""}`}
                  href={`/${locale}/administration/updates/wsus` as Route}
                  aria-current={
                    activeSection === "admin-wsus" ? "page" : undefined
                  }
                >
                  <Server aria-hidden="true" size={15} />
                  <span>{getWsusCopy(locale).adminNavigation}</span>
                </Link>
              </li>
            ) : null}
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
